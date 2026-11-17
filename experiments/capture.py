"""Run the cAPTure evaluation experiment on a scored/labeled cAPTure flow dataset CSV."""
import argparse
from datetime import timedelta

import pandas as pd

from events.conversion import CaptureFlowEventConverter
from experiments.reporting import IterationRecord, parse_dataset_metadata, write_evaluation_outputs
from metrics import MetricsCalculator
from scenario_generator import ScenarioGenerator
from scenario_generator.cli import (
    add_config_argument, add_generation_arguments, generate_with_retries,
    load_config_argument, load_explicit_scenario_path, seed_random_generators,
    validate_generation_arguments, validate_input_file,
)
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.cli import (
    add_reconstruction_arguments, prepare_log_directories, validate_reconstruction_arguments,
)
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.engine import ScenarioReconstructor
from scenario_reconstructor.manager import ReconstructionManager


def main(argv=None):
    parser = argparse.ArgumentParser(prog="reconstructScenario",
                                     description="Run the cAPTure evaluation experiment (scenario generation, reconstruction, and metric collection) on a cAPTure-structured flow dataset CSV")
    parser.add_argument("-f", "--file", required=True, help="path to input scored/labeled flow dataset CSV")
    add_config_argument(parser)
    parser.add_argument(
        "-t", "--times", help="number of evaluation cycles", default=100, type=int)
    parser.add_argument(
        "-l", "--log", help="where to log results", default="./log.txt", type=str)
    parser.add_argument("--iterations-csv", default=None, help="path to per-iteration CSV results")
    parser.add_argument("--summary-csv", default=None, help="path to summary CSV results")
    add_generation_arguments(parser, normal_divisor=10)
    add_reconstruction_arguments(parser)
    parser.add_argument("--edge-recovery-threshold", type=float, default=0.8)
    args = parser.parse_args(argv)
    validate_generation_arguments(parser, args)
    validate_reconstruction_arguments(parser, args)
    config = load_config_argument(args, parser)
    explicit_path = load_explicit_scenario_path(args, parser)
    validate_input_file(parser, args.file)
    if args.times <= 0:
        parser.error("--times must be positive")
    if not 0 <= args.edge_recovery_threshold <= 1:
        parser.error("--edge-recovery-threshold must be between 0 and 1")
    seed_random_generators(args.seed)
    reconstruction_df = pd.read_csv(args.file)
    generator = ScenarioGenerator(
        reconstruction_df, config.next_attack_dict, config.enable_src_for, config.enable_dst_for,
        config.possible_srcs, config.possible_dsts, config.dst_restricted_atks, config.final_atk, config.enable_atks,
    )
    flow_converter = CaptureFlowEventConverter()
    metrics_calc = MetricsCalculator()
    mapper = AttackMapper(config.atk_types, args.type_threshold)
    hosts = config.create_hosts()
    initial_attributes = {host: set(host.compromise_attributes) for host in hosts}
    prepare_log_directories(args)
    reconstructor = ScenarioReconstructor(
        hosts, config.external_host_attributes, config.atk_types,
        args.flow_log_path, args.state_log_path,
        max_idle_gap=timedelta(seconds=args.max_idle_gap),
    )
    manager = ReconstructionManager(
        reconstructor, mapper, args.suspect_threshold, args.anomaly_threshold, config.undetermined,
        length_when_log_flow_exploits=args.log_flow_exploits_threshold,
        length_when_log_states=args.log_states_threshold,
        suspect_list_max_length=args.suspect_max_length,
    )
    attack_goal = config.attack_goal

    def verbose(*values):
        if not args.quiet:
            print(*values)

    records = []
    false_negative_scenarios_actual = []
    false_negative_scenarios_predicted = []
    verbose("starting to run the iterations...")

    for i in range(args.times):
        verbose("generating new scenario...")
        scenario_df = generate_with_retries(generator, args, path=explicit_path)
        steps, alerts = generator.export_results(config.atk_types)
        verbose("actual exploits:")
        verbose("\n".join([str(step) for step in steps]) + "")
        verbose("actual alerts:")
        verbose("\n".join([str(alert) for alert in alerts[-20:]]) + "")
        verbose("converting scenario in flow objects...")
        flows = flow_converter.convert(scenario_df, score_columns=config.score_columns)
        verbose("reconstructing scenario from flow objects...")
        for flow in flows:
            manager.accept(flow)
        predicted_dag, p_alerts = manager.get_results()
        verbose("predicted exploits:")
        verbose("\n".join([str(step) for step in predicted_dag.steps]))
        verbose("predicted alerts:")
        verbose("\n".join([str(alert) for alert in p_alerts[-20:]]))
        verbose("predicted false negatives")
        verbose("\n".join([str(fn) for fn in manager.get_fns()]))
        verbose("predicted false positives")
        verbose("\n".join([str(fp) for fp in manager.get_fps()]))
        verbose("calculating metrics...")
        tn, fp, fn, tp = metrics_calc.get_detection_confusion_matrix(
            scenario_df, args.anomaly_threshold)
        tn_r, fp_r, fn_r, tp_r = metrics_calc.get_reconstruction_confusion_matrix(
            scenario_df, p_alerts)
        actual_dag = AttackScenarioDAG(steps, tracked_host_ips=reconstructor.host_dict)
        step_soundness, step_completeness = metrics_calc.get_step_soundness_completeness(
            predicted_dag, actual_dag, p_alerts, alerts, config.undetermined)
        scenario_soundness, scenario_completeness = metrics_calc.get_scenario_soundness_completeness(
            predicted_dag, actual_dag, config.undetermined)
        records.append(IterationRecord(
            iteration=i, actual_steps=len(steps), predicted_steps=len(predicted_dag.steps),
            actual_alerts=len(alerts), predicted_alerts=len(p_alerts),
            recovered_fns=len(manager.get_fns()), rejected_fps=len(manager.get_fps()),
            id_tn=tn, id_fp=fp, id_fn=fn, id_tp=tp,
            rec_tn=tn_r, rec_fp=fp_r, rec_fn=fn_r, rec_tp=tp_r,
            alert_precision=metrics_calc.get_alert_precision(p_alerts, alerts, config.undetermined),
            alert_recall=metrics_calc.get_alert_recall(p_alerts, alerts, config.undetermined),
            step_soundness=step_soundness, step_completeness=step_completeness,
            scenario_step_precision=metrics_calc.get_scenario_step_precision(
                predicted_dag, actual_dag, config.undetermined),
            scenario_step_recall=metrics_calc.get_scenario_step_recall(
                predicted_dag, actual_dag, config.undetermined),
            scenario_soundness=scenario_soundness, scenario_completeness=scenario_completeness,
            scenario_detected=int(metrics_calc.is_scenario_detected(
                predicted_dag, actual_dag, attack_goal, config.undetermined,
                edge_recovery_threshold=args.edge_recovery_threshold)),
        ))
        if fn_r > fn:
            false_negative_scenarios_actual.append(steps)
            false_negative_scenarios_predicted.append(predicted_dag.steps)
        manager.reset(initial_attributes)

    dataset, detector, mapper_name = parse_dataset_metadata(args.file)
    metadata = dict(
        dataset=dataset, detector=detector, mapper=mapper_name, config=args.config,
        anomaly_threshold=args.anomaly_threshold, suspect_threshold=args.suspect_threshold,
        type_threshold=args.type_threshold, edge_recovery_threshold=args.edge_recovery_threshold,
        max_idle_gap=args.max_idle_gap, seed=args.seed, times=args.times,
    )
    write_evaluation_outputs(
        args.log, records, metadata, false_negative_scenarios_actual,
        false_negative_scenarios_predicted, iterations_csv_path=args.iterations_csv,
        summary_csv_path=args.summary_csv,
    )


if __name__ == "__main__":
    main()
