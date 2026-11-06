"""cAPTure evaluation CLI; importing this module does not run experiments."""
import argparse
import os

import numpy as np
import pandas as pd

from events.conversion import CaptureFlowEventConverter
from metrics import MetricsCalculator
from scenario_generator import ScenarioGenerator
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.dag import AttackScenarioDAG
from scenario_reconstructor.engine import ScenarioReconstructor
from scenario_reconstructor.manager import ReconstructionManager
from scenario_configs.capture import (
    ATK_TYPES, DST_RESTRICTED_ATKS, ENABLE_ATKS, ENABLE_DST_FOR, ENABLE_SRC_FOR,
    FINAL_ATK, NEXT_ATTACK_DICT, POSSIBLE_DSTS, POSSIBLE_SRCS, UNDETERMINED,
    DollarCharHostAttributes, create_hosts,
)

def main(argv=None):
    parser = argparse.ArgumentParser(prog="reconstructScenario",
                                     description="Reconstruct cAPTure scenarios and compute metrics using scenario_configs.capture")
    parser.add_argument("-f", "--file", required=True, help="file name")
    parser.add_argument(
        "-t", "--times", help="number of evaluation cycles", default=100, type=int)
    parser.add_argument(
        "-l", "--log", help="where to log results", default="./log.txt", type=str)
    parser.add_argument("--anomaly-threshold", help="threshold for alert generation", default=0.8,
                        type=float)
    parser.add_argument("--suspect-threshold", help="threshold for suspicion addition", default=0.4,
                        type=float)
    parser.add_argument("--type-threshold", help="threshold for attack type mapping", default=0.2,
                        type=float)
    args = parser.parse_args(argv)
    if args.anomaly_threshold <= 0 or args.suspect_threshold < 0:
        raise argparse.ArgumentTypeError(
            f"Illegal threshold value: anomaly_threshold-{args.anomaly_threshold} suspect_threshold-{args.suspect_threshold}")
    if not args.file.endswith(".csv"):
        raise argparse.ArgumentTypeError("File must be a csv file")
    if not os.path.exists(args.file):
        raise argparse.ArgumentTypeError("File does not exist")
    reconstruction_df = pd.read_csv(args.file)
    reconstruction_df = reconstruction_df.sort_values(by="timestamp")
    generator = ScenarioGenerator(reconstruction_df, NEXT_ATTACK_DICT, ENABLE_SRC_FOR, ENABLE_DST_FOR,
                                         POSSIBLE_SRCS, POSSIBLE_DSTS, DST_RESTRICTED_ATKS, FINAL_ATK, ENABLE_ATKS)
    flow_converter = CaptureFlowEventConverter()
    metrics_calc = MetricsCalculator()
    mapper = AttackMapper(ATK_TYPES, args.type_threshold)
    hosts = create_hosts()
    initial_attributes = {host: set(host.compromise_attributes) for host in hosts}
    reconstructor = ScenarioReconstructor(hosts, {DollarCharHostAttributes.START_MACHINE},
                                                                     ATK_TYPES,
                                                                     "../data/flow_exploits.log", "../data/states.log")
    manager = ReconstructionManager(reconstructor, mapper, args.suspect_threshold, args.anomaly_threshold,
                                            UNDETERMINED)

    tn_list = []
    fp_list = []
    fn_list = []
    tp_list = []
    tnr_list = []
    fpr_list = []
    fnr_list = []
    tpr_list = []
    alert_recall_list = []
    alert_precision_list = []
    step_soundness_list = []
    step_completeness_list = []
    scenario_recall_list = []
    scenario_precision_list = []
    scenario_soundness_list = []
    scenario_completeness_list = []
    false_negative_scenarios_actual = []
    false_negative_scenarios_predicted = []
    print("starting to run the iterations...")

    for i in range(args.times):
        print("generating new scenario...")
        scenario_df = generator.generate_scenario(10)
        steps, alerts = generator.export_results(ATK_TYPES)
        print("actual exploits:")
        print("\n".join([str(step) for step in steps]) + "")
        print("actual alerts:")
        print("\n".join([str(alert) for alert in alerts[-20:]]) + "")
        print("converting scenario in flow objects...")
        flows = flow_converter.convert(scenario_df)
        print("reconstructing scenario from flow objects...")
        for flow in flows:
            manager.accept(flow)
        predicted_dag, p_alerts = manager.get_results()
        print("predicted exploits:")
        print("\n".join([str(step) for step in predicted_dag.steps]))
        print("predicted alerts:")
        print("\n".join([str(alert) for alert in p_alerts[-20:]]))
        print("predicted false negatives")
        print("\n".join([str(fn) for fn in manager.get_fns()]))
        print("predicted false positives")
        print("\n".join([str(fp) for fp in manager.get_fps()]))
        print("calculating metrics...")
        tn, fp, fn, tp = metrics_calc.get_detection_confusion_matrix(
            scenario_df, args.anomaly_threshold)
        tn_r, fp_r, fn_r, tp_r = metrics_calc.get_reconstruction_confusion_matrix(
            scenario_df, p_alerts)
        tn_list.append(tn)
        fp_list.append(fp)
        fn_list.append(fn)
        tp_list.append(tp)
        tnr_list.append(tn_r)
        fpr_list.append(fp_r)
        fnr_list.append(fn_r)
        tpr_list.append(tp_r)
        alert_recall_list.append(metrics_calc.get_alert_recall(
            p_alerts, alerts, UNDETERMINED))
        alert_precision_list.append(metrics_calc.get_alert_precision(
            p_alerts, alerts, UNDETERMINED))
        actual_dag = AttackScenarioDAG(steps, tracked_host_ips=reconstructor.host_dict)
        step_soundness, step_completeness = metrics_calc.get_step_soundness_completeness(
            predicted_dag, actual_dag, p_alerts, alerts, UNDETERMINED)
        step_soundness_list.append(step_soundness)
        step_completeness_list.append(step_completeness)
        scenario_recall_list.append(metrics_calc.get_scenario_step_recall(
            predicted_dag, actual_dag, UNDETERMINED))
        scenario_precision_list.append(metrics_calc.get_scenario_step_precision(
            predicted_dag, actual_dag, UNDETERMINED))
        scenario_soundness, scenario_completeness = metrics_calc.get_scenario_soundness_completeness(
            predicted_dag, actual_dag, UNDETERMINED)
        scenario_soundness_list.append(scenario_soundness)
        scenario_completeness_list.append(scenario_completeness)
        if fn_r > fn:
            false_negative_scenarios_actual.append(steps)
            false_negative_scenarios_predicted.append(predicted_dag.steps)
        manager.reset(initial_attributes)

    with open(args.log, "w") as f:

        f.write(
            f"mean ID true negatives: {float(np.mean(tn_list))}, mean REC true negatives: {float(np.mean(tnr_list))}\n")
        f.write(
            f"mean ID false positives: {float(np.mean(fp_list))}, mean REC false positives: {float(np.mean(fpr_list))}\n")
        f.write(
            f"mean ID false negatives: {float(np.mean(fn_list))}, mean REC false negatives: {float(np.mean(fnr_list))}\n")
        f.write(
            f"mean ID true positives: {float(np.mean(tp_list))}, mean REC true positives: {float(np.mean(tpr_list))}\n")

        f.write(
            f"mean precision of reconstructed alerts: {float(np.mean(alert_precision_list))}\n")
        f.write(
            f"mean recall of reconstructed alerts: {float(np.mean(alert_recall_list))}\n")
        f.write(
            f"mean soundness of reconstructed steps: {float(np.mean(step_soundness_list))}\n")
        f.write(
            f"mean completeness of reconstructed steps: {float(np.mean(step_completeness_list))}\n")
        f.write(
            f"mean precision of reconstructed scenarios: {float(np.mean(scenario_precision_list))}\n")
        f.write(
            f"mean recall of reconstructed scenarios: {float(np.mean(scenario_recall_list))}\n")
        f.write(
            f"mean soundness of reconstructed scenarios: {float(np.mean(scenario_soundness_list))}\n")
        f.write(
            f"mean completeness of reconstructed scenarios: {float(np.mean(scenario_completeness_list))}\n")

    with open(args.log.removesuffix(".txt") + "_fn_generating_scenarios.txt", "w") as f:
        for i in range(len(false_negative_scenarios_actual)):
            f.write("actual scenario\n")
            f.write(", ".join(str(exploit) for exploit in false_negative_scenarios_actual[i]) + "\n")
            f.write("predicted scenario\n")
            f.write(", ".join(str(exploit) for exploit in false_negative_scenarios_predicted[i]) + "\n")


if __name__ == "__main__":
    main()
