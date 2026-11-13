"""Reconstruct cAPTure scenarios from scored flow CSV files."""
import argparse
from datetime import timedelta
import math
from pathlib import Path

import pandas as pd

from events.conversion import CaptureFlowEventConverter
from scenario_configs.capture import ATK_TYPES, UNDETERMINED, DollarCharHostAttributes, create_hosts
from scenario_generator.cli import validate_input_file, write_records
from scenario_reconstructor.attack_mapper import AttackMapper
from scenario_reconstructor.engine import ScenarioReconstructor
from scenario_reconstructor.manager import ReconstructionManager


def add_reconstruction_arguments(parser):
    """Add classification, aggregation, and archive options."""
    parser.add_argument("--anomaly-threshold", type=float, default=0.8)
    parser.add_argument("--suspect-threshold", type=float, default=0.4)
    parser.add_argument("--type-threshold", type=float, default=0.2)
    parser.add_argument("--max-idle-gap", type=float, default=1.0, help="maximum idle gap in seconds")
    parser.add_argument("--flow-log-path", default="./data/flow_exploits.log")
    parser.add_argument("--state-log-path", default="./data/states.log")
    parser.add_argument("--log-flow-exploits-threshold", type=int, default=-1)
    parser.add_argument("--log-states-threshold", type=int, default=-1)
    parser.add_argument("--suspect-max-length", type=int, default=-1)


def validate_reconstruction_arguments(parser, args):
    """Reject invalid thresholds before converting flows or opening archives."""
    if not 0 <= args.suspect_threshold < args.anomaly_threshold <= 1:
        parser.error("thresholds must satisfy 0 <= suspect-threshold < anomaly-threshold <= 1")
    if not 0 <= args.type_threshold <= 1:
        parser.error("--type-threshold must be between 0 and 1")
    if not math.isfinite(args.max_idle_gap) or args.max_idle_gap < 0:
        parser.error("--max-idle-gap must be finite and nonnegative")
    try:
        timedelta(seconds=args.max_idle_gap)
    except OverflowError:
        parser.error("--max-idle-gap exceeds the supported duration")
    for name in ("log_flow_exploits_threshold", "log_states_threshold", "suspect_max_length"):
        if getattr(args, name) < -1:
            parser.error(f"--{name.replace('_', '-')} must be at least -1")


def prepare_log_directories(args):
    """Create parent directories for enabled evidence archives."""
    if args.log_flow_exploits_threshold >= 0:
        Path(args.flow_log_path).parent.mkdir(parents=True, exist_ok=True)
    if args.log_states_threshold >= 0:
        Path(args.state_log_path).parent.mkdir(parents=True, exist_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--output")
    parser.add_argument("--alerts-output")
    parser.add_argument("-q", "--quiet", action="store_true")
    add_reconstruction_arguments(parser)
    args = parser.parse_args(argv)
    validate_reconstruction_arguments(parser, args)
    validate_input_file(parser, args.file)
    flows = CaptureFlowEventConverter().convert(pd.read_csv(args.file))
    prepare_log_directories(args)
    reconstructor = ScenarioReconstructor(
        create_hosts(), {DollarCharHostAttributes.START_MACHINE}, ATK_TYPES,
        args.flow_log_path, args.state_log_path,
        max_idle_gap=timedelta(seconds=args.max_idle_gap),
    )
    manager = ReconstructionManager(
        reconstructor, AttackMapper(ATK_TYPES, args.type_threshold),
        args.suspect_threshold, args.anomaly_threshold, UNDETERMINED,
        length_when_log_flow_exploits=args.log_flow_exploits_threshold,
        length_when_log_states=args.log_states_threshold,
        suspect_list_max_length=args.suspect_max_length,
    )
    for flow in flows:
        manager.accept(flow)
    dag, alerts = manager.get_results()
    if args.output:
        write_records(args.output, dag.steps)
    if args.alerts_output:
        write_records(args.alerts_output, alerts)
    if not args.quiet:
        for step in dag.steps:
            print(step)
        print(f"Reconstructed {len(dag.steps)} steps, {len(alerts)} alerts from {len(flows)} flows.")


if __name__ == "__main__":
    main()
