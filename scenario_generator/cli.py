"""Generate scenarios using a labeled/scored flow dataset CSV as flow templates."""
import argparse
import json
import os
from pathlib import Path
import random
import re

import numpy as np
import pandas as pd

from scenario_configs import load_scenario_config
from scenario_generator import ScenarioGenerator, ScenarioSearchLimitError


def add_generation_arguments(parser, normal_divisor=1):
    """Add bounded generation and reproducibility options."""
    parser.add_argument("--normal-divisor", type=int, default=normal_divisor)
    parser.add_argument("--max-steps", type=int, default=100)
    parser.add_argument("--max-search-attempts", type=int, default=10_000)
    parser.add_argument("--max-generation-retries", type=int, default=5)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("-q", "--quiet", action="store_true")
    paths = parser.add_mutually_exclusive_group()
    paths.add_argument("--scenario-path", help="path to a .json or text file (or inline ';'/'|'-separated steps) defining an explicit step sequence")
    paths.add_argument("--step", action="append", help="explicit scenario step in 'attack:src_ip->dst_ip' or 'attack,src_ip,dst_ip' format (repeatable, overrides random search)")


def add_config_argument(parser):
    """Add the shared campaign selection option."""
    parser.add_argument("-c", "--config", default="capture",
                        help="campaign configuration name ('capture') or path to a .py/.json config file")


def load_config_argument(args, parser):
    """Report configuration errors before reading a dataset."""
    try:
        return load_scenario_config(args.config)
    except ValueError as error:
        parser.error(str(error))


def _validate_step(step):
    if (not isinstance(step, (list, tuple)) or len(step) != 3
            or not all(isinstance(value, str) and value.strip() for value in step)):
        raise ValueError("Each scenario step requires three non-empty strings: attack, src_ip, dst_ip")
    attack, src, dst = (value.strip() for value in step)
    if src == dst:
        raise ValueError("Scenario step source and destination IPs must differ")
    return attack, src, dst


def parse_step_spec(spec: str) -> tuple[str, str, str]:
    """Parse an attack:source->destination or attack,source,destination step."""
    if not isinstance(spec, str):
        raise ValueError("Scenario step must be a string")
    if "->" in spec:
        match = re.fullmatch(r"\s*([^:,]+):\s*(.+?)\s*->\s*(.+?)\s*", spec)
        if match is None or spec.count("->") != 1:
            raise ValueError(f"Invalid scenario step: {spec!r}")
        return _validate_step(match.groups())
    return _validate_step(spec.split(","))


def load_explicit_scenario_path(args, parser) -> list[tuple[str, str, str]] | None:
    """Read explicit steps from repeated options, a file, or inline text."""
    try:
        if args.step is not None:
            steps = [parse_step_spec(spec) for spec in args.step]
        elif args.scenario_path is not None:
            spec = args.scenario_path
            filename = Path(spec)
            if filename.is_file():
                contents = filename.read_text(encoding="utf-8")
                if filename.suffix.lower() == ".json":
                    records = json.loads(contents)
                    if isinstance(records, dict):
                        records = records.get("steps")
                    if not isinstance(records, list):
                        raise ValueError("Scenario path JSON must be a list or an object containing a steps list")
                    steps = []
                    for record in records:
                        if isinstance(record, dict):
                            record = (record.get("attack"), record.get("src_ip", record.get("source_ip")),
                                      record.get("dst_ip", record.get("destination_ip")))
                        steps.append(_validate_step(record))
                else:
                    steps = [parse_step_spec(line) for line in contents.splitlines()
                             if line.strip() and not line.lstrip().startswith("#")]
            elif "->" in spec or "," in spec:
                steps = [parse_step_spec(step) for step in re.split(r"[;|]", spec)]
            else:
                raise ValueError(f"Scenario path file does not exist or has invalid step syntax: {spec}")
        else:
            return None
        if not steps:
            raise ValueError("Explicit scenario path must contain at least one step")
        return steps
    except (OSError, ValueError) as error:
        parser.error(str(error))


def validate_generation_arguments(parser, args):
    """Reject invalid search limits before reading the flow dataset."""
    for name in ("normal_divisor", "max_steps", "max_search_attempts"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.max_generation_retries < 0:
        parser.error("--max-generation-retries must be nonnegative")
    if args.seed is not None and not 0 <= args.seed < 2**32:
        parser.error("--seed must satisfy 0 <= seed < 2**32")


def validate_input_file(parser, filename):
    """Require an existing CSV input path."""
    if not filename.endswith(".csv"):
        parser.error("--file must be a csv file")
    if not os.path.exists(filename):
        parser.error("--file does not exist")


def generate_with_retries(generator, args, *, path=None):
    """Retry search exhaustion, propagating the final typed failure."""
    for attempt in range(args.max_generation_retries + 1):
        try:
            options = dict(max_steps=args.max_steps, max_search_attempts=args.max_search_attempts)
            if path is not None:
                options["path"] = path
            return generator.generate_scenario(args.normal_divisor, **options)
        except ScenarioSearchLimitError:
            if attempt == args.max_generation_retries:
                raise


def seed_random_generators(seed):
    """Seed both sources of generation randomness when requested."""
    if seed is not None:
        random.seed(seed)
        np.random.seed(seed)


def write_records(filename, records):
    """Write one text record per line, creating its parent directory."""
    Path(filename).parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as output:
        for record in records:
            output.write(f"{record}\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--file", required=True,
                        help="path to input labeled/scored flow dataset CSV used as flow templates")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--steps-output")
    parser.add_argument("--alerts-output")
    add_config_argument(parser)
    add_generation_arguments(parser)
    args = parser.parse_args(argv)
    validate_generation_arguments(parser, args)
    config = load_config_argument(args, parser)
    explicit_path = load_explicit_scenario_path(args, parser)
    validate_input_file(parser, args.file)
    seed_random_generators(args.seed)
    generator = ScenarioGenerator(
        pd.read_csv(args.file), config.next_attack_dict, config.enable_src_for, config.enable_dst_for,
        config.possible_srcs, config.possible_dsts, config.dst_restricted_atks, config.final_atk, config.enable_atks,
    )
    scenario_df = generate_with_retries(generator, args, path=explicit_path)
    steps, alerts = generator.export_results(config.atk_types)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    scenario_df.to_csv(args.output, index=False)
    if args.steps_output:
        write_records(args.steps_output, steps)
    if args.alerts_output:
        write_records(args.alerts_output, alerts)
    if not args.quiet:
        print(f"Generated {len(scenario_df)} flows, {len(steps)} steps, {len(alerts)} alerts.")


if __name__ == "__main__":
    main()
