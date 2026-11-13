"""Generate cAPTure scenarios from scored template CSV files."""
import argparse
import os
from pathlib import Path
import random

import numpy as np
import pandas as pd

from scenario_configs.capture import (
    ATK_TYPES, DST_RESTRICTED_ATKS, ENABLE_ATKS, ENABLE_DST_FOR, ENABLE_SRC_FOR,
    FINAL_ATK, NEXT_ATTACK_DICT, POSSIBLE_DSTS, POSSIBLE_SRCS,
)
from scenario_generator import ScenarioGenerator, ScenarioSearchLimitError


def add_generation_arguments(parser, normal_divisor=1):
    """Add bounded generation and reproducibility options."""
    parser.add_argument("--normal-divisor", type=int, default=normal_divisor)
    parser.add_argument("--max-steps", type=int, default=100)
    parser.add_argument("--max-search-attempts", type=int, default=10_000)
    parser.add_argument("--max-generation-retries", type=int, default=5)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("-q", "--quiet", action="store_true")


def validate_generation_arguments(parser, args):
    """Reject invalid search limits before reading templates."""
    for name in ("normal_divisor", "max_steps", "max_search_attempts"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.max_generation_retries < 0:
        parser.error("--max-generation-retries must be nonnegative")


def validate_input_file(parser, filename):
    """Require an existing CSV input path."""
    if not filename.endswith(".csv"):
        parser.error("--file must be a csv file")
    if not os.path.exists(filename):
        parser.error("--file does not exist")


def generate_with_retries(generator, args):
    """Retry search exhaustion, propagating the final typed failure."""
    for attempt in range(args.max_generation_retries + 1):
        try:
            return generator.generate_scenario(
                args.normal_divisor, max_steps=args.max_steps,
                max_search_attempts=args.max_search_attempts,
            )
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
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--steps-output")
    parser.add_argument("--alerts-output")
    add_generation_arguments(parser)
    args = parser.parse_args(argv)
    validate_generation_arguments(parser, args)
    validate_input_file(parser, args.file)
    seed_random_generators(args.seed)
    generator = ScenarioGenerator(
        pd.read_csv(args.file), NEXT_ATTACK_DICT, ENABLE_SRC_FOR, ENABLE_DST_FOR,
        POSSIBLE_SRCS, POSSIBLE_DSTS, DST_RESTRICTED_ATKS, FINAL_ATK, ENABLE_ATKS,
    )
    scenario_df = generate_with_retries(generator, args)
    steps, alerts = generator.export_results(ATK_TYPES)
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
