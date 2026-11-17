"""Configured batch dispatch using the active interpreter and argument lists."""
import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from experiments.reporting import (
    BATCH_ITERATIONS_FILENAME, BATCH_SUMMARY_FILENAME,
    aggregate_batch_results, default_iterations_csv_path, default_summary_csv_path,
)

DATASET_ROOT = './data/final datasets/'
DATASET_FILES = ['iforest_lr_rec_dataset.csv',
                 'iforest_gnb_rec_dataset.csv',
                 'iforest_xgb_rec_dataset.csv',
                 'logistic_regression_gnb_rec_dataset.csv',
                 'logistic_regression_xgb_rec_dataset.csv',
                 'logistic_regression_lr_rec_dataset.csv',
                 'xgb_gnb_rec_dataset.csv',
                 'xgb_xgb_rec_dataset.csv',
                 'xgb_lr_rec_dataset.csv',
                 'xgb_perfect_rec_dataset.csv',
                 'perfect_xgb_rec_dataset.csv',
                 'perfect_perfect_rec_dataset.csv',
                 ]
OUTPUT_ROOT = './data/result logs/'

N_SCENARIOS = 100
ANOMALY_THRESHOLDS = [0.3, 0.6, 0.9]
SUSPECT_THRESHOLDS = [0.2, 0.8]
TYPE_THRESHOLD = 0.1


@dataclass(frozen=True)
class EvaluationJob:
    input_file: str
    output_file: str
    anomaly_threshold: float
    suspect_threshold: float


def build_jobs() -> list[EvaluationJob]:
    """Describe the configured evaluations without launching processes."""
    return [
        EvaluationJob(
            DATASET_ROOT + filename,
            OUTPUT_ROOT + "u_" + filename.removesuffix(".csv")
            + f"_av_{anomaly_threshold}_sv_{suspect_threshold}.txt",
            anomaly_threshold, suspect_threshold,
        )
        for filename in DATASET_FILES
        for anomaly_threshold in ANOMALY_THRESHOLDS
        for suspect_threshold in SUSPECT_THRESHOLDS
        if suspect_threshold < anomaly_threshold
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--no-seed', action='store_true', help='disable reproducible seeding')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--results-dir', default=OUTPUT_ROOT)
    args = parser.parse_args(argv)
    if not args.no_seed and not 0 <= args.seed < 2**32:
        parser.error('--seed must satisfy 0 <= seed < 2**32')
    jobs = build_jobs()
    if args.results_dir != OUTPUT_ROOT:
        jobs = [EvaluationJob(job.input_file, str(Path(args.results_dir) / Path(job.output_file).name),
                              job.anomaly_threshold, job.suspect_threshold) for job in jobs]
    # Invalidate previous combined reports even if this batch fails or is interrupted.
    # Individual job outputs are retained for diagnosis but do not imply success.
    for filename in (BATCH_SUMMARY_FILENAME, BATCH_ITERATIONS_FILENAME):
        (Path(args.results_dir) / filename).unlink(missing_ok=True)
    successful_jobs = []
    for job in jobs:
        if not args.quiet:
            print(
                f"evaluating reconstruction mechanism for {job.input_file} "
                f"with anomaly threshold {job.anomaly_threshold}, "
                f"suspect threshold {job.suspect_threshold}, type threshold {TYPE_THRESHOLD}")
        command = [
            sys.executable, "-m", "experiments.capture",
            "-f", job.input_file, "-t", str(N_SCENARIOS),
            "--anomaly-threshold", str(job.anomaly_threshold),
            "--suspect-threshold", str(job.suspect_threshold),
            "--type-threshold", str(TYPE_THRESHOLD), "-l", job.output_file,
        ]
        if not args.no_seed:
            command.extend(['--seed', str(args.seed)])
        if args.quiet:
            command.append('--quiet')
        code = subprocess.run(command, check=False).returncode
        if code != 0:
            print(f"FAILED (exit {code}): {job.output_file}")
            continue
        successful_jobs.append(job)
    aggregate_batch_results(
        args.results_dir,
        summary_paths=[default_summary_csv_path(job.output_file) for job in successful_jobs],
        iteration_paths=[default_iterations_csv_path(job.output_file) for job in successful_jobs],
    )


if __name__ == "__main__":
    main()
