"""Configured batch dispatch using the active interpreter and argument lists."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import timedelta
import math
import os
from pathlib import Path
import subprocess
import sys
from typing import Sequence

from experiments.policy import load_policy_config
from experiments.reporting import (
    BATCH_ITERATIONS_FILENAME, BATCH_SUMMARY_FILENAME,
    aggregate_batch_results, default_iterations_csv_path, default_summary_csv_path,
)

DATASET_ROOT = './data/cAPTure/final_datasets/dollar_char/'
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
OUTPUT_ROOT = './data/cAPTure/results/dollar_char/'
DEFAULT_CONFIG = 'capture'
ALL_DETECTORS = (
    'logistic_regression', 'xgb', 'qda', 'naive_bayes',
    'sampling', 'hbos', 'iforest', 'perfect',
)
DEFAULT_DETECTORS = ('iforest', 'logistic_regression', 'xgb', 'perfect')
ALL_MAPPERS = ('lr', 'gnb', 'xgb', 'perfect')

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


def _normalize_dataset_filename(name: str) -> str:
    if name.endswith('.csv'):
        return name
    if name.endswith('_rec_dataset'):
        return f'{name}.csv'
    return f'{name}_rec_dataset.csv'


def _expand_tokens(
    tokens: Sequence[str] | None,
    default: Sequence[str],
    all_values: Sequence[str],
) -> list[str]:
    if tokens is None:
        return list(default)
    expanded: list[str] = []
    for token in tokens:
        if token == 'all':
            expanded.extend(all_values)
        else:
            expanded.append(token)
    return list(dict.fromkeys(expanded))


def resolve_dataset_files(
    datasets: Sequence[str] | None = None,
    detectors: Sequence[str] | None = None,
    mappers: Sequence[str] | None = None,
) -> list[str]:
    """Resolve dataset filenames from explicit entries or detector/mapper combinations."""
    if datasets is not None:
        return list(dict.fromkeys(_normalize_dataset_filename(name) for name in datasets))
    if detectors is not None or mappers is not None:
        resolved_detectors = _expand_tokens(detectors, DEFAULT_DETECTORS, ALL_DETECTORS)
        resolved_mappers = _expand_tokens(mappers, ALL_MAPPERS, ALL_MAPPERS)
        return list(dict.fromkeys(
            f'{detector}_{mapper}_rec_dataset.csv'
            for detector in resolved_detectors
            for mapper in resolved_mappers
        ))
    return list(DATASET_FILES)


def build_jobs(
    *,
    dataset_dir: str | Path = DATASET_ROOT,
    results_dir: str | Path = OUTPUT_ROOT,
    dataset_files: Sequence[str] = DATASET_FILES,
    anomaly_thresholds: Sequence[float] = ANOMALY_THRESHOLDS,
    suspect_thresholds: Sequence[float] = SUSPECT_THRESHOLDS,
) -> list[EvaluationJob]:
    """Describe the configured evaluations without launching processes."""
    dataset_dir_str = str(dataset_dir)
    results_dir_str = str(results_dir)
    return [
        EvaluationJob(
            os.path.join(dataset_dir_str, filename),
            os.path.join(
                results_dir_str,
                'u_' + filename.removesuffix('.csv')
                + f'_av_{anomaly_threshold}_sv_{suspect_threshold}.txt',
            ),
            anomaly_threshold, suspect_threshold,
        )
        for filename in dataset_files
        for anomaly_threshold in anomaly_thresholds
        for suspect_threshold in suspect_thresholds
        if suspect_threshold < anomaly_threshold
    ]


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.no_seed and args.seed is not None and not 0 <= args.seed < 2**32:
        parser.error('--seed must satisfy 0 <= seed < 2**32')
    if args.times <= 0:
        parser.error('--times must be positive')
    if args.workers < 1:
        parser.error('--workers must be at least 1')
    if args.datasets is not None and (args.detectors is not None or args.mappers is not None):
        parser.error('--datasets cannot be combined with --detectors or --mappers')

    anomaly_thresholds = (
        args.anomaly_thresholds if args.anomaly_thresholds is not None else ANOMALY_THRESHOLDS
    )
    suspect_thresholds = (
        args.suspect_thresholds if args.suspect_thresholds is not None else SUSPECT_THRESHOLDS
    )
    for value in anomaly_thresholds:
        if not math.isfinite(value) or not 0 < value <= 1:
            parser.error('--anomaly-thresholds values must satisfy 0 < threshold <= 1')
    for value in suspect_thresholds:
        if not math.isfinite(value) or not 0 <= value < 1:
            parser.error('--suspect-thresholds values must satisfy 0 <= threshold < 1')
    if not any(sv < av for av in anomaly_thresholds for sv in suspect_thresholds):
        parser.error('at least one (suspect, anomaly) threshold pair must satisfy suspect < anomaly')

    if not math.isfinite(args.type_threshold) or not 0 <= args.type_threshold <= 1:
        parser.error('--type-threshold must be between 0 and 1')
    if args.suspect_max_length is not None and args.suspect_max_length < -1:
        parser.error('--suspect-max-length must be at least -1')
    if args.log_flow_exploits_threshold is not None and args.log_flow_exploits_threshold < -1:
        parser.error('--log-flow-exploits-threshold must be at least -1')
    if args.log_states_threshold is not None and args.log_states_threshold < -1:
        parser.error('--log-states-threshold must be at least -1')
    if args.max_idle_gap is not None:
        if not math.isfinite(args.max_idle_gap) or args.max_idle_gap < 0:
            parser.error('--max-idle-gap must be finite and nonnegative')
        try:
            timedelta(seconds=args.max_idle_gap)
        except OverflowError:
            parser.error('--max-idle-gap exceeds the supported duration')
    if args.edge_recovery_threshold is not None and (
        not math.isfinite(args.edge_recovery_threshold)
        or not 0 <= args.edge_recovery_threshold <= 1
    ):
        parser.error('--edge-recovery-threshold must be between 0 and 1')
    if args.normal_divisor is not None and args.normal_divisor <= 0:
        parser.error('--normal-divisor must be positive')


def _job_outputs_ready(job: EvaluationJob) -> bool:
    summary_path = default_summary_csv_path(job.output_file)
    iterations_path = default_iterations_csv_path(job.output_file)
    return (
        summary_path.is_file() and summary_path.stat().st_size > 0
        and iterations_path.is_file() and iterations_path.stat().st_size > 0
    )


def _build_command(job: EvaluationJob, args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable, '-m', 'experiments.capture',
        '-f', job.input_file,
        '-c', args.config,
        '-t', str(args.times),
        '--anomaly-threshold', str(job.anomaly_threshold),
        '--suspect-threshold', str(job.suspect_threshold),
        '--type-threshold', str(args.type_threshold),
        '-l', job.output_file,
    ]
    if not args.no_seed and args.seed is not None:
        command.extend(['--seed', str(args.seed)])
    if args.quiet:
        command.append('--quiet')
    if args.suspect_max_length is not None:
        command.extend(['--suspect-max-length', str(args.suspect_max_length)])
    if args.log_flow_exploits_threshold is not None:
        command.extend(['--log-flow-exploits-threshold', str(args.log_flow_exploits_threshold)])
    if args.log_states_threshold is not None:
        command.extend(['--log-states-threshold', str(args.log_states_threshold)])
    if args.max_idle_gap is not None:
        command.extend(['--max-idle-gap', str(args.max_idle_gap)])
    if args.edge_recovery_threshold is not None:
        command.extend(['--edge-recovery-threshold', str(args.edge_recovery_threshold)])
    if args.normal_divisor is not None:
        command.extend(['--normal-divisor', str(args.normal_divisor)])
    return command


def _run_job(
    job: EvaluationJob,
    command: list[str],
    type_threshold: float,
    quiet: bool,
) -> bool:
    if not quiet:
        print(
            f'evaluating reconstruction mechanism for {job.input_file} '
            f'with anomaly threshold {job.anomaly_threshold}, '
            f'suspect threshold {job.suspect_threshold}, type threshold {type_threshold}'
        )
    code = subprocess.run(command, check=False).returncode
    if code != 0:
        print(f'FAILED (exit {code}): {job.output_file}')
        return False
    return True


def main(argv=None):
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--policy-config', default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-config', default=None, help='path to JSON reconstruction/batch policy config file')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--no-seed', action='store_true', help='disable reproducible seeding')
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--dataset-dir', default=DATASET_ROOT, help='directory containing *_rec_dataset.csv files')
    parser.add_argument('--results-dir', default=OUTPUT_ROOT, help='directory where evaluation logs and CSVs are written')
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG, help='campaign configuration name or .py/.json path')
    parser.add_argument('-t', '--times', type=int, default=N_SCENARIOS, help='number of evaluation scenarios per job')
    parser.add_argument('--workers', type=int, default=1, help='number of concurrent evaluation subprocesses')
    parser.add_argument('--datasets', nargs='+', default=None, help='explicit dataset filenames or stems inside --dataset-dir')
    parser.add_argument('--detectors', nargs='+', default=None, help='detector names to evaluate, or "all"')
    parser.add_argument('--mappers', nargs='+', default=None, help='attack-type mapper names to evaluate, or "all"')
    parser.add_argument('--resume', action='store_true', help='skip jobs whose summary and iteration CSVs already exist and are non-empty')
    parser.add_argument('--anomaly-thresholds', nargs='+', type=float, default=None, help='anomaly score thresholds to evaluate')
    parser.add_argument('--suspect-thresholds', nargs='+', type=float, default=None, help='suspect score thresholds to evaluate')
    parser.add_argument('--type-threshold', type=float, default=TYPE_THRESHOLD, help='attack-type mapper score threshold')
    parser.add_argument('--suspect-max-length', type=int, default=None, help='maximum buffered suspect flows (-1 for unbounded)')
    parser.add_argument('--log-flow-exploits-threshold', type=int, default=None, help='alert count threshold before archiving flow exploits (-1 disables)')
    parser.add_argument('--log-states-threshold', type=int, default=None, help='state count threshold before archiving states (-1 disables)')
    parser.add_argument('--max-idle-gap', type=float, default=None, help='maximum idle gap in seconds for step aggregation')
    parser.add_argument('--edge-recovery-threshold', type=float, default=None, help='minimum edge recovery fraction for scenario detection')
    parser.add_argument('--normal-divisor', type=int, default=None, help='subsampling divisor for background normal flows')
    if pre_args.policy_config is not None:
        try:
            parser.set_defaults(**load_policy_config(pre_args.policy_config, scope='batch'))
        except ValueError as exc:
            parser.error(str(exc))
    args = parser.parse_args(argv)
    _validate_args(parser, args)

    has_job_overrides = any(
        value is not None
        for value in (
            args.policy_config, args.datasets, args.detectors, args.mappers,
            args.anomaly_thresholds, args.suspect_thresholds,
        )
    ) or args.dataset_dir != DATASET_ROOT

    if has_job_overrides:
        dataset_files = resolve_dataset_files(args.datasets, args.detectors, args.mappers)
        anomaly_thresholds = (
            args.anomaly_thresholds if args.anomaly_thresholds is not None else ANOMALY_THRESHOLDS
        )
        suspect_thresholds = (
            args.suspect_thresholds if args.suspect_thresholds is not None else SUSPECT_THRESHOLDS
        )
        jobs = build_jobs(
            dataset_dir=args.dataset_dir,
            results_dir=args.results_dir,
            dataset_files=dataset_files,
            anomaly_thresholds=anomaly_thresholds,
            suspect_thresholds=suspect_thresholds,
        )
    else:
        jobs = build_jobs()
        if args.results_dir != OUTPUT_ROOT:
            jobs = [
                EvaluationJob(
                    job.input_file,
                    str(Path(args.results_dir) / Path(job.output_file).name),
                    job.anomaly_threshold,
                    job.suspect_threshold,
                )
                for job in jobs
            ]

    # Invalidate previous combined reports even if this batch fails or is interrupted.
    # Individual job outputs are retained for diagnosis but do not imply success.
    for filename in (BATCH_SUMMARY_FILENAME, BATCH_ITERATIONS_FILENAME):
        (Path(args.results_dir) / filename).unlink(missing_ok=True)

    results_by_index: dict[int, bool] = {}
    pending: list[tuple[int, EvaluationJob, list[str]]] = []
    for index, job in enumerate(jobs):
        if args.resume and _job_outputs_ready(job):
            if not args.quiet:
                print(f'skipping completed job: {job.output_file}')
            results_by_index[index] = True
        else:
            pending.append((index, job, _build_command(job, args)))

    if args.workers == 1:
        for index, job, command in pending:
            results_by_index[index] = _run_job(job, command, args.type_threshold, args.quiet)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(_run_job, job, command, args.type_threshold, args.quiet): index
                for index, job, command in pending
            }
            for future in as_completed(futures):
                index = futures[future]
                results_by_index[index] = future.result()

    successful_jobs = [job for index, job in enumerate(jobs) if results_by_index.get(index)]
    aggregate_batch_results(
        args.results_dir,
        summary_paths=[default_summary_csv_path(job.output_file) for job in successful_jobs],
        iteration_paths=[default_iterations_csv_path(job.output_file) for job in successful_jobs],
    )


if __name__ == '__main__':
    main()
