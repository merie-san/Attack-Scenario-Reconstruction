"""Export evaluation records and rebuild batch CSVs without rerunning experiments."""
import argparse
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
import pandas as pd


BATCH_SUMMARY_FILENAME = 'batch_summary.csv'
BATCH_ITERATIONS_FILENAME = 'batch_iterations.csv'


@dataclass(frozen=True)
class IterationRecord:
    iteration: int
    actual_steps: int
    predicted_steps: int
    actual_alerts: int
    predicted_alerts: int
    recovered_fns: int
    rejected_fps: int
    id_tn: int
    id_fp: int
    id_fn: int
    id_tp: int
    rec_tn: int
    rec_fp: int
    rec_fn: int
    rec_tp: int
    alert_precision: float
    alert_recall: float
    step_soundness: float
    step_completeness: float
    scenario_step_precision: float
    scenario_step_recall: float
    scenario_soundness: float
    scenario_completeness: float
    scenario_detected: int


def default_iterations_csv_path(log_path: str | Path) -> Path:
    return Path(f"{str(log_path).removesuffix('.txt')}_iterations.csv")


def default_summary_csv_path(log_path: str | Path) -> Path:
    return Path(f"{str(log_path).removesuffix('.txt')}_summary.csv")


def default_fn_log_path(log_path: str | Path) -> Path:
    return Path(f"{str(log_path).removesuffix('.txt')}_fn_generating_scenarios.txt")


def parse_dataset_metadata(dataset_path: str) -> tuple[str, str, str]:
    """Split the final mapper suffix while preserving detector names with underscores."""
    path = Path(dataset_path)
    detector, separator, mapper = path.stem.removesuffix('_rec_dataset').rpartition('_')
    if detector and separator and mapper in ('xgb', 'gnb', 'lr', 'perfect'):
        return path.name, detector, mapper
    return path.name, '', ''


def write_evaluation_outputs(
    log_path: str | Path,
    records: Sequence[IterationRecord],
    metadata: Mapping[str, object],
    false_negative_scenarios_actual: Sequence[Sequence[object]],
    false_negative_scenarios_predicted: Sequence[Sequence[object]],
    iterations_csv_path: str | Path | None = None,
    summary_csv_path: str | Path | None = None,
):
    """Write the legacy text formats and structured iteration/population statistics."""
    names = [field.name for field in fields(IterationRecord)]
    frame = pd.DataFrame([asdict(record) for record in records], columns=names)
    summary = dict(metadata)
    for name in names:
        if name != 'iteration':
            values = frame[name].to_numpy()
            summary[f'{name}_mean'] = float(np.mean(values))
            summary[f'{name}_std'] = float(np.std(values, ddof=0))

    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open('w') as output:
        for suffix, label in (('tn', 'true negatives'), ('fp', 'false positives'),
                              ('fn', 'false negatives'), ('tp', 'true positives')):
            output.write(
                f"mean ID {label}: {summary[f'id_{suffix}_mean']}, "
                f"mean REC {label}: {summary[f'rec_{suffix}_mean']}\n")
        for name, label in (
            ('alert_precision', 'precision of reconstructed alerts'),
            ('alert_recall', 'recall of reconstructed alerts'),
            ('step_soundness', 'soundness of reconstructed steps'),
            ('step_completeness', 'completeness of reconstructed steps'),
            ('scenario_step_precision', 'precision of reconstructed scenarios'),
            ('scenario_step_recall', 'recall of reconstructed scenarios'),
            ('scenario_soundness', 'soundness of reconstructed scenarios'),
            ('scenario_completeness', 'completeness of reconstructed scenarios'),
            ('scenario_detected', 'scenario detection rate'),
        ):
            output.write(f"mean {label}: {summary[f'{name}_mean']}\n")

    fn_log_path = default_fn_log_path(log_path)
    fn_log_path.parent.mkdir(parents=True, exist_ok=True)
    with fn_log_path.open('w') as output:
        for index, actual in enumerate(false_negative_scenarios_actual):
            output.write('actual scenario\n')
            output.write(', '.join(str(step) for step in actual) + '\n')
            output.write('predicted scenario\n')
            output.write(', '.join(str(step) for step in false_negative_scenarios_predicted[index]) + '\n')

    iterations_path = (Path(iterations_csv_path) if iterations_csv_path is not None
                       else default_iterations_csv_path(log_path))
    summary_path = (Path(summary_csv_path) if summary_csv_path is not None
                    else default_summary_csv_path(log_path))
    iterations_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([{**metadata, **asdict(record)} for record in records],
                 columns=[*metadata, *names]).to_csv(iterations_path, index=False)
    pd.DataFrame([summary]).to_csv(summary_path, index=False)


def aggregate_batch_results(
    output_dir: str | Path,
    summary_paths: Sequence[str | Path] | None = None,
    iteration_paths: Sequence[str | Path] | None = None,
    batch_summary_name: str = BATCH_SUMMARY_FILENAME,
    batch_iterations_name: str = BATCH_ITERATIONS_FILENAME,
):
    """Concatenate available run CSVs; leave an empty workspace untouched."""
    output_dir = Path(output_dir)
    summaries = (sorted(path for path in output_dir.glob('*_summary.csv')
                        if path.name != batch_summary_name)
                 if summary_paths is None else summary_paths)
    iterations = (sorted(path for path in output_dir.glob('*_iterations.csv')
                         if path.name != batch_iterations_name)
                  if iteration_paths is None else iteration_paths)
    summaries = [Path(path) for path in summaries if Path(path).is_file()]
    iterations = [Path(path) for path in iterations if Path(path).is_file()]
    if not summaries and not iterations:
        return None, None

    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for paths, filename in ((summaries, batch_summary_name), (iterations, batch_iterations_name)):
        output_path = None
        if paths:
            output_path = output_dir / filename
            pd.concat([pd.read_csv(path) for path in paths], ignore_index=True).to_csv(output_path, index=False)
        outputs.append(output_path)
    return tuple(outputs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-d', '--results-dir', required=True, help='directory containing run CSVs')
    args = parser.parse_args(argv)
    return aggregate_batch_results(args.results_dir)


if __name__ == '__main__':
    main()
