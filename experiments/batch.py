"""Configured batch dispatch using the active interpreter and argument lists."""
import subprocess
import sys
from dataclasses import dataclass

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


def main():
    for job in build_jobs():
        print(
            f"evaluating reconstruction mechanism for {job.input_file} "
            f"with anomaly threshold {job.anomaly_threshold}, "
            f"suspect threshold {job.suspect_threshold}, type threshold {TYPE_THRESHOLD}")
        code = subprocess.run([
            sys.executable, "-m", "experiments.capture",
            "-f", job.input_file, "-t", str(N_SCENARIOS),
            "--anomaly-threshold", str(job.anomaly_threshold),
            "--suspect-threshold", str(job.suspect_threshold),
            "--type-threshold", str(TYPE_THRESHOLD), "-l", job.output_file,
        ], check=False).returncode
        if code != 0:
            print(f"FAILED (exit {code}): {job.output_file}")


if __name__ == "__main__":
    main()
