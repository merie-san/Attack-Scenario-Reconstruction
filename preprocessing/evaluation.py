"""Evaluation and plotting helpers for binary anomaly detectors and attack-type mappers."""
import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    PrecisionRecallDisplay,
    RocCurveDisplay,
    accuracy_score,
    average_precision_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def evaluate_classifier(predictor, X_test, y_test, name: str) -> dict[str, float]:
    """Print and return test accuracy, recall, and precision for a binary classifier."""
    y_pred = predictor.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    print(f"{name} test accuracy: {acc:.3f}")
    print(f"{name} test recall: {rec:.3f}")
    print(f"{name} test precision: {prec:.3f}")
    return {"accuracy": acc, "recall": rec, "precision": prec}


def _plot_curve_on_axis(ax, y_true, y_prob, estimator_name: str, curve_kind: str) -> None:
    if curve_kind == "roc":
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc = roc_auc_score(y_true, y_prob)
        RocCurveDisplay(fpr=fpr, tpr=tpr, roc_auc=roc_auc, name=estimator_name).plot(ax=ax)
    elif curve_kind == "prc":
        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        avg_precision = average_precision_score(y_true, y_prob)
        PrecisionRecallDisplay(
            precision=precision, recall=recall, average_precision=avg_precision, name=estimator_name
        ).plot(ax=ax)
    else:
        raise ValueError(f"Unsupported curve_kind: {curve_kind!r}")


def _finish_figure(fig, save_path: Path | None, show: bool) -> None:
    if save_path is not None:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    if show:
        plt.show()
    else:
        plt.close(fig)


def _plot_binary_curve(predictor, X_test, y_test, name: str, curve_kind: str, title_prefix: str, *, plots_dir=None, show: bool = True) -> np.ndarray:
    y_prob = predictor.predict_proba(X_test)[:, 1]
    if len(np.unique(y_test)) < 2:
        print(f"Skipping {curve_kind.upper()} for {name}: fewer than 2 unique labels in y_test")
        return y_prob

    fig, ax = plt.subplots(figsize=(6, 5))
    _plot_curve_on_axis(ax, y_test, y_prob, name, curve_kind)
    ax.set_title(name)
    ax.grid(True)
    fig.suptitle(f"{title_prefix} ({name})", fontsize=18)
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    save_path = Path(plots_dir) / f"{curve_kind}_{name}.png" if plots_dir is not None else None
    _finish_figure(fig, save_path, show)
    return y_prob


def plot_roc_curve(predictor, X_test, y_test, name: str, *, plots_dir=None, show: bool = True) -> np.ndarray:
    """Compute test probabilities and plot the binary ROC curve if both classes exist."""
    return _plot_binary_curve(predictor, X_test, y_test, name, "roc", "ROC Curve", plots_dir=plots_dir, show=show)


def plot_prc_curve(predictor, X_test, y_test, name: str, *, plots_dir=None, show: bool = True) -> np.ndarray:
    """Compute test probabilities and plot the binary Precision-Recall curve if both classes exist."""
    return _plot_binary_curve(predictor, X_test, y_test, name, "prc", "Precision-Recall Curve", plots_dir=plots_dir, show=show)


def evaluate_mappers(mapper_dict, X_test_dict, y_test_dict, name: str) -> dict[str, dict[str, float | None]]:
    """Print and return per-attack-type accuracy, recall, and precision metrics."""
    results: dict[str, dict[str, float | None]] = {}
    for label, model in mapper_dict.items():
        y_true = y_test_dict[label]
        y_pred = model.predict(X_test_dict[label])
        acc = float(accuracy_score(y_true, y_pred))
        if len(np.unique(y_true)) < 2:
            print(f"{name} test accuracy for {label}: {acc:.3f} (fewer than 2 unique labels in test set; recall/precision skipped)")
            results[label] = {"accuracy": acc, "recall": None, "precision": None}
            continue
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        print(f"{name} test accuracy for {label}: {acc:.3f}")
        print(f"{name} test recall for {label}: {rec:.3f}")
        print(f"{name} test precision for {label}: {prec:.3f}")
        results[label] = {"accuracy": acc, "recall": rec, "precision": prec}
    return results


def _plot_mapper_curves(mapper_dict, X_test_dict, y_test_dict, name: str, curve_kind: str, title_prefix: str, *, plots_dir=None, show: bool = True, n_cols: int = 3) -> dict[str, np.ndarray]:
    prob_dict: dict[str, np.ndarray] = {}
    n_plots = len(mapper_dict)
    if n_plots == 0:
        return prob_dict

    n_rows = math.ceil(n_plots / n_cols)
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(6 * n_cols, 5 * n_rows))
    axes = np.atleast_1d(axes).ravel()

    for ax, (label, predictor) in zip(axes, mapper_dict.items()):
        y_true = y_test_dict[label]
        y_prob = predictor.predict_proba(X_test_dict[label])[:, 1]
        prob_dict[label] = y_prob

        if len(np.unique(y_true)) < 2:
            print(f"Skipping {curve_kind.upper()} for {name} / {label}: fewer than 2 unique labels in test set")
            ax.text(0.5, 0.5, f"Single class in test set\n({curve_kind.upper()} undefined)", ha="center", va="center")
            ax.set_title(f"{label} (skipped)")
            ax.grid(True)
            continue

        _plot_curve_on_axis(ax, y_true, y_prob, f"{name} {label}", curve_kind)
        ax.set_title(f"{label}")
        ax.grid(True)

    for ax in axes[n_plots:]:
        ax.set_visible(False)

    fig.suptitle(f"{title_prefix} ({name})", fontsize=18)
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    save_path = Path(plots_dir) / f"{curve_kind}_{name}_mapper.png" if plots_dir is not None else None
    _finish_figure(fig, save_path, show)
    return prob_dict


def plot_mapper_roc_curves(mapper_dict, X_test_dict, y_test_dict, name: str, *, plots_dir=None, show: bool = True, n_cols: int = 3) -> dict[str, np.ndarray]:
    """Plot a grid of ROC curves for per-attack-type mappers."""
    return _plot_mapper_curves(
        mapper_dict, X_test_dict, y_test_dict, name, "roc", "ROC Curves", plots_dir=plots_dir, show=show, n_cols=n_cols
    )


def plot_mapper_prc_curves(mapper_dict, X_test_dict, y_test_dict, name: str, *, plots_dir=None, show: bool = True, n_cols: int = 3) -> dict[str, np.ndarray]:
    """Plot a grid of Precision-Recall curves for per-attack-type mappers."""
    return _plot_mapper_curves(
        mapper_dict, X_test_dict, y_test_dict, name, "prc", "Precision-Recall Curves", plots_dir=plots_dir, show=show, n_cols=n_cols
    )
