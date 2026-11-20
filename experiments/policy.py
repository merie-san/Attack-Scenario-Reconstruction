"""Load and validate JSON reconstruction and batch experiment policy configs."""
import json
import math
from pathlib import Path
from typing import Literal

CAPTURE_POLICY_KEYS = frozenset({
    'config',
    'times',
    'seed',
    'quiet',
    'anomaly_threshold',
    'suspect_threshold',
    'type_threshold',
    'max_idle_gap',
    'suspect_max_length',
    'log_flow_exploits_threshold',
    'log_states_threshold',
    'edge_recovery_threshold',
    'normal_divisor',
})

BATCH_ONLY_POLICY_KEYS = frozenset({
    'dataset_dir',
    'results_dir',
    'workers',
    'datasets',
    'detectors',
    'mappers',
    'resume',
    'anomaly_thresholds',
    'suspect_thresholds',
})

ALL_POLICY_KEYS = CAPTURE_POLICY_KEYS | BATCH_ONLY_POLICY_KEYS

_STRING_FIELDS = frozenset({'config', 'dataset_dir', 'results_dir'})
_NULLABLE_STRING_LIST_FIELDS = frozenset({'datasets', 'detectors', 'mappers'})
_INT_FIELDS = frozenset({
    'times',
    'workers',
    'suspect_max_length',
    'log_flow_exploits_threshold',
    'log_states_threshold',
    'normal_divisor',
})
_FLOAT_FIELDS = frozenset({
    'anomaly_threshold',
    'suspect_threshold',
    'type_threshold',
    'max_idle_gap',
    'edge_recovery_threshold',
})
_FLOAT_LIST_FIELDS = frozenset({'anomaly_thresholds', 'suspect_thresholds'})
_BOOL_FIELDS = frozenset({'resume', 'quiet'})


def _validate_int(value: object, key: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f'Policy field {key!r} must be an integer')
    return value


def _validate_float(value: object, key: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f'Policy field {key!r} must be a finite number')
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f'Policy field {key!r} must be a finite number')
    return number


def _validate_value(key: str, value: object) -> object:
    if key in _STRING_FIELDS:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f'Policy field {key!r} must be a non-empty string')
        return value
    if key in _NULLABLE_STRING_LIST_FIELDS:
        if value is None:
            return None
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item.strip() for item in value)
        ):
            raise ValueError(f'Policy field {key!r} must be null or a non-empty list of non-empty strings')
        return list(value)
    if key == 'seed':
        if value is None:
            return None
        return _validate_int(value, key)
    if key in _INT_FIELDS:
        return _validate_int(value, key)
    if key in _FLOAT_FIELDS:
        return _validate_float(value, key)
    if key in _FLOAT_LIST_FIELDS:
        if not isinstance(value, list) or not value:
            raise ValueError(f'Policy field {key!r} must be a non-empty list of numbers')
        return [_validate_float(item, key) for item in value]
    if key in _BOOL_FIELDS:
        if not isinstance(value, bool):
            raise ValueError(f'Policy field {key!r} must be a boolean')
        return value
    raise ValueError(f'Unknown policy field: {key!r}')


def load_policy_config(
    path: str | Path,
    *,
    scope: Literal['batch', 'capture'] = 'batch',
) -> dict[str, object]:
    """Load and type-validate a JSON policy configuration for batch or capture runners."""
    if scope not in ('batch', 'capture'):
        raise ValueError(f'Unsupported policy scope: {scope!r}')
    config_path = Path(path)
    try:
        raw_text = config_path.read_text(encoding='utf-8')
    except OSError as exc:
        raise ValueError(f'Unable to read policy config {config_path}: {exc}') from exc
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f'Invalid JSON in policy config {config_path}: {exc}') from exc
    if not isinstance(raw, dict):
        raise ValueError(f'Policy config {config_path} must contain a JSON object')

    unknown = set(raw) - ALL_POLICY_KEYS
    if unknown:
        raise ValueError(f"Unknown policy configuration keys: {', '.join(sorted(unknown))}")

    validated = {key: _validate_value(key, value) for key, value in raw.items()}

    if scope == 'capture':
        return {key: value for key, value in validated.items() if key in CAPTURE_POLICY_KEYS}

    if 'anomaly_threshold' in validated and 'anomaly_thresholds' in validated:
        raise ValueError("Policy config cannot specify both 'anomaly_threshold' and 'anomaly_thresholds'")
    if 'suspect_threshold' in validated and 'suspect_thresholds' in validated:
        raise ValueError("Policy config cannot specify both 'suspect_threshold' and 'suspect_thresholds'")

    batch_values = {
        key: value
        for key, value in validated.items()
        if key not in ('anomaly_threshold', 'suspect_threshold')
    }
    if 'anomaly_threshold' in validated:
        batch_values['anomaly_thresholds'] = [validated['anomaly_threshold']]
    if 'suspect_threshold' in validated:
        batch_values['suspect_thresholds'] = [validated['suspect_threshold']]
    return batch_values
