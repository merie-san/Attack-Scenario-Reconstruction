"""Core template validation on caller-independent dataframes."""
import numpy as np
import pandas as pd
from .exceptions import ScenarioGenerationError

def validate_templates(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Validate core flow fields and normalize a private copy of the templates."""
    if not isinstance(dataframe, pd.DataFrame):
        raise TypeError("Templates must be provided as a pandas DataFrame")
    required = {"timestamp", "duration", "label", "step_number"}
    missing = required - set(dataframe.columns)
    if missing:
        raise ScenarioGenerationError(f"Templates are missing required columns: {', '.join(sorted(missing))}")
    if dataframe.empty or not dataframe.columns.is_unique:
        raise ScenarioGenerationError("Templates must be nonempty and have unique column names")
    templates = dataframe.copy(deep=True)
    if templates[["label", "step_number"]].isna().any().any():
        raise ScenarioGenerationError("Template labels and step numbers must not be missing")
    try:
        templates["timestamp"] = pd.to_datetime(templates["timestamp"], errors="raise")
    except (TypeError, ValueError, OverflowError) as error:
        raise ScenarioGenerationError("Template timestamps must be valid, consistently represented datetimes") from error
    if templates["timestamp"].isna().any():
        raise ScenarioGenerationError("Template timestamps must not be missing")
    try:
        durations = pd.to_numeric(templates["duration"], errors="raise")
    except (TypeError, ValueError) as error:
        raise ScenarioGenerationError("Template durations must be numeric milliseconds") from error
    if (pd.api.types.is_bool_dtype(durations.dtype) or np.iscomplexobj(durations.to_numpy()) or durations.isna().any()
            or not np.isfinite(durations).all() or durations.lt(0).any()):
        raise ScenarioGenerationError("Template durations must be finite, nonnegative milliseconds")
    try:
        flow_ends = templates["timestamp"] + pd.to_timedelta(durations, unit="ms", errors="raise")
    except (TypeError, ValueError, OverflowError) as error:
        raise ScenarioGenerationError("Template flow end times exceed the supported datetime range") from error
    if flow_ends.isna().any():
        raise ScenarioGenerationError("Template flow end times must not be missing")
    templates["duration"] = durations
    return templates
