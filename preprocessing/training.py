"""Training-defined schema, encoding, validation partitioning, and calibration."""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


def align_test_schema(train, test):
    # The training schema is authoritative. Missing evaluation features are an
    # explicit error; silently dropping training features changes the model.
    missing = train.columns.difference(test.columns)
    if len(missing):
        raise ValueError(f"Test data is missing training columns: {list(missing)}")
    columns = list(train.columns)
    if "index" in test and "index" not in columns:
        columns.append("index")
    return test.loc[:, columns].copy()


def filter_known_test_classes(train, test):
    # Preserve the existing known-class evaluation policy without changing train.
    return test[test["label"].isin(train["label"].unique())].copy()


def encode_binary_labels(dataframe, tags):
    """Encode target classes and fit categories on a private training frame."""
    dataframe = dataframe.copy()
    dataframe['label'] = dataframe['label'].isin(tags).astype(int)
    categories = {}
    for column in _categorical_columns(dataframe):
        categories[column] = pd.Index(dataframe[column].unique())
        dataframe[column] = pd.Categorical(dataframe[column], categories=categories[column]).codes
    return dataframe, categories


def apply_label_encoding(dataframe, tags, categories):
    """Apply training categories, retaining -1 for unseen categorical values."""
    dataframe = dataframe.copy()
    dataframe['label'] = dataframe['label'].isin(tags).astype(int)
    for column in _categorical_columns(dataframe):
        dataframe[column] = pd.Categorical(dataframe[column], categories=categories[column]).codes
    return dataframe


def _categorical_columns(dataframe):
    return [column for column in dataframe.columns
            if pd.api.types.is_object_dtype(dataframe[column].dtype)
            or pd.api.types.is_string_dtype(dataframe[column].dtype)]


def calibrate_threshold(predictor, features, labels, recall):
    """Choose a strict score > threshold cutoff using validation data only."""
    if not 0 <= recall <= 1:
        raise ValueError("recall must be between zero and one")
    scores = np.asarray(predictor.predict_proba(features)[:, 1], dtype=float)
    labels = np.asarray(labels)
    if not len(scores) or len(scores) != len(labels) or not np.isfinite(scores).all():
        raise ValueError("Validation scores must be nonempty, finite, and aligned with labels")
    if recall == 0:
        threshold = float(scores.max())  # Strict score > threshold predicts none.
    else:
        positives = np.sort(scores[labels == 1])[::-1]
        if not len(positives):
            raise ValueError("Recall calibration requires positive validation examples")
        required = int(np.ceil(recall * len(positives)))
        # Match the reconstructor's strict > boundary, including tied positives.
        threshold = float(np.nextafter(positives[required - 1], -np.inf))
    return threshold


def split_training_validation(train, attack_labels, *, test_size=0.2, random_state=42):
    """Reserve a reproducible binary-stratified validation partition before fitting."""
    return train_test_split(train, test_size=test_size, random_state=random_state,
                            stratify=train["label"].isin(attack_labels))
