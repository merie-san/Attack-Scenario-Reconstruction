from collections.abc import Hashable

import pandas as pd
import numpy as np


class ScenarioGenerator:

    def __init__(self, dataframe: pd.DataFrame, root_attack: str, next_attack_dict: dict[str, list[str]]) -> None:
        self.data_source: dict[Hashable, dict[Hashable, pd.DataFrame]] = {}
        self.root_attack = root_attack
        self.next_attack_dict = next_attack_dict

        for (label, step_number), group in dataframe.groupby(["label", "step_number"]):
            self.data_source.setdefault(label, {})[step_number] = group
