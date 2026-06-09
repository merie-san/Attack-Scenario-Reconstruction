import os
import pandas as pd
import numpy as np
from event_generator.flow_event_generator import FlowEventGenerator

if __name__ == "__main__":
    generator = FlowEventGenerator(timestamp_template="%d/%m/%Y %H:%M")
    files = os.listdir("./event_generator/TrafficLabelling")
    for file in files:
        if file.endswith(".csv"):
            df = pd.read_csv(f"./event_generator/TrafficLabelling/{file}")
            df.columns = df.columns.str.strip()
            df.dropna(inplace=True)
            df.replace([np.inf, -np.inf], -1, inplace=True)
            df=df.drop(["Label"], axis=1)
            generator.log_events(df, f"./event_generator/flows/FlowEvents_{file.split('.')[0]}.log", attack_score_cols=[])
