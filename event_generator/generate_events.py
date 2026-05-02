import os
import pandas as pd
import pickle
import numpy as np
from event_generator.flow_event_generator import FlowEventGenerator

if __name__ == "__main__":
    detector = pickle.load(open("../anomaly_detector/lda.pkl", "rb"))
    generator = FlowEventGenerator(detector=detector)
    files = os.listdir("./TrafficLabelling")
    for file in files:
        if file.endswith(".csv"):
            df = pd.read_csv(f"./TrafficLabelling/{file}", encoding="latin1")
            df.columns = df.columns.str.strip()
            df.dropna(inplace=True)
            df.replace([np.inf, -np.inf], -1, inplace=True)
            generator.log_events(df, f"./FlowEvents_{file.split('.')[0]}.log")
