import pandas as pd
from event_convertor.flow_event import FlowEvent
from datetime import timedelta
from pathlib import Path


class CICIDSFlowEventConvertor:

    def __init__(self, df: pd.DataFrame):
        df["Timestamp"] = pd.to_datetime(
            df["Timestamp"], dayfirst=True, format='mixed')
        self.df = df

    def convert_and_persist(self, log_path: str | Path):
        with open(log_path, "w") as log:
            for _, row in self.df.iterrows():
                event = FlowEvent(row["Source IP"], row["Source Port"], row["Destination IP"], row["Destination Port"],
                                  row["Protocol"], row["Timestamp"],
                                  row["Timestamp"] + timedelta(milliseconds=row["Flow Duration"]), row["Anomaly Score"],
                                  {
                                      "DoS Hulk": row["DoS Hulk"], "PortScan": row["PortScan"], "DDoS": row["DDoS"],
                                      "DoS GoldenEye": row["DoS GoldenEye"], "FTP-Patator": row["FTP-Patator"],
                                      "SSH-Patator": row["SSH-Patator"], "DoS slowloris": row["DoS slowloris"],
                                      "DoS Slowhttptest": row["DoS Slowhttptest"], "Bot": row["Bot"],
                                      "Web Attack  Brute Force": row["Web Attack  Brute Force"]})
                log.write(str(event)+'\n')
