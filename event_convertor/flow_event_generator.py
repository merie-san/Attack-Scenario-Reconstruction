import pandas as pd
from event_convertor.flow_event import FlowEvent
from datetime import timedelta


class CAPTureFlowEventConvertor:

    def convert(self, df: pd.DataFrame) -> list[FlowEvent]:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        flow_events = []
        for _, row in df.itertuples():
            flow_events.append(FlowEvent(row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"],
                                         row["protocol"], row["timestamp"],
                                         row["timestamp"] + timedelta(
                                             milliseconds=row["duration"]), row["anomaly_score"],
                                         {
                "nmap_10_T5": row["nmap_10_T5"], "nmap_mqtt": row["nmap_mqtt"], "nmap_banner": row["nmap_banner"],
                "brute_force_malformed": row["brute_force_malformed"], "dollar_char": row["dollar_char"],
                "scp_inst": row["scp_inst"]}))
        return flow_events
