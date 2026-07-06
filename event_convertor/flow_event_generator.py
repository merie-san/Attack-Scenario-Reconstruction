from typing import cast

import pandas as pd
from event_convertor.flow_event import FlowEvent
from datetime import timedelta, datetime


class CAPTureFlowEventConvertor:

    @staticmethod
    def convert(df: pd.DataFrame) -> list[FlowEvent]:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        flow_events = []
        for row in df.itertuples(index=False):
            flow_events.append(FlowEvent(cast(str, row.src_ip), cast(str, row.src_port), cast(str, row.dst_ip),
                                         cast(str, row.dst_port),
                                         cast(str, row.protocol), cast(datetime, row.timestamp),
                                         cast(datetime, row.timestamp) + timedelta(
                                             milliseconds=cast(int, row.duration)), cast(float, row.anomaly_score),
                                         {
                                             "nmap_10_T5": cast(float, row.nmap_10_T5),
                                             "nmap_mqtt": cast(float, row.nmap_mqtt),
                                             "nmap_banner": cast(float, row.nmap_banner),
                                             "brute_force_malformed": cast(float, row.brute_force_malformed),
                                             "dollar_char": cast(float, row.dollar_char),
                                             "scp_inst": cast(float, row.scp_inst)}))
        return flow_events
