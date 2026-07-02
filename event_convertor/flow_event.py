from datetime import datetime


class FlowEvent:

    def __init__(self, source_ip: str, source_port: str, destination_ip: str, destination_port: str, protocol: str,
                 start_time: datetime, end_time: datetime, anomaly_score: float, attack_scores: dict[str, float]):

        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip 
        self.destination_port = destination_port
        self.protocol = protocol
        self.start_time = start_time
        self.end_time=end_time
        self.anomaly_score = anomaly_score 
        self.attack_scores = attack_scores

    def __str__(self):
        return f"[source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, start_time={self.start_time}, end_time={self.end_time}, anomaly_score={self.anomaly_score}{", " if self.attack_scores else ""}{", ".join([f"{k}={v}" for k, v in self.attack_scores.items()])}]"

    def to_dict(self):
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "anomaly_score": self.anomaly_score,
            **self.attack_scores,
        }

    @staticmethod
    def from_dict(data: dict) -> "FlowEvent":
        return FlowEvent(source_ip=data["source_ip"], source_port=data["source_port"],
                         destination_ip=data["destination_ip"], destination_port=data["destination_port"],
                         protocol=data["protocol"], start_time=data["start_time"], end_time=data["end_time"],
                         anomaly_score=data["anomaly_score"], attack_scores={
                k: v
                for k, v in data.items()
                if k
                   not in {
                       "source_ip",
                       "source_port",
                       "destination_ip",
                       "destination_port",
                       "protocol",
                       "start_time",
                       "end_time",
                       "anomaly_score",
                   }
            })

    @staticmethod
    def from_str(string: str) -> "FlowEvent":
        parts = string.strip("[]").split(", ")
        data = {}
        for part in parts:
            key, value = part.split("=")
            data[key] = value
        return FlowEvent(source_ip=data["source_ip"], source_port=data["source_port"],
                         destination_ip=data["destination_ip"], destination_port=data["destination_port"],
                         protocol=data["protocol"], start_time=datetime.fromisoformat(data["start_time"]),
                         end_time=datetime.fromisoformat(data["end_time"]), anomaly_score=float(data["anomaly_score"]),
                         attack_scores={
                             k: float(v)
                             for k, v in data.items()
                             if k
                                not in {
                                    "source_ip",
                                    "source_port",
                                    "destination_ip",
                                    "destination_port",
                                    "protocol",
                                    "start_time",
                                    "end_time",
                                    "anomaly_score",
                                }
                         })
