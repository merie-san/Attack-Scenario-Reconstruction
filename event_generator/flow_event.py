from datetime import datetime


class FlowEvent:

    def __init__(
        self,
        flow_id: str,
        source_ip: str,
        source_port: str | int,
        destination_ip: str,
        destination_port: str | int,
        protocol: str,
        timestamp: str | datetime,
        anomaly_score: str | float,
        timestamp_template: str | None = None,
        other_attributes: dict | None = None,
    ):
        if isinstance(timestamp, str):
            if timestamp_template:
                timestamp = datetime.strptime(timestamp, timestamp_template)
            else:
                timestamp = datetime.fromisoformat(timestamp)

        self.flow_id = flow_id
        self.source_ip = source_ip
        self.source_port = int(source_port)
        self.destination_ip = destination_ip 
        self.destination_port = int(destination_port) 
        self.protocol = protocol
        self.timestamp = timestamp
        self.anomaly_score = float(anomaly_score) 
        self.other_attributes = other_attributes if other_attributes is not None else {}

    def __str__(self):
        other_attrs_str = ", ".join(
            f"{key}={value}" for key, value in self.other_attributes.items()
        )
        return (
            f"[flow_id={self.flow_id}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, timestamp={self.timestamp}, anomaly_score={self.anomaly_score}, {other_attrs_str}]"
            if other_attrs_str
            else f"[flow_id={self.flow_id}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, timestamp={self.timestamp}, anomaly_score={self.anomaly_score}]"
        )

    def to_dict(self):
        return {
            "flow_id": self.flow_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "anomaly_score": self.anomaly_score,
            **self.other_attributes,
        }

    @staticmethod
    def from_dict(data: dict,timestamp_template: str | None = None,) -> "FlowEvent":
        return FlowEvent(
            flow_id=data["flow_id"],
            source_ip=data["source_ip"],
            source_port=data["source_port"] ,
            destination_ip=data["destination_ip"],
            destination_port=data["destination_port"],
            protocol=data["protocol"],
            timestamp=data["timestamp"],
            anomaly_score=data["anomaly_score"],
            timestamp_template=timestamp_template,
            other_attributes={
                k: v
                for k, v in data.items()
                if k
                not in {
                    "flow_id",
                    "source_ip",
                    "source_port",
                    "destination_ip",
                    "destination_port",
                    "protocol",
                    "timestamp",
                    "anomaly_score",
                }
            },
        )

    @staticmethod
    def from_str(string: str, timestamp_template: str | None = None,) -> "FlowEvent":
        parts = string.strip("[]").split(", ")
        data = {}
        for part in parts:
            key, value = part.split("=")
            data[key] = value
        return FlowEvent(
            flow_id=data["flow_id"],
            source_ip=data["source_ip"],
            source_port=data["source_port"],
            destination_ip=data["destination_ip"],
            destination_port=data["destination_port"],
            protocol=data["protocol"],
            timestamp=data["timestamp"],
            anomaly_score=data["anomaly_score"],
            timestamp_template=timestamp_template,
            other_attributes={
                k: v
                for k, v in data.items()
                if k
                not in {
                    "flow_id",
                    "source_ip",
                    "source_port",
                    "destination_ip",
                    "destination_port",
                    "protocol",
                    "timestamp",
                    "anomaly_score",
                }
            },
        )
