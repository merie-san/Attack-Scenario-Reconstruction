from datetime import datetime

class FlowEvent:

    def __init__(self, flow_id: str, source_ip: str, source_port: int, destination_ip: str, destination_port: int, protocol: str, timestamp: datetime, anomaly_score: float):
        self.flow_id = flow_id
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.protocol = protocol
        self.timestamp = timestamp
        self.anomaly_score = anomaly_score

    def __str__(self):
        return f"[flow_id={self.flow_id}, source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, protocol={self.protocol}, timestamp={self.timestamp}, anomaly_score={self.anomaly_score}]"
    
    def to_dict(self):
        return {
            "flow_id": self.flow_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "anomaly_score": self.anomaly_score
        }
    
    @staticmethod
    def from_dict(data: dict) -> "FlowEvent":
        return FlowEvent(
            flow_id=data["flow_id"],
            source_ip=data["source_ip"],
            source_port=data["source_port"],
            destination_ip=data["destination_ip"],
            destination_port=data["destination_port"],
            protocol=data["protocol"],
            timestamp=data["timestamp"],
            anomaly_score=data["anomaly_score"]
        )
    
    @staticmethod
    def from_str(string: str) -> "FlowEvent":
        parts = string.strip("[]").split(", ")
        data = {}
        for part in parts:
            key, value = part.split("=")
            data[key] = value
        return FlowEvent(
            flow_id=data["flow_id"],
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_ip=data["destination_ip"],
            destination_port=int(data["destination_port"]),
            protocol=data["protocol"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            anomaly_score=float(data["anomaly_score"])
        )