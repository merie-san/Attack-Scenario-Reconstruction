import pandas as pd
from event_convertor.flow_event_generator import CICIDSFlowEventConvertor
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
csv_path = BASE_DIR / "dataset" / "rec_dataset.csv"
log_path = BASE_DIR / "flows" / "flow_events.log"

if __name__ == "__main__":
    generator = CICIDSFlowEventConvertor(pd.read_csv(csv_path))
    generator.convert_and_persist(log_path)
