"""
Consumes sessions with both LLM usage and network summaries.
Applies heuristics such as:
- new or rare domains contacted shortly after suspicious LLM usage
- periodic egress to fixed endpoints (beacon-like)
- unusual ports or protocols

Emits a risk contribution based on how strange the traffic is.
"""
from dataclasses import dataclass, field
import pandas as pd 
import json

from blueflux_core.analyzers.logger_config import setup_logger

logger = setup_logger()

INCLUDED_FEATURES_FOR_ANALYSIS = ["timestamp_iso", "event_type", "data"]


def load_network_trace(path: str) -> pd.DataFrame:
    """ Load a JSON-lines dataset """
    records = []
    
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue 
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Skipping invalid JSON line: {e}")

    df = pd.DataFrame(records)

    if not all(col in df.columns for col in INCLUDED_FEATURES_FOR_ANALYSIS):
        raise ValueError("Input data is missing required columns for analysis.")
    
    return df[INCLUDED_FEATURES_FOR_ANALYSIS]


def resample_data(data: pd.DataFrame, window_size: str = '10s') -> pd.DataFrame:
    """Resample network event data."""
    data['timestamp'] = pd.to_datetime(data['timestamp_iso'])
    data.set_index('timestamp', inplace=True)

    agg_df = data.resample(window_size).agg({
        'event_type': ['count', lambda x: list(x)],   
        'data': lambda x: list(x) })
    agg_df.columns = ['event_count', 'event_types', 'data']
    return agg_df

def set_data_event_types(data: pd.DataFrame) -> pd.DataFrame:
    """ Get unique event action types from the data column."""
    all_unique_actions = set()

    for events_list in data['data']:
        for event in events_list:
            if 'action' in event:
                all_unique_actions.add(event['action'])
    
    return all_unique_actions


def get_event_type_counts_vars(data: pd.DataFrame) -> pd.DataFrame:
    """ Count occurrences of each event type in the data column."""
    event_type_counts = [{action: 0 for action in set_data_event_types(data)} for _ in range(0, data.shape[0])]
    for row_i, (_, row) in enumerate(data.iterrows()):
        events_list = row['data']
        logger.debug(f"Processing record {row_i} with {len(events_list)} events.")
        
        for event in events_list:
            if 'action' in event:
                action = event['action']
                event_type_counts[row_i][action] += 1
    
    return pd.DataFrame(event_type_counts)


def one_hot_encode_event_types(df: pd.DataFrame, column: str = "event_types") -> pd.DataFrame:
    """ One-hot encode a column containing lists of event types. """
    df = df.copy()
    df[column] = df[column].apply(lambda x: x if isinstance(x, list) else [])
    all_event_types = sorted({evt for sublist in df[column] for evt in sublist})

    for evt in all_event_types:
        df[evt] = df[column].apply(lambda events: 1 if evt in events else 0)

    return df


@dataclass
class NetworkBehaviorScenario:
    path: str
    skip_n_rows: int = 0
    time_window_size: int = 10
    data: pd.DataFrame = field(init=False)

    def __post_init__(self):
        self.data = load_network_trace(self.path)[self.skip_n_rows:]
        logger.info(f"Loaded {len(self.data)} records from {self.path}.")

        self.preprocess_data()
        self.feat_engineering()
        logger.info("Completed feature engineering on the dataset.")

    def preprocess_data(self):
        self.data = resample_data(self.data, window_size=self.time_window_size)
        self.data = self.data[self.data['event_count'] > 0]

    def feat_engineering(self):
        event_type_counts_df = get_event_type_counts_vars(self.data)
        event_type_counts_df.index = self.data.index
        self.data = pd.concat([self.data, event_type_counts_df], axis=1)
        self.data = one_hot_encode_event_types(self.data, column="event_types")


if __name__ == "__main__":
    
    # @TODO: Add a rolling window parameter to augment the resampling
    path_to_data = "infra/logs/llm_logs/scenario_events.jsonl"

    netscen = NetworkBehaviorScenario(path=path_to_data, 
                                      skip_n_rows=10, 
                                      time_window_size='5s')
    
    netscen.data.to_parquet("infra/data/network_behavior_dataset.parquet")