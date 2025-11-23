"""
Defines the analyzer interface:
- what input they accept (event or session)
- what output they produce (analysis results)

Maintains a registry so the agent can dynamically discover and run analyzers
configured in config/default.yaml.
"""
from blueflux_core.analyzers.network_behavior import NetworkBehaviorScenario
from blueflux_core.analyzers.logger_config import setup_logger

logger = setup_logger()

class BaseAnalyzer:
    def __init__(self):
        self.dataset = None
        self.model = None

    def load_dataset(self, dataset_path: str):
        """ Load dataset from the given path. """
        netscen_malware = NetworkBehaviorScenario(path=dataset_path, 
                                    skip_n_rows=10, 
                                    time_window_size='5s')
        
        self.dataset = netscen_malware.return_data()


    def train_model(self):
        """ Train the analysis model on the loaded dataset. """
        if self.dataset is None:
            raise ValueError("Dataset not loaded. Call load_dataset() first.")
        
        self.model = "trained_model_placeholder"


    def analyze(self, input_data):
        """ Analyze the input data using the trained model. """
        if self.model is None:
            raise ValueError("Model not trained. Call train_model() first.")
        
        analysis_result = {"result": "analysis_placeholder"}
        return analysis_result



if __name__ == "__main__":

    analyzer = BaseAnalyzer()
    path_to_data = "infra/logs/llm_logs/scenario_events.jsonl"

    # @TODO Augment for Supervised if normal behavior is provided
    analyzer.load_dataset(dataset_path=path_to_data)


