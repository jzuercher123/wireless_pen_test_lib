# core/modules/machine_learning/anomaly_detection.py

import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import List, Dict

class AnomalyDetector:
    def __init__(self, data: pd.DataFrame):
        """
        Initializes the AnomalyDetector.

        Args:
            data (pd.DataFrame): The dataset for anomaly detection.
        """
        self.data = data
        self.model = IsolationForest(contamination=0.05)

    def train_model(self):
        """
        Trains the anomaly detection model.
        """
        self.model.fit(self.data)

    def detect_anomalies(self) -> pd.DataFrame:
        """
        Detects anomalies in the dataset.

        Returns:
            pd.DataFrame: Data containing anomalies.
        """
        self.data['anomaly'] = self.model.predict(self.data)
        anomalies = self.data[self.data['anomaly'] == -1]
        return anomalies
