import os
import json
import logging
from typing import Any

class DataStorageManager:
    def __init__(self, report_directory: str = "reports"):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_directory = report_directory
        self.ensure_directories()

    def ensure_directories(self):
        """
        Ensures that all necessary directories exist.
        """
        data_dirs = [
            self.report_directory,
            os.path.join(self.report_directory, 'html'),
            os.path.join(self.report_directory, 'pdf'),
            os.path.join(self.report_directory, 'json'),
            os.path.join(self.report_directory, '..', 'logs')
        ]
        for directory in data_dirs:
            os.makedirs(directory, exist_ok=True)
            self.logger.debug(f"Ensured directory exists: {directory}")

    def save_json(self, data: Any, filename: str):
        """
        Saves data as a JSON file.
        """
        file_path = os.path.join(self.report_directory, 'json', filename)
        self.logger.info(f"Saving JSON data to {file_path}")
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
            self.logger.debug(f"JSON data saved successfully to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save JSON data to {file_path}: {e}")
            raise e

    def load_json(self, filename: str) -> Any:
        """
        Loads data from a JSON file.
        """
        file_path = os.path.join(self.report_directory, 'json', filename)
        self.logger.info(f"Loading JSON data from {file_path}")
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            self.logger.debug(f"JSON data loaded successfully from {file_path}")
            return data
        except Exception as e:
            self.logger.error(f"Failed to load JSON data from {file_path}: {e}")
            raise e

    def save_text(self, data: str, filename: str):
        """
        Saves data as a text file.
        """
        file_path = os.path.join(self.report_directory, 'txt', filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        self.logger.info(f"Saving text data to {file_path}")
        try:
            with open(file_path, 'w') as f:
                f.write(data)
            self.logger.debug(f"Text data saved successfully to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save text data to {file_path}: {e}")
            raise e

    def save_binary(self, data: bytes, filename: str):
        """
        Saves data as a binary file.
        """
        file_path = os.path.join(self.report_directory, 'binary', filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        self.logger.info(f"Saving binary data to {file_path}")
        try:
            with open(file_path, 'wb') as f:
                f.write(data)
            self.logger.debug(f"Binary data saved successfully to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save binary data to {file_path}: {e}")
            raise e

    def get_report_path(self, report_type: str, filename: str) -> str:
        """
        Returns the full path for a report based on its type.
        """
        valid_types = ['html', 'pdf', 'json', 'txt', 'binary']
        if report_type not in valid_types:
            self.logger.error(f"Invalid report type: {report_type}")
            raise ValueError(f"Report type must be one of {valid_types}")
        file_path = os.path.join(self.report_directory, report_type, filename)
        self.logger.debug(f"Report path for {report_type} report: {file_path}")
        return file_path
