import logging
import os
from logging.handlers import RotatingFileHandler
from core.config_manager import ConfigManager


class LogManager:
    def __init__(self, config: ConfigManager):
        self.config = config.get_config()
        self.logger = logging.getLogger()
        self.configure_logging()

    def configure_logging(self):
        # Clear existing handlers
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        # Set log level
        log_level_str = self.config.general.log_level.upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        self.logger.setLevel(log_level)

        # Create log formatter
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(name)s - %(message)s')

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler with rotation
        log_file = os.path.join(self.config.general.report_directory, '..', 'logs', 'app.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        self.logger.debug("Logging has been configured.")
