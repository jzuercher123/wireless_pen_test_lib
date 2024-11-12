#!/usr/bin/env python3

import sys
import logging
from ui.cli import cli

def setup_logging():
    """
    Configures the root logger to ensure that logs are captured correctly.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all levels; adjust as needed

    # Create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)  # Set to INFO to reduce verbosity; adjust as needed

    # Create formatter and add it to the handlers
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(name)s - %(message)s')
    ch.setFormatter(formatter)

    # Add the handlers to the logger
    if not logger.handlers:
        logger.addHandler(ch)

def main():
    """
    The main entry point of the application.
    """
    setup_logging()
    sys.exit(cli())

if __name__ == '__main__':
    main()
