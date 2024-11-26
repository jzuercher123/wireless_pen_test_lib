# main.py

#!/usr/bin/env python3

import sys
import logging
from wireless_pen_test_lib.ui import cli  # Ensure the import path is correct

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

    try:
        # Pass command-line arguments to Click's CLI
        cli.main(args=sys.argv[1:], obj={})
    except Exception as e:
        logging.error(f"An error occurred while running the CLI: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
