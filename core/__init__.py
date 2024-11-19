# core/__init__.py

import os
import logging
import time
import json
import importlib.util
from scapy.all import sendp
from test_network.manage import start_network, stop_network, status_network
from core.config_manager import ConfigManager
from project_specifc_utils.network_interface_manager import NetworkInterfaceManager
from project_specifc_utils.data_storage_manager import DataStorageManager
from project_specifc_utils.authentication_tools import AuthenticationTools

def setup_core_logging(project_root: str) -> logging.Logger:
    """
    Set up logging for the CoreFramework.

    Args:
        project_root (str): The root directory of the project.

    Returns:
        logging.Logger: Configured logger for the CoreFramework.
    """
    logs_dir = os.path.join(project_root, 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    log_file = os.path.join(logs_dir, 'core_framework.log')

    logger = logging.getLogger('CoreFramework')
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(name)s - %(message)s')

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    return logger

class CoreFramework:
    def __init__(self, modules_path: str,
                 config_dir: str = "config",
                 vulnerabilities_path: str = None,
                 sendp_func=sendp,
                 sleep_func=time.sleep,
                 network_manager=None,
                 data_storage_manager=None,
                 auth_tools=None,
                 scanners=None,
                 exploits=None,
                 test_network: bool=False):
        """
        Initialize the CoreFramework with necessary configurations.

        Args:
            modules_path (str): Path to the protocol modules.
            config_dir (str): Directory for configuration files.
            vulnerabilities_path (str): Path to the vulnerabilities file.
            sendp_func (function): Function to send packets.
            sleep_func (function): Function to sleep.
            network_manager (NetworkInterfaceManager): Network manager instance.
            data_storage_manager (DataStorageManager): Data storage manager instance.
            auth_tools (AuthenticationTools): Authentication tools instance.
            scanners (dict): Dictionary of scanners.
            exploits (dict): Dictionary of exploits.
            test_network (bool): Flag to enable test network.
        """
        self.test_network = test_network
        self.modules_path = modules_path
        self.project_root = os.path.abspath(os.path.join(modules_path, os.pardir, os.pardir))
        self.logger = setup_core_logging(self.project_root)
        self.logger.info("Initializing CoreFramework...")

        # Initialize ConfigManager
        try:
            self.config_manager = ConfigManager(config_dir=config_dir)
            self.config = self.config_manager.get_config()
            self.logger.info("Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}", exc_info=True)
            raise

        # Validate general configuration keys
        required_general_keys = ['interface', 'report_directory']
        missing_keys = [key for key in required_general_keys if not hasattr(self.config.general, key)]
        if missing_keys:
            self.logger.error(f"Missing keys in general configuration: {missing_keys}")
            raise AttributeError(f"Missing keys in general configuration: {missing_keys}")

        # Set vulnerabilities path
        if vulnerabilities_path:
            path_to_vulnerabilities = vulnerabilities_path
        else:
            path_to_vulnerabilities = os.path.join(self.project_root, 'vulnerabilities', 'vulnerabilities.json')

        # Ensure vulnerabilities directory exists
        vulnerabilities_dir = os.path.dirname(path_to_vulnerabilities)
        os.makedirs(vulnerabilities_dir, exist_ok=True)

        # Load vulnerability database
        try:
            if not os.path.isfile(path_to_vulnerabilities):
                self.logger.warning(f"Vulnerability database not found at {path_to_vulnerabilities}. Creating a new one.")
                with open(path_to_vulnerabilities, 'w') as f:
                    json.dump({}, f, indent=4)
                self.vulnerability_db = {}
            else:
                with open(path_to_vulnerabilities, 'r') as f:
                    self.vulnerability_db = json.load(f)
                if not isinstance(self.vulnerability_db, dict):
                    self.logger.error(f"Vulnerability database must be a dictionary. Found type: {type(self.vulnerability_db)}")
                    raise TypeError("Vulnerability database must be a dictionary.")
                self.logger.info(f"Loaded vulnerability database from {path_to_vulnerabilities}.")
        except (FileNotFoundError, json.JSONDecodeError, TypeError) as e:
            self.logger.warning(f"Error loading vulnerability database: {e}. Initializing empty vulnerability database.", exc_info=True)
            self.vulnerability_db = {}

        # Initialize Network and Data Storage Managers
        try:
            self.network_manager = network_manager if network_manager else NetworkInterfaceManager(interface=self.config.general.interface)
            self.data_storage_manager = data_storage_manager if data_storage_manager else DataStorageManager(report_directory=self.config.general.report_directory)
            self.auth_tools = auth_tools if auth_tools else AuthenticationTools()
            self.logger.info("Network and Data Storage Managers initialized successfully.")
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}", exc_info=True)
            raise

        # Initialize Scanners and Exploits
        self.scanners = scanners if scanners else {}
        self.exploits = exploits if exploits else {}

        # Assign sendp and sleep functions
        self.sendp = sendp_func
        self.sleep = sleep_func

        # Load Protocol Modules
        try:
            self.load_protocol_modules()
        except Exception as e:
            self.logger.error(f"Failed to load protocol modules: {e}", exc_info=True)
            raise

        self.logger.info("CoreFramework initialized successfully.")

    def run_local_scan(self, interface: str):
        """
        Run a local scan on the specified interface.

        Args:
            interface (str): Network interface to scan.
        """
        self.logger.info(f"Running local scan on interface: {interface}")
        try:
            self.network_manager.set_monitor_mode()
            self.network_manager.start_scanning()
            self.sleep(30)
            self.network_manager.stop_scanning()
            self.network_manager.set_managed_mode()
            self.logger.info("Local scan completed successfully.")
        except Exception as e:
            self.logger.error(f"Error running local scan: {e}", exc_info=True)
            raise

    def load_protocol_modules(self):
        """
        Load protocol modules from the specified directory.
        """
        protocols_dir = self.modules_path
        self.logger.info(f"Loading protocol modules from {protocols_dir}...")

        if not os.path.isdir(protocols_dir):
            self.logger.error(f"Protocols directory not found at {protocols_dir}.")
            raise FileNotFoundError(f"Protocols directory not found at {protocols_dir}.")

        for filename in os.listdir(protocols_dir):
            if filename.endswith('.py') and filename != '__init__.py':
                module_name = filename[:-3]
                file_path = os.path.join(protocols_dir, filename)
                self.logger.debug(f"Loading module '{module_name}' from '{file_path}'.")
                try:
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'register_scanner'):
                        scanner = module.register_scanner()
                        if scanner.name in self.scanners:
                            self.logger.warning(f"Scanner '{scanner.name}' is already registered. Skipping.")
                        else:
                            self.scanners[scanner.name] = scanner
                            self.logger.info(f"Registered scanner: {scanner.name}")

                    if hasattr(module, 'register_exploit'):
                        exploit = module.register_exploit()
                        if exploit.name in self.exploits:
                            self.logger.warning(f"Exploit '{exploit.name}' is already registered. Skipping.")
                        else:
                            self.exploits[exploit.name] = exploit
                            self.logger.info(f"Registered exploit: {exploit.name}")

                except Exception as e:
                    self.logger.error(f"Failed to load module '{module_name}': {e}", exc_info=True)

        self.logger.info("Protocol modules loaded successfully.")

    def run_scanner(self, scanner_name: str, target_info: dict):
        """
        Run the specified scanner on the target information.

        Args:
            scanner_name (str): Name of the scanner to run.
            target_info (dict): Information about the target to scan.
        """
        scanner = self.scanners.get(scanner_name)
        if not scanner:
            self.logger.error(f"Scanner '{scanner_name}' not found.")
            raise ValueError(f"Scanner '{scanner_name}' not found.")
        self.logger.info(f"Running scanner: {scanner_name} on target: {target_info}")
        try:
            vulnerabilities = scanner.scan(target_info)
            self.logger.debug(f"Vulnerabilities found by {scanner_name}: {vulnerabilities}")
            for key, value in vulnerabilities.items():
                if key not in self.vulnerability_db:
                    self.vulnerability_db[key] = []
                self.vulnerability_db[key].extend(value)
            self.logger.info(f"Scanner '{scanner_name}' completed successfully.")
        except Exception as e:
            self.logger.error(f"Error running scanner '{scanner_name}': {e}", exc_info=True)
            raise

    def run_exploit(self, exploit_name: str, vuln_info: dict):
        """
        Run the specified exploit on the vulnerability information.

        Args:
            exploit_name (str): Name of the exploit to run.
            vuln_info (dict): Information about the vulnerability to exploit.
        """
        exploit = self.exploits.get(exploit_name)
        if not exploit:
            self.logger.error(f"Exploit '{exploit_name}' not found.")
            raise ValueError(f"Exploit '{exploit_name}' not found.")
        self.logger.info(f"Running exploit: {exploit_name} with vulnerability info: {vuln_info}")
        try:
            vulnerabilities = exploit.execute(vuln_info)
            self.logger.debug(f"Vulnerabilities affected by {exploit_name}: {vulnerabilities}")
            for key, value in vulnerabilities.items():
                if key not in self.vulnerability_db:
                    self.vulnerability_db[key] = []
                self.vulnerability_db[key].extend(value)
            self.logger.info(f"Exploit '{exploit_name}' completed successfully.")
        except Exception as e:
            self.logger.error(f"Error running exploit '{exploit_name}': {e}", exc_info=True)
            raise

    def start_test_network(self, compose_file: str):
        """
        Start the test network using the specified compose file.

        Args:
            compose_file (str): Path to the Docker Compose file.
        """
        if self.test_network:
            self.logger.info("Starting test network...")
            start_network(compose_file)

    def stop_test_network(self, compose_file: str):
        """
        Stop the test network using the specified compose file.

        Args:
            compose_file (str): Path to the Docker Compose file.
        """
        if self.test_network is False:
            self.logger.warning("Test network is not enabled. Skipping stop operation.")
            return
        stop_network(compose_file)

    def send_continuous_packets(self, packet, interval: float):
        """
        Send packets continuously at the specified interval.

        Args:
            packet: The packet to send.
            interval (float): Interval between packet sends in seconds.
        """
        self.logger.info(f"Starting to send packets every {interval} seconds.")
        self.continuous_sending = True
        while self.continuous_sending:
            try:
                self.sendp(packet, iface=self.network_manager.interface, verbose=False)
                self.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error sending packet: {e}", exc_info=True)
                self.continuous_sending = False

    def stop_continuous_packets(self):
        """
        Stop sending packets continuously.
        """
        self.logger.info("Stopping continuous packet sending.")
        self.continuous_sending = False

    def finalize(self):
        """
        Finalize testing activities and generate a report.
        """
        self.logger.info("Finalizing testing activities...")
        try:
            self.data_storage_manager.generate_report(self.vulnerability_db)
            self.logger.info("Finalization and report generation completed successfully.")
        except Exception as e:
            self.logger.error(f"Error during finalization: {e}", exc_info=True)
            raise