# core/__init__.py

"""
CoreFramework Module

This module defines the CoreFramework class, which serves as the backbone of the WirelessPenTestLib.
It manages configurations, logging, network interfaces, data storage, scanners, exploits, and report generation.

⚠️ Important Note:
Ensure that all penetration testing activities are performed ethically and with explicit authorization.
Unauthorized access to networks is illegal and unethical.
"""

import os
import logging
import threading
import time
import json
import importlib.util
from scapy.all import sendp
from typing import List, Dict, Any, Optional

import pandas as pd

# Importing necessary modules from the project
from wireless_pen_test_lib.modules.network_enumeration.hidden_ssid_reveal import HiddenSSIDRevealer
from wireless_pen_test_lib.modules.network_enumeration.signal_heatmap import SignalHeatmap
from test_network.manage import start_network, stop_network
from wireless_pen_test_lib.core.config_manager import ConfigManager
from project_specific_utils.network_interface_manager import NetworkInterfaceManager
from project_specific_utils.data_storage_manager import DataStorageManager
from project_specific_utils.authentication_tools import AuthenticationTools
from wireless_pen_test_lib.modules.network_enumeration.wifi_scanner import WifiScanner
from wireless_pen_test_lib.modules.machine_learning.anomaly_detection import AnomalyDetector
from wireless_pen_test_lib.modules.data_analytics.report_generator import ReportGenerator
from wireless_pen_test_lib.modules.network_enumeration.beacon_analyzer import BeaconAnalyzer
from wireless_pen_test_lib.modules.attack_modules.deauth_attack import DeauthAttack

def setup_core_logging(project_root: str) -> logging.Logger:
    """
    Sets up logging for the CoreFramework.

    Args:
        project_root (str): The root directory of the project.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logs_dir = os.path.join(project_root, 'logs')
    os.makedirs(logs_dir, exist_ok=True)

    log_file = os.path.join(logs_dir, 'core_framework.log')

    logger = logging.getLogger('CoreFramework')
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('[%(asctime)s] %(levelname)s - %(name)s - %(message)s')

    # File handler for detailed logs
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Stream handler for console output
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    # Avoid adding multiple handlers if they already exist
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    return logger

class CoreFramework:
    """
    CoreFramework Class

    Manages configurations, logging, network interfaces, data storage, scanners, exploits,
    and report generation for the WirelessPenTestLib application.
    """

    def __init__(
        self,
        modules_path: str = "core/config/protocols",  # Corrected from "core/configs/protocols"
        config_dir: str = "core/config",             # Corrected from "core/configs"
        vulnerabilities_path: Optional[str] = None,
        sendp_func=sendp,
        sleep_func=time.sleep,
        network_manager: Optional[NetworkInterfaceManager] = None,
        data_storage_manager: Optional[DataStorageManager] = None,
        auth_tools: Optional[AuthenticationTools] = None,
        scanners: Optional[Dict[str, Any]] = None,
        exploits: Optional[Dict[str, Any]] = None,
        test_network: bool = False,
        interface: str = 'wlan0'
    ):
        """
        Initializes the CoreFramework.

        Args:
            modules_path (str): Path to the protocol modules.
            config_dir (str): Path to the configuration directory.
            vulnerabilities_path (Optional[str]): Path to the vulnerability database.
            sendp_func: Function to send packets (default: scapy's sendp).
            sleep_func: Function to sleep (default: time.sleep).
            network_manager (Optional[NetworkInterfaceManager]): Network interface manager.
            data_storage_manager (Optional[DataStorageManager]): Data storage manager.
            auth_tools (Optional[AuthenticationTools]): Authentication tools manager.
            scanners (Optional[Dict[str, Any]]): Dictionary of scanner instances.
            exploits (Optional[Dict[str, Any]]): Dictionary of exploit instances.
            test_network (bool): Flag to indicate if a test network should be started.
            interface (str): Network interface to use.
        """
        self.stop_event = threading.Event()
        self.modules_path = modules_path
        self.interface = interface
        self.test_network = test_network

        # Determine project root based on modules_path
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

        # Setup logging
        self.logger = setup_core_logging(self.project_root)
        self.logger.info("Initializing CoreFramework...")

        # Initialize components
        try:
            # Configuration Management
            self.config_manager = ConfigManager(config_dir=config_dir)
            self.config = self.config_manager.get_config()
            self.logger.info("Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}", exc_info=True)
            raise

        try:
            self.wifi_scanner = WifiScanner(interface=self.interface, logger=self.logger)
            self.logger.info("WifiScanner initialized successfully.")
        except Exception as e:
            self.logger.error(f"Error initializing WifiScanner: {e}", exc_info=True)
            raise

        # Ensure required configuration keys are present
        required_general_keys = ['interface', 'report_directory']
        missing_keys = [key for key in required_general_keys if not hasattr(self.config.general, key)]
        if missing_keys:
            self.logger.error(f"Missing keys in general configuration: {missing_keys}")
            raise AttributeError(f"Missing keys in general configuration: {missing_keys}")

        # Vulnerability Database Setup
        if vulnerabilities_path:
            path_to_vulnerabilities = vulnerabilities_path
        else:
            path_to_vulnerabilities = os.path.join(self.project_root, 'vulnerabilities', 'vulnerabilities.json')

        vulnerabilities_dir = os.path.dirname(path_to_vulnerabilities)
        os.makedirs(vulnerabilities_dir, exist_ok=True)

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

        # Initialize Managers
        try:
            self.network_manager = network_manager if network_manager else NetworkInterfaceManager(interface=self.config.general.interface)
            self.data_storage_manager = data_storage_manager if data_storage_manager else DataStorageManager(report_directory=self.config.general.report_directory)
            self.auth_tools = auth_tools if auth_tools else AuthenticationTools()
            self.logger.info("Network and Data Storage Managers initialized successfully.")
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}", exc_info=True)
            raise

        # Test Network Setup
        try:
            if self.test_network:
                compose_file = self.config.test_network.compose_file if hasattr(self.config, 'test_network') else None
                self.start_test_network(compose_file)
        except Exception as e:
            self.logger.error(f"Error starting test network: {e}", exc_info=True)
            raise

        # Initialize Scanners and Exploits
        self.scanners = scanners if scanners else {}
        self.exploits = exploits if exploits else {}

        # Packet Sending and Sleeping Functions
        self.sendp = sendp_func
        self.sleep = sleep_func

        # Initialize Protocol Modules
        try:
            self.load_protocol_modules()
        except Exception as e:
            self.logger.error(f"Failed to load protocol modules: {e}", exc_info=True)
            raise

        self.logger.info("CoreFramework initialized successfully.")

        # Initialize Network Enumeration Modules
        self.hidden_ssid_revealer = HiddenSSIDRevealer(interface=self.interface, stop_event=self.stop_event)
        self.signal_heatmap = SignalHeatmap(interface=self.interface, stop_event=self.stop_event)
        self.beacon_analyzer = BeaconAnalyzer(interface=self.interface, stop_event=self.stop_event)
        self.deauth_attacks: List[DeauthAttack] = []

    def load_protocol_modules(self):
        """
        Loads protocol modules from the specified modules_path.

        Raises:
            FileNotFoundError: If the protocols directory does not exist.
            Exception: For any other errors during module loading.
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

                    # Register Scanners
                    if hasattr(module, 'register_scanner'):
                        scanner = module.register_scanner()
                        if scanner.name in self.scanners:
                            self.logger.warning(f"Scanner '{scanner.name}' is already registered. Skipping.")
                        else:
                            self.scanners[scanner.name] = scanner
                            self.logger.info(f"Registered scanner: {scanner.name}")

                    # Register Exploits
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

    def scan_wifi_networks(self, scan_duration: int = 5) -> List[Dict[str, Any]]:
        """
        Scans for available Wi-Fi networks.

        Args:
            scan_duration (int, optional): Duration to wait for the scan to complete in seconds. Defaults to 5.

        Returns:
            List[Dict[str, Any]]: List of dictionaries containing SSID, BSSID, signal strength, channel, and security.
        """
        self.logger.info("Initiating Wi-Fi network scan...")
        try:
            networks = self.wifi_scanner.scan_networks(scan_duration=scan_duration)
            self.logger.info(f"Wi-Fi scan completed. {len(networks)} networks found.")
            return networks
        except Exception as e:
            self.logger.error(f"Error during Wi-Fi scan: {e}", exc_info=True)
            raise

    def run_scanner(self, scanner_name: str, target_info: dict):
        """
        Executes a scanner on the given target.

        Args:
            scanner_name (str): Name of the scanner to run.
            target_info (dict): Information about the target network.

        Raises:
            ValueError: If the scanner is not found.
            Exception: For any errors during scanning.
        """
        scanner = self.scanners.get(scanner_name)
        if not scanner:
            self.logger.error(f"Scanner '{scanner_name}' not found.")
            raise ValueError(f"Scanner '{scanner_name}' not found.")
        self.logger.info(f"Running scanner: {scanner_name} on target: {target_info}")
        try:
            vulnerabilities = scanner.scan(target_info, self.stop_event)
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
        Executes an exploit based on the provided vulnerability information.

        Args:
            exploit_name (str): Name of the exploit to run.
            vuln_info (dict): Information about the vulnerability to exploit.

        Raises:
            ValueError: If the exploit is not found.
            Exception: For any errors during exploitation.
        """
        exploit = self.exploits.get(exploit_name)
        if not exploit:
            self.logger.error(f"Exploit '{exploit_name}' not found.")
            raise ValueError(f"Exploit '{exploit_name}' not found.")
        self.logger.info(f"Running exploit: {exploit_name} with vulnerability info: {vuln_info}")
        try:
            vulnerabilities = exploit.execute(vuln_info, self.stop_event)
            self.logger.debug(f"Vulnerabilities affected by {exploit_name}: {vulnerabilities}")
            for key, value in vulnerabilities.items():
                if key not in self.vulnerability_db:
                    self.vulnerability_db[key] = []
                self.vulnerability_db[key].extend(value)
            self.logger.info(f"Exploit '{exploit_name}' completed successfully.")
        except Exception as e:
            self.logger.error(f"Error running exploit '{exploit_name}': {e}", exc_info=True)
            raise

    def generate_report(self, format: str = 'json'):
        """
        Generates a report based on the vulnerability database.

        Args:
            format (str, optional): Format of the report ('json', 'txt'). Defaults to 'json'.

        Raises:
            ValueError: If an unsupported format is specified.
        """
        self.logger.info("Generating reports...")
        try:
            # Ensure report directories exist
            json_dir = os.path.join(self.data_storage_manager.report_directory, "json")
            txt_dir = os.path.join(self.data_storage_manager.report_directory, "txt")
            os.makedirs(json_dir, exist_ok=True)
            os.makedirs(txt_dir, exist_ok=True)

            # JSON Report
            if format == 'json':
                json_report_path = os.path.join(json_dir, "report.json")
                with open(json_report_path, 'w') as f:
                    json.dump(self.vulnerability_db, f, indent=4)
                self.logger.info(f"JSON report generated at {json_report_path}")

            # TXT Report
            elif format == 'txt':
                txt_report_path = os.path.join(txt_dir, "report.txt")
                with open(txt_report_path, 'w') as f:
                    for scanner, vulnerabilities in self.vulnerability_db.get('scans', {}).items():
                        f.write(f"Scanner: {scanner}\n")
                        for vuln in vulnerabilities:
                            f.write(f"  - SSID: {vuln.get('ssid', 'N/A')}\n")
                            f.write(f"    BSSID: {vuln.get('bssid', 'N/A')}\n")
                            f.write(f"    Protocol: {vuln.get('protocol', 'N/A')}\n")
                            f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                    for exploit, vulnerabilities in self.vulnerability_db.get('exploits', {}).items():
                        f.write(f"Exploit: {exploit}\n")
                        for vuln in vulnerabilities:
                            f.write(f"  - BSSID: {vuln.get('bssid', 'N/A')}\n")
                            f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                            f.write(f"    Action: {vuln.get('action', 'N/A')}\n")
                self.logger.info(f"TXT report generated at {txt_report_path}")

            else:
                self.logger.error(f"Unsupported report format: {format}")
                raise ValueError(f"Unsupported report format: {format}")

            self.logger.info("Reports generated successfully.")

        except Exception as e:
            self.logger.error(f"Error generating report: {e}", exc_info=True)
            raise

    def finalize(self):
        """
        Finalizes testing activities by generating reports and ensuring all operations are cleanly terminated.
        """
        self.logger.info("Finalizing testing activities...")
        try:
            self.generate_report(format='json')  # You can parameterize the format as needed
            self.data_storage_manager.generate_additional_reports(self.vulnerability_db)
            self.logger.info("Finalization and report generation completed successfully.")
        except Exception as e:
            self.logger.error(f"Error during finalization: {e}", exc_info=True)
            raise

    def stop_all_operations(self):
        """
        Signals all running operations (scans, exploits, network attacks) to terminate gracefully.
        """
        self.logger.info("Stopping all operations...")
        self.stop_event.set()

        # Stop Test Network if running
        if self.test_network:
            self.stop_test_network()

        # Stop Continuous Packet Sending
        self.stop_continuous_packets()

        # Stop all Deauth Attacks
        self.stop_all_deauth_attacks()

        # Stop Network Enumeration Modules
        self.hidden_ssid_revealer.stop()
        self.signal_heatmap.stop()
        self.beacon_analyzer.stop()

        self.logger.info("All operations stopped successfully.")

    def start_test_network(self, compose_file: Optional[str] = None):
        """
        Starts a test network using Docker Compose.

        Args:
            compose_file (Optional[str]): Path to the Docker Compose file.
        """
        self.logger.info("Starting test network...")
        try:
            if compose_file:
                start_network(compose_file)
            else:
                start_network(self.compose_file_path)
            self.logger.info("Test network started successfully.")
        except Exception as e:
            self.logger.error(f"Error starting test network: {e}", exc_info=True)
            raise

    def stop_test_network(self):
        """
        Stops the test network if it was started.
        """
        self.logger.info("Stopping test network...")
        try:
            stop_network(self.compose_file_path)
            self.logger.info("Test network stopped successfully.")
        except Exception as e:
            self.logger.error(f"Error stopping test network: {e}", exc_info=True)
            raise

    def send_continuous_packets(self, packet, interval: float):
        """
        Sends packets continuously at specified intervals.

        Args:
            packet: The packet to send.
            interval (float): Time interval between packets in seconds.
        """
        self.logger.info(f"Starting to send packets every {interval} seconds.")
        self.continuous_sending = True
        while self.continuous_sending and not self.stop_event.is_set():
            try:
                self.sendp(packet, iface=self.network_manager.interface, verbose=False)
                self.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error sending packet: {e}", exc_info=True)
                self.continuous_sending = False

    def stop_continuous_packets(self):
        """
        Stops the continuous packet sending process.
        """
        self.logger.info("Stopping continuous packet sending.")
        self.continuous_sending = False

    def stop_all_deauth_attacks(self):
        """
        Stops all ongoing deauthentication attacks.
        """
        self.logger.info("Stopping all deauthentication attacks.")
        for attack in self.deauth_attacks:
            attack.stop_attack()
        self.deauth_attacks = []
        self.logger.info("All deauthentication attacks stopped.")

    def perform_anomaly_detection(self, traffic_data: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Performs anomaly detection on the provided traffic data.

        Args:
            traffic_data (List[Dict[str, Any]]): List of traffic data dictionaries.

        Returns:
            pd.DataFrame: DataFrame containing detected anomalies.
        """
        self.logger.info("Performing anomaly detection on traffic data.")
        df = pd.DataFrame(traffic_data)
        detector = AnomalyDetector(df)
        detector.train_model()
        anomalies = detector.detect_anomalies()
        self.logger.info("Anomaly detection completed.")
        return anomalies

    # Placeholder methods for future implementations
    def get_scan_results(self):
        pass

    def get_exploit_results(self):
        pass

    def get_additional_report_data(self):
        pass
