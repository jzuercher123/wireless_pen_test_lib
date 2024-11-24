import os
import logging
import threading
import time
import json
import importlib.util
from scapy.all import sendp

from modules.network_enumeration.hidden_ssid_reveal import HiddenSSIDRevealer
from modules.network_enumeration.signal_heatmap import SignalHeatmap
from test_network.manage import start_network, stop_network, status_network
from core.config_manager import ConfigManager
from project_specific_utils.network_interface_manager import NetworkInterfaceManager
from project_specific_utils.data_storage_manager import DataStorageManager
from project_specific_utils.authentication_tools import AuthenticationTools
from modules.machine_learning.anomaly_detection import AnomalyDetector
from modules.data_analytics.report_generator import ReportGenerator
from modules.network_enumeration.beacon_analyzer import BeaconAnalyzer
from modules.attack_modules.deauth_attack import DeauthAttack
from typing import List, Dict, Any
import pandas as pd

def setup_core_logging(project_root: str) -> logging.Logger:
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
    def __init__(self, modules_path: str = "core/config/protocols",
                 config_dir: str = "core/config",
                 vulnerabilities_path: str = None,
                 sendp_func=sendp,
                 sleep_func=time.sleep,
                 network_manager=None,
                 data_storage_manager=None,
                 auth_tools=None,
                 scanners=None,
                 exploits=None,
                 test_network: bool=False,
                 interface: str='wlan0'):
        self.stop_event = threading.Event()
        self.modules_path = modules_path
        self.compose_file_path = os.path.join(modules_path, 'test_network', 'docker-compose.yml')
        self.project_root = os.path.abspath(os.path.join(modules_path, os.pardir, os.pardir))
        self.logger = setup_core_logging(self.project_root)
        self.logger.info("Initializing CoreFramework...")
        self.hidden_ssid_revealer = HiddenSSIDRevealer(interface='wlan0', stop_event=self.stop_event)
        self.signal_heatmap = SignalHeatmap(interface='wlan0', stop_event=self.stop_event)
        self.beacon_analyzer = BeaconAnalyzer(interface='wlan0', stop_event=self.stop_event)
        self.deauth_attacks: List[DeauthAttack] = []
        self.interface = interface

        try:
            self.config_manager = ConfigManager(config_dir=config_dir)
            self.config = self.config_manager.get_config()
            self.logger.info("Configuration loaded successfully.")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}", exc_info=True)
            raise

        required_general_keys = ['interface', 'report_directory']
        missing_keys = [key for key in required_general_keys if not hasattr(self.config.general, key)]
        if missing_keys:
            self.logger.error(f"Missing keys in general configuration: {missing_keys}")
            raise AttributeError(f"Missing keys in general configuration: {missing_keys}")

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

        try:
            self.network_manager = network_manager if network_manager else NetworkInterfaceManager(interface=self.config.general.interface)
            self.data_storage_manager = data_storage_manager if data_storage_manager else DataStorageManager(report_directory=self.config.general.report_directory)
            self.auth_tools = auth_tools if auth_tools else AuthenticationTools()
            self.logger.info("Network and Data Storage Managers initialized successfully.")
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}", exc_info=True)
            raise

        try:
            self.test_network = test_network
            if self.test_network:
                self.start_test_network(self.config.test_network.compose_file)
        except Exception as e:
            self.logger.error(f"Error starting test network: {e}", exc_info=True)
            raise

        self.scanners = scanners if scanners else {}
        self.exploits = exploits if exploits else {}

        self.sendp = sendp_func
        self.sleep = sleep_func

        try:
            self.load_protocol_modules()
        except Exception as e:
            self.logger.error(f"Failed to load protocol modules: {e}", exc_info=True)
            raise

        self.logger.info("CoreFramework initialized successfully.")

    def run_local_scan(self, interface: str):
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

    def set_interface(self, iface: str):
        self.interface = iface

    def stop_all_operations(self):
        self.logger.info("Stopping all operations...")
        self.stop_event.set()
        self.stop_test_network()
        self.stop_continuous_packets()
        self.logger.info("All operations stopped successfully.")

    def start_signal_heatmap(self):
        self.signal_heatmap.run()

    def generate_heatmap(self):
        self.signal_heatmap.generate_heatmap()

    def load_protocol_modules(self):
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

    def execute_deauth_attack(self, interface: str, target_bssid: str, target_client: str = None):
        stop_event = threading.Event()
        attack = DeauthAttack(interface, target_bssid, target_client, stop_event)
        attack.start_attack()
        self.deauth_attacks.append(attack)

    def stop_all_deauth_attacks(self):
        for attack in self.deauth_attacks:
            attack.stop_attack()
        self.deauth_attacks = []

    def run_scanner(self, scanner_name: str, target_info: dict):
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

    def start_beacon_analysis(self):
        self.beacon_analyzer.run()

    def get_access_points(self):
        return self.beacon_analyzer.get_access_points()

    def start_hidden_ssid_reveal(self):
        self.hidden_ssid_revealer.run()

    def get_hidden_ssids(self):
        return self.hidden_ssid_revealer.get_hidden_ssids()

    def run_exploit(self, exploit_name: str, vuln_info: dict):
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

    def start_test_network(self, compose_file: str = None):
        if not compose_file:
            self.logger.info("Starting test network...")
            start_network(self.compose_file_path)

        if self.test_network:
            self.logger.info("Starting test network...")
            start_network(compose_file)

    def stop_test_network(self, compose_file: str):
        if self.test_network is False:
            self.logger.warning("Test network is not enabled. Skipping stop operation.")
            return
        stop_network(compose_file)

    def send_continuous_packets(self, packet, interval: float):
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
        self.logger.info("Stopping continuous packet sending.")
        self.continuous_sending = False

    def perform_anomaly_detection(self, traffic_data: List[Dict[str, Any]]) -> pd.DataFrame:
        df = pd.DataFrame(traffic_data)
        detector = AnomalyDetector(df)
        detector.train_model()
        anomalies = detector.detect_anomalies()
        return anomalies

    def get_scan_results(self):
        pass

    def get_exploit_results(self):
        pass

    def get_additional_report_data(self):
        pass

    def generate_detailed_report(self, scan_results: Dict[str, Any], exploit_results: Dict[str, Any],
                                 report_data: Dict[str, Any], export_format: str, file_path: str):
        reporter = ReportGenerator(scan_results, exploit_results, report_data)
        if export_format == 'pdf':
            reporter.generate_pdf_report(file_path)
        elif export_format == 'json':
            reporter.export_json(file_path)
        elif export_format == 'csv':
            reporter.export_csv(file_path)

    def generate_report(self, vulnerability_db: dict, format: str = 'json'):
        """
        Generates a report based on the vulnerability database.

        Args:
            vulnerability_db (dict): Dictionary containing detected vulnerabilities.
        """
        self.logger.info("Generating reports...")
        # Ensure report directories exist
        json_dir = os.path.join(self.report_directory, "json")
        txt_dir = os.path.join(self.report_directory, "txt")
        os.makedirs(json_dir, exist_ok=True)
        os.makedirs(txt_dir, exist_ok=True)

        # JSON Report
        if format == 'json':
            json_report_path = os.path.join(json_dir, "report.json")
            with open(json_report_path, 'w') as f:
                json.dump(vulnerability_db, f, indent=4)
            self.logger.info(f"JSON report generated at {json_report_path}")

        # TXT Report
        elif format == 'txt':
            txt_report_path = os.path.join(txt_dir, "report.txt")
            with open(txt_report_path, 'w') as f:
                for scanner, vulnerabilities in vulnerability_db.get('scans', {}).items():
                    f.write(f"Scanner: {scanner}\n")
                    for vuln in vulnerabilities:
                        f.write(f"  - SSID: {vuln.get('ssid', 'N/A')}\n")
                        f.write(f"    BSSID: {vuln.get('bssid', 'N/A')}\n")
                        f.write(f"    Protocol: {vuln.get('protocol', 'N/A')}\n")
                        f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                for exploit, vulnerabilities in vulnerability_db.get('exploits', {}).items():
                    f.write(f"Exploit: {exploit}\n")
                    for vuln in vulnerabilities:
                        f.write(f"  - BSSID: {vuln.get('bssid', 'N/A')}\n")
                        f.write(f"    Description: {vuln.get('description', 'N/A')}\n")
                        f.write(f"    Action: {vuln.get('action', 'N/A')}\n")
            self.logger.info(f"TXT report generated at {txt_report_path}")

        self.logger.info("Reports generated successfully.")

    def finalize(self):
        self.logger.info("Finalizing testing activities...")
        try:
            self.data_storage_manager.generate_report(self.vulnerability_db)
            self.logger.info("Finalization and report generation completed successfully.")
        except Exception as e:
            self.logger.error(f"Error during finalization: {e}", exc_info=True)
            raise