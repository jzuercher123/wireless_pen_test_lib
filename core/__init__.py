from .module_manager import ModuleManager
from .task_scheduler import TaskScheduler
from .event_dispatcher import EventDispatcher
from packet_handler.packet_sniffer import PacketSniffer
from packet_handler.packet_injector import PacketInjector
from packet_handler.packet_analyzer import PacketAnalyzer
from scanners.encryption_scanner import EncryptionWeaknessScanner
from scanners.auth_bypass_scanner import AuthenticationBypassScanner
from scanners.dos_scanner import DoSScanner
from exploits.session_hijacking import SessionHijacking
from exploits.credential_extraction import CredentialExtraction
from exploits.payload_delivery import PayloadDelivery
from core.config_manager import ConfigManager
from core.log_manager import LogManager
from core.report_generator import ReportGenerator
from utils.network_interface_manager import NetworkInterfaceManager
from utils.data_storage_manager import DataStorageManager
from utils.authentication_tools import AuthenticationTools
import logging
import json
import os
import time


class CoreFramework:
    def __init__(self, modules_path, config_path="config"):
        # Initialize Configuration Manager
        self.config_manager = ConfigManager(config_dir=config_path)
        self.config = self.config_manager.get_config()

        # Initialize Log Manager
        self.log_manager = LogManager(self.config_manager)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.debug("Core Framework is initializing.")

        self.logger.info("Initializing Core Framework.")

        # Initialize Utilities
        self.network_manager = NetworkInterfaceManager()
        self.data_storage_manager = DataStorageManager(report_directory=self.config.general.report_directory)
        self.auth_tools = AuthenticationTools()

        # Initialize Event Dispatcher
        self.event_dispatcher = EventDispatcher()

        # Initialize Task Scheduler
        self.task_scheduler = TaskScheduler()

        # Initialize Packet Handler Components
        self.packet_analyzer = PacketAnalyzer(self.event_dispatcher)
        self.packet_sniffer = PacketSniffer(
            interface=self.config.general.interface,
            filter="wlan type mgt",
            prn=self.packet_analyzer.analyze_packet
        )
        self.packet_injector = PacketInjector(interface=self.config.general.interface)

        # Initialize Module Manager with Event Dispatcher and Core Framework reference
        self.module_manager = ModuleManager(modules_path, self.event_dispatcher, self)

        # Initialize Vulnerability Scanners
        self.scanners = {
            'encryption_scanner': EncryptionWeaknessScanner(self, self.config.scanners.encryption_scanner.dict()),
            'auth_bypass_scanner': AuthenticationBypassScanner(self, self.config.scanners.auth_bypass_scanner.dict()),
            'dos_scanner': DoSScanner(self, self.config.scanners.dos_scanner.dict())
        }

        # Initialize Exploitation Modules
        self.exploits = {
            'session_hijacking': SessionHijacking(self, self.config.exploits.session_hijacking.dict()),
            'credential_extraction': CredentialExtraction(self, self.config.exploits.credential_extraction.dict()),
            'payload_delivery': PayloadDelivery(self, self.config.exploits.payload_delivery.dict())
        }

        # Initialize Report Generator
        self.report_generator = ReportGenerator(self.config, self.scanners, self.exploits)

        self.logger.info("Core Framework initialized successfully.")

    def load_protocol_modules(self):
        """
        Loads protocol modules using the module manager.
        """
        self.logger.debug("Loading protocol modules.")
        self.module_manager.load_modules()

    def run_scanner(self, scanner_name: str, target: dict):
        """
        Executes a specified scanner on the given target.
        """
        if scanner_name in self.scanners:
            scanner = self.scanners[scanner_name]
            self.logger.info(f"Running scanner: {scanner_name} on target: {target}")
            scanner.scan(target)
            scanner.report()
        else:
            self.logger.error(f"Scanner '{scanner_name}' not found.")

    def run_exploit(self, exploit_name: str, target_info: dict):
        """
        Executes a specified exploit on the given target information.
        """
        if exploit_name in self.exploits:
            exploit = self.exploits[exploit_name]
            self.logger.info(f"Running exploit: {exploit_name} with target info: {target_info}")
            exploit.execute(target_info)
            exploit.report()
        else:
            self.logger.error(f"Exploit '{exploit_name}' not found.")

    def finalize(self):
        """
        Called when testing is complete to generate reports.
        """
        self.logger.info("Finalizing testing activities and generating reports.")
        self.report_generator.generate_reports()
        self.logger.info("Reports generated successfully.")
