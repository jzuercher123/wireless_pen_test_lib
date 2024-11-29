# gui.py

"""
WirelessPenTestLib GUI Module

This module defines the graphical user interface (GUI) for the WirelessPenTestLib application.
It leverages Tkinter to create a tabbed interface that includes various frames for different functionalities:
- Live Network Details
- Live Packet Monitor
- Fake Devices Manager
- Rogue Access Point Manager
- Scans
- Exploits
- Reports
- Settings
- Targets
- Wi-Fi Scanner

The GUI interacts with the CoreFramework to perform network scanning, exploitation, and reporting tasks.

**⚠️ Important Note:**
Creating rogue access points and performing network penetration testing should only be done
with explicit permission on networks you own or have authorization to test. Unauthorized access
to networks is illegal and unethical.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from threading import Event
import queue
import os
import json
import re
from typing import Optional, Dict, Any, List
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Dict, Any
import threading
import re
import logging

# Ensure the package is installed in editable mode and use absolute imports
from wireless_pen_test_lib.core import CoreFramework
from wireless_pen_test_lib.core.config.protocols import register_scanners, register_exploits

# Import all necessary frames
from wireless_pen_test_lib.ui.frames.anomaly_detector_frame import AnomalyDetectionFrame
from wireless_pen_test_lib.ui.frames.signal_heatmap_frame import SignalHeatmapFrame
from wireless_pen_test_lib.ui.frames.live_network_frame import LiveNetworkFrame
from wireless_pen_test_lib.ui.frames.live_packet_monitor import LivePacketMonitor
from wireless_pen_test_lib.ui.frames.rogue_access_point import FakeAccessPoint
from wireless_pen_test_lib.ui.frames.network_graph_visualization import NetworkGraphVisualizationFrame
from wireless_pen_test_lib.ui.frames.report_generation_frame import ReportGenerationFrame
from wireless_pen_test_lib.ui.frames.beacon_analysis_frame import BeaconAnalysisFrame
from wireless_pen_test_lib.ui.frames.deauth_attack_frame import DeauthAttackFrame
from wireless_pen_test_lib.ui.frames.hidden_ssid_frame import HiddenSSIDFrame
from wireless_pen_test_lib.ui.frames.wifi_scan_frame import WifiScanFrame
from wireless_pen_test_lib.ui.frames.test_devices import FakeDeviceManager
from wireless_pen_test_lib.ui.frames.targets_tab import TargetsTab
from wireless_pen_test_lib.core.pool_manager import Pool

def create_test_data() -> Dict[str, Any]:
    """
    Creates and returns test data for WEP and WPA networks.

    Returns:
        Dict[str, Any]: A dictionary containing test data for WEP and WPA networks.
    """
    return {
        "wpa_networks": {
            "00:11:22:33:44:55": {
                "SSID": "TestNetwork",
                "BSSID": "00:11:22:33:44:55",
                "Security": "WPA2",
                "WPS_Enabled": False
            }
        },
        "wep_networks": {
            "00:11:22:33:44:66": {
                "SSID": "TestNetwork",
                "BSSID": "00:11:22:33:44:66",
                "Security": "WEP",
                "Key_Strength": "Weak"
            }
        }
    }


class WirelessPenTestGUI(tk.Tk):
    """
    Main GUI class for the WirelessPenTestLib application.

    Inherits from Tkinter's Tk class and sets up a tabbed interface with various functionalities
    for network penetration testing, including live monitoring, fake device management, and rogue
    access point setup.

    Attributes:
        core (CoreFramework): Instance of the CoreFramework for backend operations.
        scan_log_queue (queue.Queue): Queue for scan log messages.
        exploit_log_queue (queue.Queue): Queue for exploit log messages.
    """

    def __init__(self):
        """
        Initializes the WirelessPenTestGUI application.

        Sets up the main window, initializes the CoreFramework, and creates all necessary tabs.
        """
        super().__init__()
        self.title("WirelessPenTestLib GUI")
        self.geometry("1400x900")  # Increased size for better usability

        # Initialize queues for thread-safe GUI updates
        self.scan_log_queue = queue.Queue()
        self.exploit_log_queue = queue.Queue()

        # Schedule periodic checks for log queues
        self.after(100, self.process_scan_log_queue)
        self.after(100, self.process_exploit_log_queue)

        # Initialize Core Framework
        self.core = self.initialize_coreframework()
        if not self.core:
            messagebox.showerror("Initialization Error", "Failed to initialize CoreFramework. Exiting.")
            self.destroy()
            return

        # Warning message for legal and ethical use
        messagebox.showwarning(
            "Legal and Ethical Use",
            "Ensure you have authorization to perform penetration testing on the target networks."
        )

        # Create a container frame to hold the Notebook (tabbed interface) and Stop button
        container_frame = ttk.Frame(self)
        container_frame.pack(fill=tk.BOTH, expand=True)

        # Create a Notebook (tabbed interface) inside the container frame
        self.notebook = ttk.Notebook(container_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, side='top')

        # Initialize and add all tabs
        self.initialize_tabs()

        # Add a Stop button at the bottom of the container frame to halt ongoing operations
        self.add_stop_button(container_frame)

        # Bind the protocol for window closing to ensure cleanup
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # pool
        self.pool = Pool()

    def initialize_coreframework(self) -> Optional[CoreFramework]:
        """
        Initializes the CoreFramework with necessary configurations.

        Returns:
            Optional[CoreFramework]: An instance of CoreFramework if successful, else None.
        """
        # Define paths to configuration directories and vulnerability database
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, '..'))
        protocols_path = os.path.join(project_root, 'core', 'config', 'protocols')
        config_dir = os.path.join(project_root, 'core', 'config')
        vulnerabilities_path = os.path.join(project_root, 'vulnerabilities', 'vulnerabilities.json')

        # Initialize CoreFramework
        try:
            core = CoreFramework(
                modules_path=protocols_path,
                config_dir=config_dir,
                scanners=register_scanners(),
                exploits=register_exploits(),
                vulnerabilities_path=vulnerabilities_path
            )
            core.logger.info("CoreFramework initialized successfully.")
            return core
        except FileNotFoundError as e:
            messagebox.showerror("Initialization Error", f"Configuration file not found: {e}")
        except json.JSONDecodeError as e:
            messagebox.showerror("Initialization Error", f"Invalid configuration format: {e}")
        except Exception as e:
            messagebox.showerror("Initialization Error", f"An unexpected error occurred: {e}")
        return None

    def initialize_tabs(self):
        """
        Initializes and adds all tabs to the Notebook.
        """
        # Live Network Details tab
        self.live_network_frame = LiveNetworkFrame(
            parent=self.notebook,
            core_framework=self.core,
            scan_interval=30  # Scan every 30 seconds
        )
        self.notebook.add(self.live_network_frame, text="Live Network Details")

        # Hidden SSID Reveal tab
        self.hidden_ssid_frame = HiddenSSIDFrame(self.notebook, self.core)
        self.notebook.add(self.hidden_ssid_frame, text='Hidden SSID Reveal')

        # Wi-Fi Scanner tab
        self.wifi_scan_frame = WifiScanFrame(self.notebook, self.core)
        self.notebook.add(self.wifi_scan_frame, text='Wi-Fi Scanner')

        # Scans tab
        self.scans_tab = ScansTab(
            parent=self.notebook,
            core_framework=self.core,
            stop_event=self.core.stop_event,
            log_queue=self.scan_log_queue
        )
        self.notebook.add(self.scans_tab, text='Scans')

        # Exploits tab
        self.exploits_tab = ExploitsTab(
            parent=self.notebook,
            core_framework=self.core,
            stop_event=self.core.stop_event,
            log_queue=self.exploit_log_queue
        )
        self.notebook.add(self.exploits_tab, text='Exploits')

        # Reports tab
        self.reports_tab = ReportsTab(self.notebook, self.core)
        self.notebook.add(self.reports_tab, text='Reports')

        # Settings tab
        self.settings_tab = SettingsTab(self.notebook)
        self.notebook.add(self.settings_tab, text='Settings')

        # Targets tab (Newly added)
        self.targets_tab = TargetsTab(self.notebook, self.core)
        self.notebook.add(self.targets_tab, text='Targets')

        # Live Packet Monitor tab
        self.live_packet_monitor = LivePacketMonitor(self.notebook)
        self.notebook.add(self.live_packet_monitor, text="Live Packet Monitor")

        # Fake Devices tab
        self.fake_devices_frame = FakeDeviceManager(self.notebook)
        self.notebook.add(self.fake_devices_frame, text="Fake Devices")

        # Rogue Access Point tab
        self.rogue_access_point_frame = FakeAccessPoint(self.notebook)
        self.notebook.add(self.rogue_access_point_frame, text="Rogue Access Point")

        # Network Visualization tab
        self.network_visualization_frame = NetworkGraphVisualizationFrame(self.notebook)
        self.notebook.add(self.network_visualization_frame, text="Network Visualization")

        # Report Generation tab
        self.report_generation_frame = ReportGenerationFrame(self.notebook, self.core)
        self.notebook.add(self.report_generation_frame, text='Report Generation')

        # Beacon Analysis tab
        self.beacon_analysis_frame = BeaconAnalysisFrame(self.notebook, self.core)
        self.notebook.add(self.beacon_analysis_frame, text='Beacon Analysis')

        # Signal Heatmap tab
        self.signal_heatmap_frame = SignalHeatmapFrame(self.notebook, self.core)
        self.notebook.add(self.signal_heatmap_frame, text='Signal Heatmap')

        # Anomaly Detection tab
        self.anomaly_detection_frame = AnomalyDetectionFrame(self.notebook, self.core)
        self.notebook.add(self.anomaly_detection_frame, text="Anomaly Detection")

        # Deauth Attack tab
        self.deauth_attack_frame = DeauthAttackFrame(self.notebook, self.core)
        self.notebook.add(self.deauth_attack_frame, text='Deauth Attack')

    def add_stop_button(self, parent: ttk.Frame) -> None:
        """
        Adds a Stop button at the bottom of the GUI to halt ongoing operations.

        Args:
            parent (ttk.Frame): The parent frame to attach the button.
        """
        stop_button = ttk.Button(parent, text="Stop", command=self.stop_operations)
        stop_button.pack(pady=10, side='bottom')

    def stop_operations(self) -> None:
        """
        Handles the Stop button click event.

        Signals all running operations to terminate gracefully.
        """
        if not self.core.stop_event.is_set():
            self.core.stop_all_operations()
            messagebox.showinfo("Operations Stopped", "All ongoing operations have been stopped.")
        else:
            messagebox.showinfo("No Ongoing Operations", "There are no ongoing operations to stop.")

    def process_scan_log_queue(self) -> None:
        """
        Processes the scan log queue and updates the scan log text widget.
        """
        while not self.scan_log_queue.empty():
            message = self.scan_log_queue.get_nowait()
            self.scans_tab.log_message(self.scans_tab.scan_log, message)
        self.after(100, self.process_scan_log_queue)

    def process_exploit_log_queue(self) -> None:
        """
        Processes the exploit log queue and updates the exploit log text widget.
        """
        while not self.exploit_log_queue.empty():
            message = self.exploit_log_queue.get_nowait()
            self.exploits_tab.log_message(self.exploits_tab.exploit_log, message)
        self.after(100, self.process_exploit_log_queue)

    def on_closing(self) -> None:
        """
        Handles the window closing event to ensure proper cleanup.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.stop_operations()
            self.destroy()


class ScansTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, core_framework: CoreFramework, stop_event: threading.Event,
                 log_queue: queue.Queue):
        super().__init__(parent)
        self.core = core_framework
        self.stop_event = stop_event
        self.log_queue = log_queue
        self.create_widgets()

    def create_widgets(self) -> None:
        """
        Creates the widgets for the 'Scans' tab.
        """
        # Scanner Selection Section
        scanner_label = ttk.Label(self, text="Select Scanners:")
        scanner_label.pack(pady=5)

        self.scanner_vars: Dict[str, tk.BooleanVar] = {}
        for sc in self.core.scanners.keys():
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(self, text=sc, variable=var)
            chk.pack(anchor='w', padx=20)
            self.scanner_vars[sc] = var

        # Target Selection Section
        target_frame = ttk.LabelFrame(self, text="Target Network")
        target_frame.pack(padx=10, pady=10, fill='x')

        ssid_label = ttk.Label(target_frame, text="SSID:")
        ssid_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.scan_ssid_entry = ttk.Entry(target_frame, width=50)
        self.scan_ssid_entry.grid(row=0, column=1, padx=5, pady=5)

        bssid_label = ttk.Label(target_frame, text="BSSID:")
        bssid_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.scan_bssid_entry = ttk.Entry(target_frame, width=50)
        self.scan_bssid_entry.grid(row=1, column=1, padx=5, pady=5)

        # Scan and Finalize Buttons
        scan_button = ttk.Button(self, text="Run Scans", command=self.run_scans)
        scan_button.pack(pady=10)

        finalize_button = ttk.Button(self, text="Finalize and Generate Reports",
                                     command=self.finalize_and_generate_reports)
        finalize_button.pack(pady=10)

        # Log Area for Scans
        self.scan_log = tk.Text(self, height=20, state='disabled')
        self.scan_log.pack(padx=10, pady=10, fill='both', expand=True)

    def run_scans(self) -> None:
        """
        Initiates the scanning process based on selected scanners and target network.

        Validates user inputs and starts a separate thread to perform scans to keep the GUI responsive.
        """
        selected_scanners = [sc for sc, var in self.scanner_vars.items() if var.get()]
        ssid = self.scan_ssid_entry.get().strip()
        bssid = self.scan_bssid_entry.get().strip()

        # Input validation
        if not selected_scanners:
            messagebox.showwarning("No Scanners Selected", "Please select at least one scanner.")
            return
        if not ssid or not bssid:
            messagebox.showwarning("Incomplete Target Information", "Please provide both SSID and BSSID.")
            return
        if not self.is_valid_bssid(bssid):
            messagebox.showwarning("Invalid BSSID", "Please provide a valid BSSID (MAC address).")
            return

        target = {'ssid': ssid, 'bssid': bssid}

        # Reset stop_event before starting new scans
        if self.stop_event.is_set():
            self.stop_event.clear()

        # Start scanning in a separate thread
        self.scan_thread = threading.Thread(target=self.execute_scans, args=(selected_scanners, target), daemon=True)
        self.scan_thread.start()

    def finalize_and_generate_reports(self) -> None:
        """
        Finalizes the scanning process and generates reports.

        Initiates a separate thread to handle finalization to keep the GUI responsive.
        """
        threading.Thread(target=self.execute_finalize, daemon=True).start()

    def execute_finalize(self) -> None:
        """
        Executes the finalization and report generation process.

        Handles any exceptions and updates the report log accordingly.
        """
        try:
            self.core.finalize()
            self.log_queue.put("Reports generated successfully.\n")
            messagebox.showinfo("Finalize Complete", "Reports generated successfully.")
        except Exception as e:
            self.log_queue.put(f"Failed to finalize and generate reports: {e}\n")
            messagebox.showerror("Finalize Error", f"Failed to finalize and generate reports: {e}")

    def execute_scans(self, scanners: List[str], target: Dict[str, str]) -> None:
        """
        Executes the selected scanners against the target network.

        Args:
            scanners (list): List of scanner names to run.
            target (Dict[str, str]): Dictionary containing target SSID and BSSID.
        """
        for sc in scanners:
            if self.stop_event.is_set():
                self.log_queue.put("Scan operation interrupted by user.")
                break
            self.log_queue.put(f"Running scanner: {sc}")
            try:
                # Run scanner via CoreFramework
                scan_result = self.core.run_scanner(sc, target)
                self.log_queue.put(f"Scanner '{sc}' completed.\n")

                # Display scan results in the log
                devices = scan_result.get("devices", [])
                if not devices:
                    self.log_queue.put(f"No devices found by scanner '{sc}'.\n")
                for device in devices:
                    device_info = (f"SSID: {device.get('ssid', 'N/A')}, "
                                   f"BSSID: {device.get('bssid', 'N/A')}, "
                                   f"IP: {device.get('ip', 'N/A')}, "
                                   f"MAC: {device.get('mac', 'N/A')}, "
                                   f"Hostname: {device.get('hostname', 'N/A')}, "
                                   f"Signal: {device.get('signal', 'N/A')} dBm, "
                                   f"Channel: {device.get('channel', 'N/A')}, "
                                   f"Security: {device.get('security', 'N/A')}")
                    self.log_queue.put(f"Discovered Device: {device_info}")

                    # Add the discovered device to the universal pool
                    self.core.add_target_to_pool(device)

            except Exception as e:
                self.log_queue.put(f"Error running scanner '{sc}': {e}\n")

    def log_message(self, log_widget: tk.Text, message: str) -> None:
        """
        Logs messages to the specified log widget.

        Args:
            log_widget (tk.Text): The text widget to log messages to.
            message (str): The message to log.
        """
        log_widget.config(state='normal')
        log_widget.insert(tk.END, message + '\n')
        log_widget.see(tk.END)
        log_widget.config(state='disabled')

    @staticmethod
    def is_valid_bssid(bssid: str) -> bool:
        """
        Validates the BSSID (MAC address) format.

        Args:
            bssid (str): The BSSID to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(bssid))


# wireless_pen_test_lib/ui/frames/exploits_tab.py

"""
ExploitsTab Module

This module defines the ExploitsTab class, which provides a user interface for selecting and
running network exploits against targeted Wi-Fi networks. It integrates with the CoreFramework
to manage and execute exploits based on user selections.
"""



class ExploitsTab(ttk.Frame):
    """
    ExploitsTab Class

    Provides a user interface for selecting and executing network exploits against chosen targets.
    """

    def __init__(
        self,
        parent: ttk.Notebook,
        core_framework: Any,
        stop_event: threading.Event,
        log_queue: queue.Queue[Dict[str, Any]]
    ):

        """
        Initializes the ExploitsTab.

        Args:
            parent (ttk.Notebook): The parent Notebook widget.
            core_framework (Any): Reference to the CoreFramework instance for backend operations.
            stop_event (threading.Event): Event to signal stopping of ongoing exploits.
            log_queue (threading.Queue): Queue for logging messages from exploit threads.
        """
        super().__init__(parent)
        self.core = core_framework
        self.stop_event = stop_event
        self.log_queue = log_queue
        self.logger = logging.getLogger('ExploitsTab')
        self.logger.debug("Initializing ExploitsTab.")
        self.create_widgets()
        self.populate_exploits()
        self.update_target_list()

    def create_widgets(self) -> None:
        """
        Creates the widgets for the 'Exploits' tab.
        """
        # Exploit Selection Section
        exploit_label = ttk.Label(self, text="Select Exploits:", font=("Helvetica", 12))
        exploit_label.pack(pady=5)

        self.exploit_vars: Dict[str, tk.BooleanVar] = {}
        exploits = self.core.exploits.keys()
        for ex in exploits:
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(self, text=ex, variable=var)
            chk.pack(anchor='w', padx=20)
            self.exploit_vars[ex] = var

        # Target Selection Section
        target_frame = ttk.LabelFrame(self, text="Target Network")
        target_frame.pack(padx=10, pady=10, fill='x')

        target_label = ttk.Label(target_frame, text="Select Target:")
        target_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

        self.selected_target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(target_frame, textvariable=self.selected_target_var, state='readonly')
        self.target_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        refresh_button = ttk.Button(target_frame, text="Refresh Targets", command=self.update_target_list)
        refresh_button.grid(row=0, column=2, padx=5, pady=5)

        # Exploit-specific Parameters Section
        params_frame = ttk.LabelFrame(self, text="Exploit Parameters")
        params_frame.pack(padx=10, pady=10, fill='x')

        # Payload Type Selection (for Payload Delivery)
        payload_label = ttk.Label(params_frame, text="Payload Type (for Payload Delivery):")
        payload_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.payload_type_var = tk.StringVar()
        self.payload_type_combo = ttk.Combobox(
            params_frame,
            textvariable=self.payload_type_var,
            state='readonly',
            values=['reverse_shell', 'malicious_script']
        )
        self.payload_type_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.payload_type_combo.current(0)

        # Duration Selection (for duration-based exploits)
        duration_label = ttk.Label(params_frame, text="Exploit Duration (seconds):")
        duration_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.duration_entry = ttk.Entry(params_frame, width=30)
        self.duration_entry.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        self.duration_entry.insert(0, "10")  # Default duration

        # Exploit Execution Button
        exploit_button = ttk.Button(self, text="Run Exploits", command=self.run_exploits)
        exploit_button.pack(pady=10)

        # Log Area for Exploits
        self.exploit_log = tk.Text(self, height=15, state='disabled', wrap='word')
        self.exploit_log.pack(padx=10, pady=10, fill='both', expand=True)

    def populate_exploits(self) -> None:
        """
        Populates the exploit selection checkboxes based on available exploits.
        """
        # This method is already handled in create_widgets via self.exploit_vars
        # Included for future enhancements if needed
        pass

    def update_target_list(self) -> None:
        """
        Updates the target selection combobox with the latest targets from the universal pool.
        """
        try:
            targets = self.core.get_all_targets()
            target_list = [f"{t.ssid} ({t.bssid})" for t in targets]
            self.target_combo['values'] = target_list
            if target_list:
                self.target_combo.current(0)
            else:
                self.selected_target_var.set('')
                self.logger.warning("No targets available in the pool.")
        except Exception as e:
            self.log_message(f"Error fetching targets: {e}")
            self.logger.error(f"Error fetching targets: {e}")

    def run_exploits(self) -> None:
        """
        Initiates the exploitation process based on selected exploits and target information.
        """
        selected_exploits = [ex for ex, var in self.exploit_vars.items() if var.get()]
        selected_target = self.selected_target_var.get()

        # Input validation
        if not selected_exploits:
            messagebox.showwarning("No Exploits Selected", "Please select at least one exploit.")
            return
        if not selected_target:
            messagebox.showwarning("No Target Selected", "Please select a target network.")
            return

        # Extract BSSID from selection
        bssid_match = re.search(r'\(([^)]+)\)', selected_target)
        if bssid_match:
            bssid = bssid_match.group(1)
        else:
            messagebox.showwarning("Invalid Target Format", "Selected target has an invalid format.")
            return

        target = {'ssid': selected_target.split('(')[0].strip(), 'bssid': bssid}

        # Gather exploit-specific parameters
        payload_type = self.payload_type_var.get()
        duration = self.duration_entry.get().strip()
        try:
            duration = int(duration)
        except ValueError:
            messagebox.showwarning("Invalid Duration", "Please enter a valid integer for exploit duration.")
            return

        # Reset stop_event before starting new exploits
        if self.stop_event.is_set():
            self.stop_event.clear()

        # Start exploitation in a separate thread
        exploit_thread = threading.Thread(
            target=self.execute_exploits,
            args=(selected_exploits, target, payload_type, duration),
            daemon=True
        )
        exploit_thread.start()

    def execute_exploits(self, exploits: List[str], target: Dict[str, str],
                         payload_type: str, duration: int) -> None:
        """
        Executes the selected exploits against the target network.

        Args:
            exploits (List[str]): List of exploit names to run.
            target (Dict[str, str]): Target network details (SSID and BSSID).
            payload_type (str): Type of payload for payload delivery exploits.
            duration (int): Duration for which the exploit should run.
        """
        for ex in exploits:
            if self.stop_event.is_set():
                self.log_message("Exploit operation interrupted by user.")
                break
            self.log_message(f"Running exploit: {ex}")
            self.logger.info(f"Running exploit: {ex}")

            vuln = self.core.vulnerability_db.get(ex, {})

            # Customize exploit parameters based on exploit type
            if ex == 'session_hijacking':
                # Assuming the exploit expects a target_session dictionary
                target_session = {
                    'target_ip': target.get('ip', ''),
                    'target_mac': target.get('mac', ''),
                    'gateway_ip': target.get('gateway_ip', ''),
                    'gateway_mac': target.get('gateway_mac', '')
                }
                vuln['target_session'] = target_session
            elif ex == 'payload_delivery':
                vuln['payload_type'] = payload_type
                vuln['duration'] = duration

            try:
                # Execute the exploit via CoreFramework
                self.core.run_exploit(ex, vuln)
                self.log_message(f"Exploit '{ex}' completed successfully.\n")
                self.logger.info(f"Exploit '{ex}' completed successfully.")
            except Exception as e:
                self.log_message(f"Error running exploit '{ex}': {e}\n")
                self.logger.error(f"Error running exploit '{ex}': {e}")

    def log_message(self, message: str) -> None:
        """
        Logs messages to the exploit log text widget.

        Args:
            message (str): The message to log.
        """
        self.exploit_log.config(state='normal')
        self.exploit_log.insert(tk.END, message + '\n')
        self.exploit_log.see(tk.END)
        self.exploit_log.config(state='disabled')
        self.logger.debug(f"Logged message: {message}")



class ReportsTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self) -> None:
        """
        Creates the widgets for the 'Reports' tab.
        """
        # Report Display Area
        self.report_text = tk.Text(self, height=25, state='disabled')
        self.report_text.pack(padx=10, pady=10, fill='both', expand=True)

        # Export Report Button
        export_button = ttk.Button(self, text="Export Report", command=self.export_report)
        export_button.pack(pady=5)

        # Load and Display Current Report
        self.load_report()

    def load_report(self) -> None:
        """
        Loads and displays the current report from the vulnerabilities database.
        """
        try:
            report_data = self.core.vulnerability_db
            report_str = json.dumps(report_data, indent=4)
            self.report_text.config(state='normal')
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, report_str)
            self.report_text.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to load report: {e}")
            self.report_text.config(state='normal')
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, "Error loading report.")
            self.report_text.config(state='disabled')

    def export_report(self) -> None:
        """
        Exports the generated reports to a file.

        Allows the user to choose the format (TXT or JSON) and the destination file.
        """
        # Prompt user to choose export format and location
        export_format = tk.StringVar(value='json')
        format_window = tk.Toplevel(self)
        format_window.title("Select Export Format")
        ttk.Label(format_window, text="Choose Report Format:").pack(padx=10, pady=10)
        format_combo = ttk.Combobox(format_window, textvariable=export_format, state='readonly')
        format_combo['values'] = ['txt', 'json']
        format_combo.pack(padx=10, pady=5)
        format_combo.current(0)

        def confirm_export():
            selected_format = export_format.get()
            if selected_format == 'txt':
                file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                         filetypes=[("Text Files", "*.txt"), ("All files", "*.*")])
                if file_path:
                    try:
                        with open(file_path, 'w') as f:
                            f.write(self.report_text.get(1.0, tk.END))
                        messagebox.showinfo("Export Successful", f"Report exported to {file_path}")
                    except Exception as e:
                        messagebox.showerror("Export Error", f"Failed to export report: {e}")
            elif selected_format == 'json':
                file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                         filetypes=[("JSON Files", "*.json"), ("All files", "*.*")])
                if file_path:
                    try:
                        with open(file_path, 'w') as f:
                            json.dump(self.core.vulnerability_db, f, indent=4)
                        messagebox.showinfo("Export Successful", f"Report exported to {file_path}")
                    except Exception as e:
                        messagebox.showerror("Export Error", f"Failed to export report: {e}")
            format_window.destroy()

        ttk.Button(format_window, text="Export", command=confirm_export).pack(pady=10)


class SettingsTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook):
        super().__init__(parent)
        self.create_widgets()

    def create_widgets(self) -> None:
        """
        Creates the widgets for the 'Settings' tab.
        """
        # Configuration Settings Label
        config_label = ttk.Label(self, text="Configuration Settings:")
        config_label.pack(pady=5)

        # Configuration Display Area
        self.config_text = tk.Text(self, height=20, state='disabled')
        self.config_text.pack(padx=10, pady=10, fill='both', expand=True)

        # Refresh Configuration Button
        refresh_button = ttk.Button(self, text="Refresh Configuration", command=self.load_configuration)
        refresh_button.pack(pady=5)

        # Load and Display Current Configuration
        self.load_configuration()

    def load_configuration(self) -> None:
        """
        Loads and displays the current configuration settings from the vulnerabilities database.
        """
        try:
            report_data = self.core.vulnerability_db
            report_str = json.dumps(report_data, indent=4)
            self.config_text.config(state='normal')
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(tk.END, report_str)
            self.config_text.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to load configuration: {e}")
            self.config_text.config(state='normal')
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(tk.END, "Error loading configuration.")
            self.config_text.config(state='disabled')


def main():
    """
    Entry point for the WirelessPenTestLib GUI application.

    Initializes and runs the GUI application.
    """
    # Initialize and run the GUI application
    app = WirelessPenTestGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
