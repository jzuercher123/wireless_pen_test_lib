# ui/gui.py

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

The GUI interacts with the CoreFramework to perform network scanning, exploitation, and reporting tasks.

**⚠️ Important Note:**
Creating rogue access points and performing network penetration testing should only be done
with explicit permission on networks you own or have authorization to test. Unauthorized access
to networks is illegal and unethical.
"""

import sys
import os
import json
import threading
import queue
import re
from typing import Optional, Dict, Any, List

# Add the parent directory to the system path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from core.__init__ import CoreFramework
from core.config.protocols import register_scanners, register_exploits
from ui.frames.live_network_frame import LiveNetworkFrame
from ui.frames.live_packet_monitor import LivePacketMonitor
from ui.frames.test_devices import FakeDeviceManager
from ui.frames.rogue_access_point import FakeAccessPoint
from ui.frames.network_graph_visualization import NetworkGraphVisualizationFrame


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
        wep_networks (Optional[Dict[str, Any]]): Stores WEP network information.
        wpa_networks (Optional[Dict[str, Any]]): Stores WPA network information.
        core (Optional[CoreFramework]): Instance of the CoreFramework for backend operations.
        vulnerability_db (Any): Database of known vulnerabilities.
        stop_event (threading.Event): Event to signal threads to stop operations.
    """

    def __init__(self):
        """
        Initializes the WirelessPenTestGUI application.

        Sets up the main window, initializes the CoreFramework, and creates all necessary tabs.
        """
        super().__init__()
        self.wep_networks: Optional[Dict[str, Any]] = None
        self.wpa_networks: Optional[Dict[str, Any]] = None
        self.title("WirelessPenTestLib GUI")
        self.geometry("1200x800")  # Increased size for better usability

        # Initialize stop event to manage thread termination
        self.stop_event = threading.Event()

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

        # Add Live Network Details tab
        self.live_network_frame = LiveNetworkFrame(
            parent=self.notebook,
            core_framework=self.core,
            scan_interval=30  # Scan every 30 seconds
        )
        self.notebook.add(self.live_network_frame, text="Live Network Details")

        # Load vulnerability database from CoreFramework
        self.vulnerability_db = self.core.vulnerability_db

        # Create additional tabs for various functionalities
        self.create_scan_tab()
        self.create_exploit_tab()
        self.create_report_tab()
        self.create_settings_tab()
        self.create_live_packet_monitor_tab()
        self.create_fake_devices_tab()
        self.create_rogue_access_point_tab()
        self.create_network_visualization_tab()

        # Add a Stop button at the bottom of the container frame to halt ongoing operations
        self.add_stop_button(container_frame)

        # Bind the protocol for window closing to ensure cleanup
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

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

    def enter_fake_data(self):
        """
        Inserts fake test data into the LiveNetworkFrame for testing purposes.
        """
        test_data = create_test_data()
        self.wpa_networks = test_data["wpa_networks"]
        self.wep_networks = test_data["wep_networks"]
        self.live_network_frame.update_gui(test_data)

    def run_gui_as_test(self):
        """
        Populates the GUI with fake data and starts the main loop.

        Useful for testing the GUI without connecting to real networks.
        """
        self.enter_fake_data()
        self.mainloop()

    def create_scan_tab(self) -> None:
        """
        Creates the 'Scans' tab in the Notebook.
        """
        self.scans_tab = ScansTab(self.notebook, self.core, self.stop_event, self.scan_log_queue)
        self.notebook.add(self.scans_tab, text='Scans')

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

        Signals all running operations (scans and exploits) to terminate gracefully.
        """
        if not self.stop_event.is_set():
            self.stop_event.set()
            self.scan_log_queue.put("Stopping operations...")
            self.exploit_log_queue.put("Stopping operations...")

            # Wait for threads to finish
            if hasattr(self, 'scan_thread') and self.scan_thread.is_alive():
                self.scan_thread.join(timeout=5)
            if hasattr(self, 'exploit_thread') and self.exploit_thread.is_alive():
                self.exploit_thread.join(timeout=5)

            self.scan_log_queue.put("Operations stopped.")
            self.exploit_log_queue.put("Operations stopped.")
        else:
            self.scan_log_queue.put("No ongoing operations to stop.")
            self.exploit_log_queue.put("No ongoing operations to stop.")

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

    def create_exploit_tab(self) -> None:
        """
        Creates the 'Exploits' tab in the Notebook.
        """
        self.exploits_tab = ExploitsTab(self.notebook, self.core, self.stop_event, self.exploit_log_queue)
        self.notebook.add(self.exploits_tab, text='Exploits')

    def create_report_tab(self) -> None:
        """
        Creates the 'Reports' tab in the Notebook.
        """
        self.reports_tab = ReportsTab(self.notebook, self.core)
        self.notebook.add(self.reports_tab, text='Reports')

    def create_settings_tab(self) -> None:
        """
        Creates the 'Settings' tab in the Notebook.
        """
        self.settings_tab = SettingsTab(self.notebook)
        self.notebook.add(self.settings_tab, text='Settings')

    def create_live_packet_monitor_tab(self) -> None:
        """
        Creates the 'Live Packet Monitor' tab in the Notebook.
        """
        live_packet_monitor = LivePacketMonitor(self.notebook)
        self.notebook.add(live_packet_monitor, text="Live Packet Monitor")

    def create_fake_devices_tab(self) -> None:
        """
        Creates the 'Fake Devices' tab in the Notebook.
        """
        fake_devices_frame = FakeDeviceManager(self.notebook)
        self.notebook.add(fake_devices_frame, text="Fake Devices")

    def create_rogue_access_point_tab(self) -> None:
        """
        Creates the 'Rogue Access Point' tab in the Notebook.
        """
        rogue_access_point_frame = FakeAccessPoint(self.notebook)
        self.notebook.add(rogue_access_point_frame, text="Rogue Access Point")

    def create_network_visualization_tab(self) -> None:
        """
        Creates the 'Network Visualization' tab in the Notebook.
        """
        network_graph_frame = NetworkGraphVisualizationFrame(self.notebook)
        self.notebook.add(network_graph_frame, text="Network Visualization")

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
        self.scan_log = tk.Text(self, height=15, state='disabled')
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
                # Pass the stop_event to the scanner's scan method if possible
                scan_result = self.core.run_scanner(sc, target, self.stop_event)
                self.log_queue.put(f"Scanner '{sc}' completed.\n")

                # Optionally, display scan results in the log
                for device in scan_result.get("devices", []):
                    device_info = (f"IP: {device.get('ip', 'N/A')}, "
                                   f"MAC: {device.get('mac', 'N/A')}, "
                                   f"Hostname: {device.get('hostname', 'N/A')}, "
                                   f"SSID: {device.get('ssid', 'N/A')}, "
                                   f"BSSID: {device.get('bssid', 'N/A')}")
                    self.log_queue.put(f"Discovered Device: {device_info}")
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


class ExploitsTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, core_framework: CoreFramework, stop_event: threading.Event,
                 log_queue: queue.Queue):
        super().__init__(parent)
        self.core = core_framework
        self.stop_event = stop_event
        self.log_queue = log_queue
        self.create_widgets()

    def create_widgets(self) -> None:
        """
        Creates the widgets for the 'Exploits' tab.
        """
        # Exploit Selection Section
        exploit_label = ttk.Label(self, text="Select Exploits:")
        exploit_label.pack(pady=5)

        self.exploit_vars: Dict[str, tk.BooleanVar] = {}
        for ex in self.core.exploits.keys():
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(self, text=ex, variable=var)
            chk.pack(anchor='w', padx=20)
            self.exploit_vars[ex] = var

        # Target Selection Section
        target_frame = ttk.LabelFrame(self, text="Target Network")
        target_frame.pack(padx=10, pady=10, fill='x')

        ssid_label = ttk.Label(target_frame, text="SSID:")
        ssid_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.exploit_ssid_entry = ttk.Entry(target_frame, width=50)
        self.exploit_ssid_entry.grid(row=0, column=1, padx=5, pady=5)

        bssid_label = ttk.Label(target_frame, text="BSSID:")
        bssid_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.exploit_bssid_entry = ttk.Entry(target_frame, width=50)
        self.exploit_bssid_entry.grid(row=1, column=1, padx=5, pady=5)

        # Exploit-specific Parameters Section
        params_frame = ttk.LabelFrame(self, text="Exploit Parameters")
        params_frame.pack(padx=10, pady=10, fill='x')

        # Session Hijacking Parameters
        ip_label = ttk.Label(params_frame, text="Target IP (for Session Hijacking):")
        ip_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.exploit_ip_entry = ttk.Entry(params_frame, width=50)
        self.exploit_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        mac_label = ttk.Label(params_frame, text="Target MAC Address:")
        mac_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.exploit_mac_entry = ttk.Entry(params_frame, width=50)
        self.exploit_mac_entry.grid(row=1, column=1, padx=5, pady=5)

        gateway_ip_label = ttk.Label(params_frame, text="Gateway IP:")
        gateway_ip_label.grid(row=2, column=0, padx=5, pady=5, sticky='e')
        self.exploit_gateway_ip_entry = ttk.Entry(params_frame, width=50)
        self.exploit_gateway_ip_entry.grid(row=2, column=1, padx=5, pady=5)

        gateway_mac_label = ttk.Label(params_frame, text="Gateway MAC Address:")
        gateway_mac_label.grid(row=3, column=0, padx=5, pady=5, sticky='e')
        self.exploit_gateway_mac_entry = ttk.Entry(params_frame, width=50)
        self.exploit_gateway_mac_entry.grid(row=3, column=1, padx=5, pady=5)

        # Payload Type Selection (for Payload Delivery)
        payload_label = ttk.Label(params_frame, text="Payload Type (for Payload Delivery):")
        payload_label.grid(row=4, column=0, padx=5, pady=5, sticky='e')
        self.payload_type_var = tk.StringVar()
        self.payload_type_combo = ttk.Combobox(params_frame, textvariable=self.payload_type_var, state='readonly')
        self.payload_type_combo['values'] = ['reverse_shell', 'malicious_script']
        self.payload_type_combo.grid(row=4, column=1, padx=5, pady=5)
        self.payload_type_combo.current(0)

        # Exploit Execution Button
        exploit_button = ttk.Button(self, text="Run Exploits", command=self.run_exploits)
        exploit_button.pack(pady=10)

        # Log Area for Exploits
        self.exploit_log = tk.Text(self, height=15, state='disabled')
        self.exploit_log.pack(padx=10, pady=10, fill='both', expand=True)

    def run_exploits(self) -> None:
        """
        Initiates the exploitation process based on selected exploits and target information.

        Validates user inputs and starts a separate thread to perform exploits to keep the GUI responsive.
        """
        selected_exploits = [ex for ex, var in self.exploit_vars.items() if var.get()]
        ssid = self.exploit_ssid_entry.get().strip()
        bssid = self.exploit_bssid_entry.get().strip()

        # Input validation
        if not selected_exploits:
            messagebox.showwarning("No Exploits Selected", "Please select at least one exploit.")
            return
        if not ssid or not bssid:
            messagebox.showwarning("Incomplete Target Information", "Please provide both SSID and BSSID.")
            return
        if not self.is_valid_bssid(bssid):
            messagebox.showwarning("Invalid BSSID", "Please provide a valid BSSID (MAC address).")
            return

        # Gather exploit-specific parameters
        target_session = {
            'target_ip': self.exploit_ip_entry.get().strip(),
            'target_mac': self.exploit_mac_entry.get().strip(),
            'gateway_ip': self.exploit_gateway_ip_entry.get().strip(),
            'gateway_mac': self.exploit_gateway_mac_entry.get().strip()
        }
        payload_type = self.payload_type_var.get()
        duration = 10  # Default duration; can be enhanced to allow user input

        # Define the target network details
        target = {
            'ssid': ssid,
            'bssid': bssid
        }

        # Reset stop_event before starting new exploits
        if self.stop_event.is_set():
            self.stop_event.clear()

        # Start exploitation in a separate thread
        self.exploit_thread = threading.Thread(
            target=self.execute_exploits,
            args=(selected_exploits, target, target_session, payload_type, duration),
            daemon=True
        )
        self.exploit_thread.start()

    def execute_exploits(self, exploits: List[str], target: Dict[str, str],
                         target_session: Dict[str, str], payload_type: str, duration: int) -> None:
        """
        Executes the selected exploits against the target network.

        Args:
            exploits (list): List of exploit names to run.
            target (Dict[str, str]): Target network details (SSID and BSSID).
            target_session (Dict[str, str]): Session hijacking parameters.
            payload_type (str): Type of payload for payload delivery exploits.
            duration (int): Duration for which the exploit should run.
        """
        for ex in exploits:
            if self.stop_event.is_set():
                self.log_queue.put("Exploit operation interrupted by user.")
                break
            self.log_queue.put(f"Running exploit: {ex}")
            vuln = self.core.vulnerability_db.get(ex, {})

            # Customize exploit parameters based on exploit type
            if ex == 'session_hijacking':
                vuln['target_session'] = target_session
            elif ex == 'payload_delivery':
                vuln['payload_type'] = payload_type
                vuln['duration'] = duration

            try:
                # Execute the exploit via CoreFramework
                self.core.run_exploit(ex, vuln, self.stop_event)
                self.log_queue.put(f"Exploit '{ex}' completed.\n")
            except Exception as e:
                self.log_queue.put(f"Error running exploit '{ex}': {e}\n")

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

    def export_report(self) -> None:
        """
        Exports the generated reports to a file.

        Allows the user to choose the format (TXT or JSON) and the destination file.
        """
        # Prompt user to choose export format and location
        export_format = tk.StringVar(value='txt')
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
                    # Collect report data from scanners and exploits
                    report_data = {
                        'scans': [],
                        'exploits': []
                    }
                    for sc_name, scanner in self.core.scanners.items():
                        if hasattr(scanner, 'detected_vulnerabilities') and scanner.detected_vulnerabilities:
                            report_data['scans'].append({
                                'scanner': sc_name,
                                'vulnerabilities': scanner.detected_vulnerabilities
                            })
                    for ex_name, exploit in self.core.exploits.items():
                        if hasattr(exploit, 'detected_vulnerabilities') and exploit.detected_vulnerabilities:
                            report_data['exploits'].append({
                                'exploit': ex_name,
                                'vulnerabilities': exploit.detected_vulnerabilities
                            })
                    try:
                        with open(file_path, 'w') as f:
                            json.dump(report_data, f, indent=4)
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
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, '..'))
        config_path = os.path.join(project_root, 'vulnerabilities', 'vulnerabilities.json')

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                self.config_text.config(state='normal')
                self.config_text.delete(1.0, tk.END)
                for key, value in config.items():
                    self.config_text.insert(tk.END, f"{key}: {value}\n")
                self.config_text.config(state='disabled')
            except Exception as e:
                messagebox.showerror("Configuration Error", f"Failed to load configuration: {e}")
                self.config_text.config(state='normal')
                self.config_text.delete(1.0, tk.END)
                self.config_text.insert(tk.END, "Error loading configuration.")
                self.config_text.config(state='disabled')
        else:
            self.config_text.config(state='normal')
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(tk.END, "No configuration found.")
            self.config_text.config(state='disabled')


def main():
    """
    Entry point for the WirelessPenTestLib GUI application.

    Ensures the script is run with proper permissions and initializes the GUI.
    """
    # Initialize and run the GUI application
    app = WirelessPenTestGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
