# ui/gui.py
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tkinter import messagebox, filedialog
import threading
import json
from core.__init__ import CoreFramework
import tkinter as tk
from tkinter import ttk
from ui.frames.live_network_frame import LiveNetworkFrame
from ui.frames.live_packet_monitor import LivePacketMonitor
from ui.frames.test_devices import FakeDeviceManager
from ui.frames.rogue_access_point import FakeAccessPoint

# Adjust the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.insert(0, project_root)
# Import register_scanners and register_exploits
from core.config.protocols import register_scanners, register_exploits


def create_test_data():
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
    def __init__(self):
        super().__init__()
        self.wep_networks = None
        self.wpa_networks = None
        self.title("WirelessPenTestLib GUI")
        self.geometry("800x600")
        # Initialize stop event
        self.stop_event = threading.Event()
        # Initialize Core Framework
        self.core = self.initialize_coreframework()
        if not self.core:
            messagebox.showerror("Initialization Error", "Failed to initialize CoreFramework. Exiting.")
            self.destroy()
            return
        # Create a Container Frame to hold Notebook and Stop Button
        container_frame = ttk.Frame(self)
        container_frame.pack(fill=tk.BOTH, expand=True)
        # Create a Notebook (tabbed interface) inside the Container Frame
        self.notebook = ttk.Notebook(container_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, side='top')
        # Add Live Network Details tab
        self.live_network_frame = LiveNetworkFrame(
            parent=self.notebook,
            core_framework=self.core,
            scan_interval=30  # Scan every 30 seconds
        )
        self.notebook.add(self.live_network_frame, text="Live Network Details")
        # Load vulnerability database
        self.vulnerability_db = self.core.vulnerability_db
        # Create additional tabs
        self.create_scan_tab(container_frame)
        self.create_exploit_tab(container_frame)
        self.create_report_tab(container_frame)
        self.create_settings_tab(container_frame)
        # Add Stop Button at the bottom of the Container Frame
        self.add_stop_button(container_frame)
        self.create_live_packet_monitor_tab(container_frame)
        self.create_fake_devices_tab(container_frame)
        self.create_rogue_access_point_tab(container_frame)


    def initialize_coreframework(self):
        """
        Initializes the CoreFramework with necessary configurations.
        """
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
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Failed to initialize CoreFramework: {e}")
            return None

    def enter_fake_data(self):
        test_data = create_test_data()
        self.wpa_networks = test_data["wpa_networks"]
        self.wep_networks = test_data["wep_networks"]
        self.live_network_frame.update_gui(test_data)

    def run_gui_as_test(self):
        self.enter_fake_data()
        self.mainloop()

    def create_scan_tab(self, parent):
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text='Scans')
        # Scanner Selection
        scanner_label = ttk.Label(scan_frame, text="Select Scanners:")
        scanner_label.pack(pady=5)
        self.scanner_vars = {}
        for sc in self.core.scanners.keys():
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(scan_frame, text=sc, variable=var)
            chk.pack(anchor='w', padx=20)
            self.scanner_vars[sc] = var
        # Target Selection
        target_frame = ttk.LabelFrame(scan_frame, text="Target Network")
        target_frame.pack(padx=10, pady=10, fill='x')
        ssid_label = ttk.Label(target_frame, text="SSID:")
        ssid_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.scan_ssid_entry = ttk.Entry(target_frame, width=50)
        self.scan_ssid_entry.grid(row=0, column=1, padx=5, pady=5)
        bssid_label = ttk.Label(target_frame, text="BSSID:")
        bssid_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.scan_bssid_entry = ttk.Entry(target_frame, width=50)
        self.scan_bssid_entry.grid(row=1, column=1, padx=5, pady=5)
        # Scan Button
        scan_button = ttk.Button(scan_frame, text="Run Scans", command=self.run_scans)
        scan_button.pack(pady=10)
        finalize_button = ttk.Button(scan_frame, text="Finalize and Generate Reports",
                                     command=self.finalize_and_generate_reports)
        finalize_button.pack(pady=10)
        # Log Area
        self.scan_log = tk.Text(scan_frame, height=15, state='disabled')
        self.scan_log.pack(padx=10, pady=10, fill='both', expand=True)

    def add_stop_button(self, parent):
        """
        Adds a Stop button at the bottom of the GUI to halt ongoing operations.
        """
        stop_button = ttk.Button(parent, text="Stop", command=self.stop_operations)
        stop_button.pack(pady=10, side='bottom')

    def stop_operations(self):
        """
        Handles the Stop button click event. Signals all running operations to terminate.
        """
        if not self.stop_event.is_set():
            self.stop_event.set()
            self.log_scan("Stop signal sent. Attempting to halt ongoing operations...")
            self.log_exploit("Stop signal sent. Attempting to halt ongoing operations...")
            # Stop ongoing exploits
            self.core.stop_continuous_packets()
            self.log_scan("Stop signal processed.")
            self.log_exploit("Stop signal processed.")
        else:
            self.log_scan("No ongoing operations to stop.")
            self.log_exploit("No ongoing operations to stop.")

    def run_scans(self):
        selected_scanners = [sc for sc, var in self.scanner_vars.items() if var.get()]
        ssid = self.scan_ssid_entry.get()
        bssid = self.scan_bssid_entry.get()
        if not selected_scanners:
            messagebox.showwarning("No Scanners Selected", "Please select at least one scanner.")
            return
        if not ssid or not bssid:
            messagebox.showwarning("Incomplete Target Information", "Please provide both SSID and BSSID.")
            return
        target = {'ssid': ssid, 'bssid': bssid}
        # Reset stop_event before starting new scans
        if self.stop_event.is_set():
            self.stop_event.clear()
        # Start scanning in a separate thread
        threading.Thread(target=self.execute_scans, args=(selected_scanners, target), daemon=True).start()

    def finalize_and_generate_reports(self):
        threading.Thread(target=self.execute_finalize, daemon=True).start()

    def execute_finalize(self):
        try:
            self.core.finalize()
            self.report_text.config(state='normal')
            self.report_text.insert(tk.END, "Reports generated successfully.\n")
            self.report_text.see(tk.END)
            self.report_text.config(state='disabled')
            messagebox.showinfo("Finalize Complete", "Reports generated successfully.")
        except Exception as e:
            messagebox.showerror("Finalize Error", f"Failed to finalize and generate reports: {e}")

    def execute_scans(self, scanners, target):
        for sc in scanners:
            if self.stop_event.is_set():
                self.log_scan("Scan operation interrupted by user.")
                break
            self.log_scan(f"Running scanner: {sc}")
            try:
                # Pass the stop_event to the scanner's scan method if possible
                scan_result = self.core.run_scanner(sc, target, self.stop_event)
                self.log_scan(f"Scanner '{sc}' completed.\n")
                # Optionally, display scan results in the log
                for device in scan_result.get("devices", []):
                    device_info = f"IP: {device.get('ip', 'N/A')}, MAC: {device.get('mac', 'N/A')}, Hostname: {device.get('hostname', 'N/A')}, SSID: {device.get('ssid', 'N/A')}, BSSID: {device.get('bssid', 'N/A')}"
                    self.log_scan(f"Discovered Device: {device_info}")
            except Exception as e:
                self.log_scan(f"Error running scanner '{sc}': {e}\n")

    def log_scan(self, message):
        self.scan_log.config(state='normal')
        self.scan_log.insert(tk.END, message + '\n')
        self.scan_log.see(tk.END)
        self.scan_log.config(state='disabled')

    def create_exploit_tab(self, parent):
        exploit_frame = ttk.Frame(self.notebook)
        self.notebook.add(exploit_frame, text='Exploits')
        # Exploit Selection
        exploit_label = ttk.Label(exploit_frame, text="Select Exploits:")
        exploit_label.pack(pady=5)
        self.exploit_vars = {}
        for ex in self.core.exploits.keys():
            var = tk.BooleanVar()
            chk = ttk.Checkbutton(exploit_frame, text=ex, variable=var)
            chk.pack(anchor='w', padx=20)
            self.exploit_vars[ex] = var
        # Target Selection
        target_frame = ttk.LabelFrame(exploit_frame, text="Target Network")
        target_frame.pack(padx=10, pady=10, fill='x')
        ssid_label = ttk.Label(target_frame, text="SSID:")
        ssid_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.exploit_ssid_entry = ttk.Entry(target_frame, width=50)
        self.exploit_ssid_entry.grid(row=0, column=1, padx=5, pady=5)
        bssid_label = ttk.Label(target_frame, text="BSSID:")
        bssid_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.exploit_bssid_entry = ttk.Entry(target_frame, width=50)
        self.exploit_bssid_entry.grid(row=1, column=1, padx=5, pady=5)
        # Exploit-specific Parameters
        params_frame = ttk.LabelFrame(exploit_frame, text="Exploit Parameters")
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
        # Payload Type (for Payload Delivery)
        payload_label = ttk.Label(params_frame, text="Payload Type (for Payload Delivery):")
        payload_label.grid(row=4, column=0, padx=5, pady=5, sticky='e')
        self.payload_type_var = tk.StringVar()
        self.payload_type_combo = ttk.Combobox(params_frame, textvariable=self.payload_type_var, state='readonly')
        self.payload_type_combo['values'] = ['reverse_shell', 'malicious_script']
        self.payload_type_combo.grid(row=4, column=1, padx=5, pady=5)
        self.payload_type_combo.current(0)
        # Exploit Button
        exploit_button = ttk.Button(exploit_frame, text="Run Exploits", command=self.run_exploits)
        exploit_button.pack(pady=10)
        # Log Area
        self.exploit_log = tk.Text(exploit_frame, height=15, state='disabled')
        self.exploit_log.pack(padx=10, pady=10, fill='both', expand=True)

    def run_exploits(self):
        selected_exploits = [ex for ex, var in self.exploit_vars.items() if var.get()]
        ssid = self.exploit_ssid_entry.get()
        bssid = self.exploit_bssid_entry.get()
        if not selected_exploits:
            messagebox.showwarning("No Exploits Selected", "Please select at least one exploit.")
            return
        if not ssid or not bssid:
            messagebox.showwarning("Incomplete Target Information", "Please provide both SSID and BSSID.")
            return
        # Gather exploit-specific parameters
        target_session = {
            'target_ip': self.exploit_ip_entry.get(),
            'target_mac': self.exploit_mac_entry.get(),
            'gateway_ip': self.exploit_gateway_ip_entry.get(),
            'gateway_mac': self.exploit_gateway_mac_entry.get()
        }
        payload_type = self.payload_type_var.get()
        duration = 10  # Default duration, can be enhanced to allow user input
        # Define the target and vulnerability details
        target = {
            'ssid': ssid,
            'bssid': bssid
        }
        # Reset stop_event before starting new exploits
        if self.stop_event.is_set():
            self.stop_event.clear()
        # Start exploitation in a separate thread
        threading.Thread(target=self.execute_exploits,
                         args=(selected_exploits, target, target_session, payload_type, duration),
                         daemon=True).start()

    def execute_exploits(self, exploits, target, target_session, payload_type, duration):
        for ex in exploits:
            if self.stop_event.is_set():
                self.log_exploit("Exploit operation interrupted by user.")
                break
            self.log_exploit(f"Running exploit: {ex}")
            vuln = self.vulnerability_db.get(ex, {})
            if ex == 'session_hijacking':
                vuln['target_session'] = target_session
            elif ex == 'payload_delivery':
                vuln['payload_type'] = payload_type
                vuln['duration'] = duration
            try:
                # Pass the stop_event to the exploit's scan method
                self.core.run_exploit(ex, vuln, self.stop_event)
                self.log_exploit(f"Exploit '{ex}' completed.\n")
            except Exception as e:
                self.log_exploit(f"Error running exploit '{ex}': {e}\n")

    def log_exploit(self, message):
        self.exploit_log.config(state='normal')
        self.exploit_log.insert(tk.END, message + '\n')
        self.exploit_log.see(tk.END)
        self.exploit_log.config(state='disabled')

    def create_report_tab(self, parent):
        report_frame = ttk.Frame(self.notebook)
        self.notebook.add(report_frame, text='Reports')
        # Report Display
        self.report_text = tk.Text(report_frame, height=25, state='disabled')
        self.report_text.pack(padx=10, pady=10, fill='both', expand=True)
        # Export Button
        export_button = ttk.Button(report_frame, text="Export Report", command=self.export_report)
        export_button.pack(pady=5)

    def export_report(self):
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
                file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
                if file_path:
                    try:
                        with open(file_path, 'w') as f:
                            f.write(self.report_text.get(1.0, tk.END))
                        messagebox.showinfo("Export Successful", f"Report exported to {file_path}")
                    except Exception as e:
                        messagebox.showerror("Export Error", f"Failed to export report: {e}")
            elif selected_format == 'json':
                file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
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

    def create_settings_tab(self, parent):
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text='Settings')
        # Configuration Settings
        config_label = ttk.Label(settings_frame, text="Configuration Settings:")
        config_label.pack(pady=5)
        self.config_text = tk.Text(settings_frame, height=20, state='disabled')
        self.config_text.pack(padx=10, pady=10, fill='both', expand=True)
        # Load and Display Current Configuration
        self.load_configuration()
        # Refresh Button
        refresh_button = ttk.Button(settings_frame, text="Refresh Configuration", command=self.load_configuration)
        refresh_button.pack(pady=5)

    def load_configuration(self):
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

    def create_live_packet_monitor_tab(self, parent):
        live_packet_monitor = LivePacketMonitor(parent)
        self.notebook.add(live_packet_monitor, text="Live Packet Monitor")

    def create_fake_devices_tab(self, parent):
        fake_devices_frame = FakeDeviceManager(parent)
        self.notebook.add(fake_devices_frame, text="Fake Devices")

    def create_rogue_access_point_tab(self, parent):
        rogue_access_point_frame = FakeAccessPoint(parent)
        self.notebook.add(rogue_access_point_frame, text="Rogue Access Point")




if __name__ == '__main__':
    app = WirelessPenTestGUI()
    app.mainloop()