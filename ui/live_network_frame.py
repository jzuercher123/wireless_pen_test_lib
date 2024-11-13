import tkinter as tk
from tkinter import ttk
from threading import Thread, Event
import time
from typing import List, Dict, Any
import queue

from scanners.local_scanner import LocalScanner
from scanners.dos_scanner import DosScanner  # Assuming DosScanner is available


class LiveNetworkFrame(tk.Frame):
    def __init__(self, parent, core_framework, scan_interval=30, *args, **kwargs):
        """
        Initialize the LiveNetworkFrame with network and DoS scanning capabilities.

        Args:
            parent (tk.Widget): Parent widget.
            core_framework: Instance of CoreFramework.
            scan_interval (int): Time interval between scans in seconds.
            *args, **kwargs: Additional arguments.
        """
        super().__init__(parent, *args, **kwargs)
        self.core_framework = core_framework
        self.scan_interval = scan_interval
        self.device_queue = queue.Queue()
        self.stop_monitoring_event = Event()

        # Initialize LocalScanner for network discovery and DosScanner for DoS testing
        self.scanner = LocalScanner(core_framework=self.core_framework)
        self.dos_scanner = DosScanner(core_framework=self.core_framework,
                                      vulnerability_db={},
                                      gui_update_callback=self.update_feedback)

        self.create_widgets()
        self.start_scanning()

    def create_widgets(self):
        """
        Create and layout the widgets.
        """
        # Title Label
        title = tk.Label(self, text="Live Network Details", font=("Helvetica", 16))
        title.pack(pady=10)

        # Treeview for Devices
        columns = ("IP Address", "MAC Address", "Hostname", "SSID", "BSSID")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Feedback Box for real-time feedback
        self.feedback_box = tk.Text(self, height=6, wrap='word', state='disabled')
        self.feedback_box.pack(fill=tk.X, padx=20, pady=10)

        # Refresh and DoS Scan Buttons
        refresh_button = tk.Button(self, text="Refresh Now", command=self.refresh_scan)
        refresh_button.pack(pady=5)

        dos_button = tk.Button(self, text="Start DoS Scan", command=self.start_dos_scan)
        dos_button.pack(pady=5)

    def update_feedback(self, message):
        """
        Updates the feedback box with the latest status message.
        """
        self.feedback_box.config(state='normal')
        self.feedback_box.insert('end', f"{message}\n")
        self.feedback_box.see('end')  # Scroll to the end
        self.feedback_box.config(state='disabled')

    def start_scanning(self):
        """
        Start the scanning thread for continuous network scanning.
        """
        scan_thread = Thread(target=self.scan_loop, daemon=True)
        scan_thread.start()
        self.after(100, self.process_queue)

    def scan_loop(self):
        """
        Continuously scan the network at specified intervals.
        """
        while True:
            self.logger = self.scanner.logger  # Access the scanner's logger
            self.logger.info("Initiating network scan.")
            scan_results = self.scanner.scan()
            self.device_queue.put(scan_results)
            self.logger.info("Network scan completed.")
            time.sleep(self.scan_interval)

    def refresh_scan(self):
        """
        Manually trigger a network scan.
        """
        Thread(target=self.manual_scan, daemon=True).start()

    def manual_scan(self):
        """
        Perform a manual network scan and update the Treeview.
        """
        self.logger = self.scanner.logger
        self.logger.info("Manual network scan initiated.")
        scan_results = self.scanner.scan()
        self.device_queue.put(scan_results)
        self.logger.info("Manual network scan completed.")

    def process_queue(self):
        """
        Process scan results from the queue and update the Treeview.
        """
        try:
            while not self.device_queue.empty():
                scan_results = self.device_queue.get_nowait()
                self.update_treeview(scan_results.get("devices", []))
        except queue.Empty:
            pass
        finally:
            self.after(1000, self.process_queue)  # Check the queue every second

    def update_treeview(self, devices: List[Dict[str, Any]]):
        """
        Update the Treeview with new scan results.

        Args:
            devices (List[Dict[str, Any]]): List of detected devices.
        """
        # Clear existing entries
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert new entries
        for device in devices:
            ip = device.get("ip", "N/A")
            mac = device.get("mac", "N/A")
            hostname = device.get("hostname", "N/A")
            vendor = device.get("vendor", "N/A")
            # Assuming SSID and BSSID are part of the device info
            ssid = device.get("ssid", "N/A")
            bssid = device.get("bssid", "N/A")
            self.tree.insert("", "end", values=(ip, mac, hostname, ssid, bssid))

    def start_dos_scan(self):
        """
        Starts the DoS scan on the selected target in the Treeview.
        """
        selected_item = self.tree.selection()
        if not selected_item:
            self.update_feedback("No target selected for DoS scan.")
            return

        target = self.tree.item(selected_item)['values']
        if not target:
            self.update_feedback("Invalid target selected.")
            return

        target_info = {
            'bssid': target[4]  # Assuming BSSID is at index 4 in Treeview columns
        }
        self.update_feedback(f"Initiating DoS scan on target with BSSID: {target_info['bssid']}")
        Thread(target=self.dos_scanner.scan, args=(target_info,), daemon=True).start()
