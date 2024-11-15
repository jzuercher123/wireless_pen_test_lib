# ui/live_network_frame.py

import threading
import queue
from typing import List, Dict, Any
import tkinter as tk
from tkinter import ttk, messagebox
from scanners.local_scanner import LocalScanner  # Ensure this import is correct
from scanners.dos_scanner import DosScanner      # Ensure this import is correct

class LiveNetworkFrame(ttk.Frame):
    def __init__(self, parent: tk.Tk, core_framework, scan_interval: int = 5, *args, **kwargs):
        """
        Initializes the LiveNetworkFrame.

        Args:
            parent (tk.Tk): The parent Tkinter widget.
            core_framework (CoreFramework): An instance of CoreFramework.
            scan_interval (int): Interval between scans in seconds.
        """
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.pack(fill='both', expand=True)
        self.core_framework = core_framework  # Assign the CoreFramework instance

        # Initialize Scanners with CoreFramework
        self.scanner = LocalScanner(core_framework=self.core_framework, interface="eth0")
        self.dos_scanner = DosScanner(core_framework=self.core_framework, vulnerability_db={})
        self.scan_interval = scan_interval  # Scan interval in seconds

        # Initialize Queue for Scan Results
        self.device_queue = queue.Queue()

        # Setup Logger
        self.logger = self.scanner.logger  # Assuming LocalScanner has a logger

        # Setup GUI Components
        self.create_widgets()

        # Start processing the scan queue
        self.process_scan_queue()

    def create_widgets(self):
        """
        Creates and arranges all GUI components.
        """
        # Frame for Scan Controls
        control_frame = ttk.LabelFrame(self, text="Network Scan Controls")
        control_frame.pack(padx=10, pady=10, fill='x')

        # Manual Scan Button
        scan_button = ttk.Button(control_frame, text="Perform Manual Scan", command=self.perform_manual_scan)
        scan_button.pack(side='left', padx=5, pady=5)

        # DoS Scan Button
        dos_button = ttk.Button(control_frame, text="Start DoS Scan", command=self.initiate_dos_scan)
        dos_button.pack(side='left', padx=5, pady=5)

        # Treeview for Displaying Devices
        columns = ("IP Address", "MAC Address", "Hostname", "SSID", "BSSID")
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(padx=10, pady=10, fill='both', expand=True)

        # Scrollbar for Treeview
        scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # Feedback Label
        self.feedback_label = ttk.Label(self, text="Welcome to Network Scanner GUI", foreground="blue")
        self.feedback_label.pack(pady=5)

    def perform_manual_scan(self):
        """
        Initiates a manual network scan and updates the Treeview with the scan results.
        """
        self.logger.info("Manual network scan initiated.")
        self.update_feedback("Manual network scan started.")

        def scan():
            try:
                scan_results = self.scanner.scan()  # Implement the actual scan method
                self.device_queue.put(scan_results)
                self.logger.info("Manual network scan completed.")
                self.update_feedback("Manual network scan completed.")
            except Exception as e:
                self.logger.error(f"Error during manual network scan: {e}")
                self.update_feedback(f"Error during manual network scan: {e}")

        threading.Thread(target=scan, daemon=True).start()

    def process_scan_queue(self):
        """
        Processes scan results from the device_queue and updates the Treeview.
        Schedules itself to run every second.
        """
        try:
            while not self.device_queue.empty():
                scan_results = self.device_queue.get_nowait()
                devices = scan_results.get("devices", [])
                self.update_treeview(devices)
        except queue.Empty:
            pass
        except Exception as e:
            self.logger.error(f"Error processing scan queue: {e}")
            self.update_feedback(f"Error processing scan queue: {e}")
        finally:
            self.after(1000, self.process_scan_queue)  # Check the queue every second

    def update_treeview(self, devices: List[Dict[str, Any]]):
        """
        Updates the Treeview with new scan results.

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
            ssid = device.get("ssid", "N/A")
            bssid = device.get("bssid", "N/A")
            self.tree.insert("", "end", values=(ip, mac, hostname, ssid, bssid))

    def initiate_dos_scan(self):
        """
        Initiates a DoS scan on the selected target(s) in the Treeview.
        """
        selected_items = self.tree.selection()
        if not selected_items:
            self.update_feedback("No target selected for DoS scan.")
            return

        for item_id in selected_items:
            target = self.tree.item(item_id)['values']
            if not target:
                self.update_feedback("Invalid target selected.")
                continue

            # Assuming Treeview columns are ordered as: IP, MAC, Hostname, SSID, BSSID
            bssid = target[4]  # BSSID is at index 4
            target_info = {'bssid': bssid}

            self.update_feedback(f"Initiating DoS scan on target with BSSID: {bssid}")

            def dos_scan():
                try:
                    self.dos_scanner.scan(target_info)  # Implement the actual DoS scan method
                    self.update_feedback(f"DoS scan on BSSID {bssid} completed.")
                except Exception as e:
                    self.logger.error(f"Error during DoS scan on BSSID {bssid}: {e}")
                    self.update_feedback(f"Error during DoS scan on BSSID {bssid}: {e}")

            threading.Thread(target=dos_scan, daemon=True).start()

    def update_feedback(self, message: str):
        """
        Updates the feedback label with the provided message.

        Args:
            message (str): The message to display to the user.
        """
        self.feedback_label.config(text=message)
