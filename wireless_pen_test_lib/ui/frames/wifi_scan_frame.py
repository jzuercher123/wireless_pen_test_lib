# ui/frames/wifi_scan_frame.py

import tkinter as tk
from tkinter import ttk, messagebox
from wireless_pen_test_lib.core import CoreFramework


class WifiScanFrame(ttk.Frame):
    """
    Frame for Wi-Fi Scanning Functionality
    """

    def __init__(self, parent, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self):
        # Title
        title = ttk.Label(self, text="Wi-Fi Network Scanner", font=("Helvetica", 16))
        title.pack(pady=10)

        # Scan Button
        scan_button = ttk.Button(self, text="Scan Wi-Fi Networks", command=self.scan_wifi)
        scan_button.pack(pady=5)

        # Results Treeview
        columns = ("SSID", "BSSID", "Signal", "Channel", "Security")
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor='center')
        self.tree.pack(pady=10, fill='both', expand=True)

    def scan_wifi(self):
        try:
            # Clear previous results
            for row in self.tree.get_children():
                self.tree.delete(row)

            # Initiate scan
            networks = self.core.scan_wifi_networks(scan_duration=5)

            # Populate Treeview with results
            for network in networks:
                self.tree.insert("", "end", values=(
                    network.get('ssid', 'N/A'),
                    network.get('bssid', 'N/A'),
                    f"{network.get('signal', 'N/A')} dBm",
                    network.get('channel', 'N/A'),
                    network.get('security', 'N/A')
                ))

            messagebox.showinfo("Scan Complete", f"Found {len(networks)} networks.")

        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during Wi-Fi scanning:\n{e}")
