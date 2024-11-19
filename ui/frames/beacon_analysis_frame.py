# ui/frames/beacon_analysis_frame.py

import tkinter as tk
from tkinter import ttk
from core import CoreFramework

class BeaconAnalysisFrame(ttk.Frame):
    def __init__(self, parent, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self):
        self.start_button = ttk.Button(self, text="Start Beacon Analysis", command=self.start_analysis)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(self, text="Stop Analysis", command=self.stop_analysis)
        self.stop_button.pack(pady=10)

        self.ap_tree = ttk.Treeview(self, columns=("SSID", "BSSID", "Capabilities", "Last Seen"), show='headings')
        self.ap_tree.heading("SSID", text="SSID")
        self.ap_tree.heading("BSSID", text="BSSID")
        self.ap_tree.heading("Capabilities", text="Capabilities")
        self.ap_tree.heading("Last Seen", text="Last Seen")
        self.ap_tree.pack(fill=tk.BOTH, expand=True)

        self.refresh_button = ttk.Button(self, text="Refresh", command=self.refresh_data)
        self.refresh_button.pack(pady=10)

    def start_analysis(self):
        self.core.start_beacon_analysis()

    def stop_analysis(self):
        self.core.stop_event.set()

    def refresh_data(self):
        ap_list = self.core.get_access_points()
        for row in self.ap_tree.get_children():
            self.ap_tree.delete(row)
        for ap in ap_list:
            self.ap_tree.insert("", tk.END, values=(ap['SSID'], ap['BSSID'], ", ".join(ap['Capabilities']), ap['Last Seen']))
