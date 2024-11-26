# ui/frames/hidden_ssid_frame.py

import tkinter as tk
from tkinter import ttk
from wireless_pen_test_lib.core import CoreFramework

class HiddenSSIDFrame(ttk.Frame):
    def __init__(self, parent, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self):
        self.start_button = ttk.Button(self, text="Start Hidden SSID Reveal", command=self.start_reveal)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(self, text="Stop Reveal", command=self.stop_reveal)
        self.stop_button.pack(pady=10)

        self.ssid_tree = ttk.Treeview(self, columns=("SSID", "MAC Address", "Last Seen"), show='headings')
        self.ssid_tree.heading("SSID", text="SSID")
        self.ssid_tree.heading("MAC Address", text="MAC Address")
        self.ssid_tree.heading("Last Seen", text="Last Seen")
        self.ssid_tree.pack(fill=tk.BOTH, expand=True)

        self.refresh_button = ttk.Button(self, text="Refresh", command=self.refresh_data)
        self.refresh_button.pack(pady=10)

    def start_reveal(self):
        self.core.start_hidden_ssid_reveal()

    def stop_reveal(self):
        self.core.stop_event.set()

    def refresh_data(self):
        ssid_list = self.core.get_hidden_ssids()
        for row in self.ssid_tree.get_children():
            self.ssid_tree.delete(row)
        for ssid in ssid_list:
            self.ssid_tree.insert("", tk.END, values=(ssid['SSID'], ssid['MAC Address'], ssid['Last Seen']))
