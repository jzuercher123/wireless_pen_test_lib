# ui/frames/deauth_attack_frame.py

import tkinter as tk
from tkinter import ttk, messagebox
from core import CoreFramework

class DeauthAttackFrame(ttk.Frame):
    def __init__(self, parent, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self):
        # Target BSSID
        bssid_label = ttk.Label(self, text="Target BSSID:")
        bssid_label.pack(pady=5)
        self.bssid_entry = ttk.Entry(self, width=30)
        self.bssid_entry.pack(pady=5)

        # Target Client (Optional)
        client_label = ttk.Label(self, text="Target Client MAC (Optional):")
        client_label.pack(pady=5)
        self.client_entry = ttk.Entry(self, width=30)
        self.client_entry.pack(pady=5)

        # Interface Selection
        interface_label = ttk.Label(self, text="Network Interface:")
        interface_label.pack(pady=5)
        self.interface_entry = ttk.Entry(self, width=30)
        self.interface_entry.pack(pady=5)

        # Start and Stop Buttons
        self.start_button = ttk.Button(self, text="Start Deauth Attack", command=self.start_attack)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(self, text="Stop Deauth Attack", command=self.stop_attack)
        self.stop_button.pack(pady=10)

    def start_attack(self):
        bssid = self.bssid_entry.get().strip()
        client = self.client_entry.get().strip()
        interface = self.interface_entry.get().strip()

        if not bssid or not interface:
            messagebox.showwarning("Input Required", "Please provide at least the Target BSSID and Interface.")
            return

        # Validate MAC address format
        if not self.is_valid_mac(bssid):
            messagebox.showerror("Invalid BSSID", "Please enter a valid BSSID (MAC address).")
            return
        if client and not self.is_valid_mac(client):
            messagebox.showerror("Invalid Client MAC", "Please enter a valid Client MAC address.")
            return

        self.core.execute_deauth_attack(interface, bssid, client)
        messagebox.showinfo("Attack Started", "Deauthentication attack has been started.")

    def stop_attack(self):
        self.core.stop_all_deauth_attacks()
        messagebox.showinfo("Attack Stopped", "All deauthentication attacks have been stopped.")

    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        import re
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac))
