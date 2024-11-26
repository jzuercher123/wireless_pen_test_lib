import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import StringVar, Text, Scrollbar, END, VERTICAL, HORIZONTAL, N, S, E, W

import threading
import time
import subprocess
import re
import os
import sys
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether


# Assuming BaseFrame is a subclass of ttk.Frame
class BaseFrame(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)


class FakeAccessPoint(BaseFrame):
    """
    Frame for creating and managing a fake (rogue) access point and monitoring connected devices.
    """
    def __init__(self, parent):
        """
        Initializes the FakeAccessPoint.
        """
        super().__init__(parent)
        self.parent = parent
        self.pack(fill=tk.BOTH, expand=True)

        # Initialize variables
        self.ap_running = False
        self.monitor_thread = None
        self.scan_thread = None
        self.stop_event = threading.Event()

        # Path to hostapd and dnsmasq configuration files
        self.hostapd_conf_path = "/tmp/hostapd.conf"
        self.dnsmasq_conf_path = "/tmp/dnsmasq.conf"

        # Wireless interface (default)
        self.interface = "wlan0"

        # List to store connected devices
        self.connected_devices = []

        # Create GUI components
        self.create_widgets()

    def create_widgets(self):
        """
        Creates and arranges all GUI components.
        """
        # Configuration Frame
        config_frame = ttk.LabelFrame(self, text="Access Point Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)

        # SSID
        ttk.Label(config_frame, text="SSID:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.ssid_var = StringVar()
        self.ssid_entry = ttk.Entry(config_frame, textvariable=self.ssid_var)
        self.ssid_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.ssid_entry.insert(0, "TestAP")

        # Channel
        ttk.Label(config_frame, text="Channel:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.channel_var = StringVar()
        self.channel_entry = ttk.Entry(config_frame, textvariable=self.channel_var)
        self.channel_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.channel_entry.insert(0, "6")

        # Interface
        ttk.Label(config_frame, text="Interface:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.interface_var = StringVar()
        self.interface_entry = ttk.Entry(config_frame, textvariable=self.interface_var)
        self.interface_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.interface_entry.insert(0, self.interface)

        # Security
        ttk.Label(config_frame, text="Security:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.security_var = StringVar()
        self.security_combo = ttk.Combobox(config_frame, textvariable=self.security_var, state="readonly")
        self.security_combo['values'] = ("Open", "WPA/WPA2")
        self.security_combo.current(0)
        self.security_combo.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        self.security_combo.bind("<<ComboboxSelected>>", self.toggle_password)

        # Password
        ttk.Label(config_frame, text="Password:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.password_var = StringVar()
        self.password_entry = ttk.Entry(config_frame, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        self.password_entry.configure(state='disabled')

        # Buttons Frame
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)

        # Start AP Button
        self.start_ap_button = ttk.Button(buttons_frame, text="Start AP", command=self.start_ap)
        self.start_ap_button.pack(side=tk.LEFT, padx=5)

        # Stop AP Button
        self.stop_ap_button = ttk.Button(buttons_frame, text="Stop AP", command=self.stop_ap, state=tk.DISABLED)
        self.stop_ap_button.pack(side=tk.LEFT, padx=5)

        # Refresh Devices Button
        self.refresh_button = ttk.Button(buttons_frame, text="Refresh Devices", command=self.refresh_devices, state=tk.DISABLED)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        # Devices Frame
        devices_frame = ttk.LabelFrame(self, text="Connected Devices")
        devices_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Treeview for devices
        columns = ("MAC Address", "IP Address", "Signal Strength")
        self.devices_tree = ttk.Treeview(devices_frame, columns=columns, show="headings")
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, anchor=tk.W, stretch=True)
        self.devices_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Scrollbar for Treeview
        devices_vsb = ttk.Scrollbar(devices_frame, orient=VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscroll=devices_vsb.set)
        devices_vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def toggle_password(self, event):
        """
        Enables or disables the password entry based on selected security.
        """
        if self.security_var.get() == "WPA/WPA2":
            self.password_entry.configure(state='normal')
        else:
            self.password_entry.configure(state='disabled')
            self.password_var.set("")

    def start_ap(self):
        """
        Starts the rogue access point.
        """
        ssid = self.ssid_var.get().strip()
        channel = self.channel_var.get().strip()
        interface = self.interface_var.get().strip()
        security = self.security_var.get().strip()
        password = self.password_var.get().strip()

        # Validate inputs
        if not ssid:
            messagebox.showerror("Input Error", "SSID is required.")
            return
        if not channel.isdigit() or not (1 <= int(channel) <= 14):
            messagebox.showerror("Input Error", "Channel must be a number between 1 and 14.")
            return
        if not self.validate_interface(interface):
            messagebox.showerror("Input Error", f"Interface '{interface}' is not valid or not up.")
            return
        if security == "WPA/WPA2" and not password:
            messagebox.showerror("Input Error", "Password is required for WPA/WPA2 security.")
            return
        if security == "WPA/WPA2" and len(password) < 8:
            messagebox.showerror("Input Error", "Password must be at least 8 characters long.")
            return

        # Generate hostapd configuration
        try:
            self.generate_hostapd_conf(ssid, channel, interface, security, password)
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to generate hostapd configuration:\n{e}")
            return

        # Start hostapd
        try:
            self.hostapd_process = subprocess.Popen(['hostapd', self.hostapd_conf_path],
                                                    stdout=subprocess.PIPE,
                                                    stderr=subprocess.PIPE)
        except FileNotFoundError:
            messagebox.showerror("hostapd Not Found", "hostapd is not installed or not found in PATH.")
            return
        except Exception as e:
            messagebox.showerror("hostapd Error", f"Failed to start hostapd:\n{e}")
            return

        # Start dnsmasq for DHCP (optional)
        try:
            self.generate_dnsmasq_conf(interface)
            self.dnsmasq_process = subprocess.Popen(['dnsmasq', '-C', self.dnsmasq_conf_path, '-d'],
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE)
        except FileNotFoundError:
            messagebox.showerror("dnsmasq Not Found", "dnsmasq is not installed or not found in PATH.")
            self.hostapd_process.terminate()
            return
        except Exception as e:
            messagebox.showerror("dnsmasq Error", f"Failed to start dnsmasq:\n{e}")
            self.hostapd_process.terminate()
            return

        self.ap_running = True
        self.start_ap_button.config(state=tk.DISABLED)
        self.stop_ap_button.config(state=tk.NORMAL)
        self.refresh_button.config(state=tk.NORMAL)

        # Start monitoring connected devices
        self.monitor_thread = threading.Thread(target=self.monitor_devices, daemon=True)
        self.monitor_thread.start()

        messagebox.showinfo("AP Started", f"Rogue Access Point '{ssid}' has been started on channel {channel}.")

    def stop_ap(self):
        """
        Stops the rogue access point.
        """
        if self.ap_running:
            # Terminate hostapd
            self.hostapd_process.terminate()
            self.hostapd_process.wait()

            # Terminate dnsmasq
            self.dnsmasq_process.terminate()
            self.dnsmasq_process.wait()

            # Remove temporary configuration files
            try:
                os.remove(self.hostapd_conf_path)
                os.remove(self.dnsmasq_conf_path)
            except Exception:
                pass

            # Stop device monitoring
            self.ap_running = False
            self.stop_event.set()
            if self.monitor_thread.is_alive():
                self.monitor_thread.join()

            # Clear devices list
            self.connected_devices.clear()
            self.devices_tree.delete(*self.devices_tree.get_children())

            self.start_ap_button.config(state=tk.NORMAL)
            self.stop_ap_button.config(state=tk.DISABLED)
            self.refresh_button.config(state=tk.DISABLED)

            messagebox.showinfo("AP Stopped", "Rogue Access Point has been stopped.")
        else:
            messagebox.showwarning("Not Running", "Access Point is not running.")

    def generate_hostapd_conf(self, ssid, channel, interface, security, password):
        """
        Generates the hostapd configuration file.
        """
        # Base configuration
        config = f"""
    interface={interface}
    driver=nl80211
    ssid={ssid}
    channel={channel}
    hw_mode=g
    ieee80211n=1
    wmm_enabled=1
        """

        # Add security configuration
        if security == "WPA/WPA2":
            config += f"""
    wpa=2
    wpa_passphrase={password}
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
            """
        else:
            config += """
    auth_algs=1
            """

        # Write the configuration to the file
        with open(self.hostapd_conf_path, 'w') as f:
            f.write(config)

    def generate_dnsmasq_conf(self, interface):
        """
        Generates the dnsmasq configuration file for DHCP services.
        """
        config = f"""
            interface={interface}
            dhcp-range=192.168.10.10,192.168.10.50,12h
            dhcp-option=3,192.168.10.1
            dhcp-option=6,192.168.10.1
            server=8.8.8.8
            log-queries
            log-dhcp
        """

        with open(self.dnsmasq_conf_path, 'w') as f:
            f.write(config)

    def validate_interface(self, interface):
        """
        Validates if the wireless interface exists and is up.
        """
        try:
            output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT).decode()
            if "no wireless extensions" in output.lower():
                return False
            return True
        except subprocess.CalledProcessError:
            return False

    def monitor_devices(self):
        """
        Monitors connected devices by periodically scanning the network.
        """
        while self.ap_running and not self.stop_event.is_set():
            devices = self.scan_connected_devices()
            self.update_device_list(devices)
            time.sleep(5)  # Adjust the scan interval as needed

    def scan_connected_devices(self):
        """
        Scans the network for connected devices using ARP.
        """
        # Assuming the AP is on 192.168.10.0/24
        target_ip = "192.168.10.0/24"

        # Construct ARP request
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'mac': received.hwsrc, 'ip': received.psrc, 'signal': "N/A"})  # Signal strength can be added if available

        return devices

    def update_device_list(self, devices):
        """
        Updates the Treeview with the list of connected devices.
        """
        # Clear existing entries
        self.devices_tree.delete(*self.devices_tree.get_children())

        for device in devices:
            self.devices_tree.insert("", "end", values=(
                device['mac'],
                device['ip'],
                device['signal']
            ))

    def refresh_devices(self):
        """
        Manually refreshes the list of connected devices.
        """
        if self.ap_running:
            devices = self.scan_connected_devices()
            self.update_device_list(devices)
        else:
            messagebox.showwarning("AP Not Running", "Access Point is not running.")

    def save_devices(self):
        """
        Saves the list of connected devices to a file.
        """
        if not self.connected_devices:
            messagebox.showwarning("No Devices", "There are no connected devices to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    for device in self.connected_devices:
                        f.write(f"MAC Address: {device['mac']}\n")
                        f.write(f"IP Address: {device['ip']}\n")
                        f.write(f"Signal Strength: {device['signal']}\n")
                        f.write("\n")
                messagebox.showinfo("Success", f"Connected devices saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save devices:\n{e}")

    # Additional methods like view_device_info, export_device_info can be implemented here if needed


# Example usage within a Tkinter application
def main():
    root = tk.Tk()
    root.title("Network Testing Tool")
    root.geometry("800x600")

    # Create a Notebook (tabbed interface)
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Add FakeAccessPoint tab
    fake_access_point = FakeAccessPoint(notebook)
    notebook.add(fake_access_point, text="Fake Access Point")

    root.mainloop()


if __name__ == "__main__":
    if os.geteuid() != 0:
        messagebox.showerror("Permission Denied", "Please run this script with sudo or as root.")
        sys.exit(1)
    main()
