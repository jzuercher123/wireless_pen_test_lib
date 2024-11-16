import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import StringVar, Text, Scrollbar, END, VERTICAL, HORIZONTAL, N, S, E, W

from scapy.all import send
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import threading
import time
import queue
import re


# Assuming BaseFrame is a subclass of ttk.Frame
class BaseFrame(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)


class FakeDeviceManager(BaseFrame):
    """
    Frame for creating and managing fake test devices for network testing purposes.
    """
    def __init__(self, parent):
        """
        Initializes the FakeDeviceManager.
        """
        super().__init__(parent)
        self.parent = parent
        self.pack(fill=tk.BOTH, expand=True)

        # Initialize variables
        self.fake_devices = {}
        self.device_queue = queue.Queue()

        # Create GUI components
        self.create_widgets()

    def create_widgets(self):
        """
        Creates and arranges all GUI components.
        """
        # Input Frame
        input_frame = ttk.LabelFrame(self, text="Create Fake Device")
        input_frame.pack(fill=tk.X, padx=10, pady=5)

        # Device Name
        ttk.Label(input_frame, text="Device Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.device_name_var = StringVar()
        self.device_name_entry = ttk.Entry(input_frame, textvariable=self.device_name_var)
        self.device_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # MAC Address
        ttk.Label(input_frame, text="MAC Address:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.mac_address_var = StringVar()
        self.mac_address_entry = ttk.Entry(input_frame, textvariable=self.mac_address_var)
        self.mac_address_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.mac_address_entry.insert(0, "00:11:22:33:44:55")  # Default MAC

        # IP Address
        ttk.Label(input_frame, text="IP Address:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.ip_address_var = StringVar()
        self.ip_address_entry = ttk.Entry(input_frame, textvariable=self.ip_address_var)
        self.ip_address_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.ip_address_entry.insert(0, "192.168.1.100")  # Default IP

        # Protocol
        ttk.Label(input_frame, text="Protocol:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.protocol_var = StringVar()
        self.protocol_combo = ttk.Combobox(input_frame, textvariable=self.protocol_var, state="readonly")
        self.protocol_combo['values'] = ("TCP", "UDP", "ICMP")
        self.protocol_combo.current(0)
        self.protocol_combo.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        # Destination IP
        ttk.Label(input_frame, text="Destination IP:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.dest_ip_var = StringVar()
        self.dest_ip_entry = ttk.Entry(input_frame, textvariable=self.dest_ip_var)
        self.dest_ip_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        self.dest_ip_entry.insert(0, "192.168.1.1")  # Default Destination IP

        # Destination Port (for TCP/UDP)
        ttk.Label(input_frame, text="Destination Port:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.E)
        self.dest_port_var = StringVar()
        self.dest_port_entry = ttk.Entry(input_frame, textvariable=self.dest_port_var)
        self.dest_port_entry.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        self.dest_port_entry.insert(0, "80")  # Default Port

        # Create Device Button
        self.create_button = ttk.Button(input_frame, text="Add Device", command=self.add_fake_device)
        self.create_button.grid(row=6, column=0, columnspan=2, pady=10)

        # Separator
        separator = ttk.Separator(self, orient='horizontal')
        separator.pack(fill=tk.X, padx=10, pady=10)

        # Devices Frame
        devices_frame = ttk.LabelFrame(self, text="Fake Devices")
        devices_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Treeview for devices
        columns = ("Device Name", "MAC Address", "IP Address", "Protocol", "Destination IP", "Destination Port", "Status")
        self.devices_tree = ttk.Treeview(devices_frame, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, anchor=tk.W, stretch=True)
        self.devices_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Scrollbars for Treeview
        devices_vsb = ttk.Scrollbar(devices_frame, orient=VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscroll=devices_vsb.set)
        devices_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Buttons Frame
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(fill=tk.X, padx=10, pady=5)

        # Start Emulation Button
        self.start_emulation_button = ttk.Button(buttons_frame, text="Start Emulation", command=self.start_emulation)
        self.start_emulation_button.pack(side=tk.LEFT, padx=5)

        # Stop Emulation Button
        self.stop_emulation_button = ttk.Button(buttons_frame, text="Stop Emulation", command=self.stop_emulation, state=tk.DISABLED)
        self.stop_emulation_button.pack(side=tk.LEFT, padx=5)

        # Remove Device Button
        self.remove_button = ttk.Button(buttons_frame, text="Remove Device", command=self.remove_fake_device)
        self.remove_button.pack(side=tk.LEFT, padx=5)

    def validate_mac(self, mac):
        """
        Validates MAC address format.
        """
        if re.match("[0-9a-fA-F]{2}([-:])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}$", mac):
            return True
        return False

    def validate_ip(self, ip):
        """
        Validates IP address format.
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for item in parts:
            if not item.isdigit():
                return False
            num = int(item)
            if num < 0 or num > 255:
                return False
        return True

    def add_fake_device(self):
        """
        Adds a new fake device based on input fields.
        """
        device_name = self.device_name_var.get().strip()
        mac_address = self.mac_address_var.get().strip()
        ip_address = self.ip_address_var.get().strip()
        protocol = self.protocol_var.get().strip().upper()
        dest_ip = self.dest_ip_var.get().strip()
        dest_port = self.dest_port_var.get().strip()

        # Validate inputs
        if not device_name:
            messagebox.showerror("Input Error", "Device Name is required.")
            return

        if not self.validate_mac(mac_address):
            messagebox.showerror("Input Error", "Invalid MAC Address format.")
            return

        if not self.validate_ip(ip_address):
            messagebox.showerror("Input Error", "Invalid IP Address format.")
            return

        if protocol not in ("TCP", "UDP", "ICMP"):
            messagebox.showerror("Input Error", "Protocol must be TCP, UDP, or ICMP.")
            return

        if not self.validate_ip(dest_ip):
            messagebox.showerror("Input Error", "Invalid Destination IP Address format.")
            return

        if protocol in ("TCP", "UDP"):
            if not dest_port.isdigit() or not (0 < int(dest_port) < 65536):
                messagebox.showerror("Input Error", "Destination Port must be a number between 1 and 65535.")
                return
            dest_port = int(dest_port)
        else:
            dest_port = "N/A"

        if device_name in self.fake_devices:
            messagebox.showerror("Duplicate Device", "A device with this name already exists.")
            return

        # Add device to Treeview
        status = "Stopped"
        self.devices_tree.insert("", "end", iid=device_name, values=(
            device_name,
            mac_address,
            ip_address,
            protocol,
            dest_ip,
            dest_port,
            status
        ))

        # Store device information
        self.fake_devices[device_name] = {
            'mac': mac_address,
            'ip': ip_address,
            'protocol': protocol,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'status': status,
            'thread': None,
            'stop_event': None
        }

        # Clear input fields
        self.device_name_var.set("")
        self.mac_address_var.set("00:11:22:33:44:55")
        self.ip_address_var.set("192.168.1.100")
        self.protocol_combo.current(0)
        self.dest_ip_var.set("192.168.1.1")
        self.dest_port_var.set("80")

    def remove_fake_device(self):
        """
        Removes the selected fake device.
        """
        selected = self.devices_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to remove.")
            return

        device_name = selected[0]
        device_info = self.fake_devices.get(device_name)

        if device_info and device_info['status'] == "Running":
            messagebox.showwarning("Device Running", "Stop the device before removing it.")
            return

        # Remove from Treeview and dictionary
        self.devices_tree.delete(device_name)
        del self.fake_devices[device_name]

    def start_emulation(self):
        """
        Starts packet emulation for the selected fake device.
        """
        selected = self.devices_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to start emulation.")
            return

        device_name = selected[0]
        device_info = self.fake_devices.get(device_name)

        if device_info['status'] == "Running":
            messagebox.showwarning("Already Running", "Emulation is already running for this device.")
            return

        # Create a stop event
        stop_event = threading.Event()
        device_info['stop_event'] = stop_event

        # Start the emulation thread
        emulation_thread = threading.Thread(target=self.emulate_device, args=(device_name, stop_event), daemon=True)
        device_info['thread'] = emulation_thread
        emulation_thread.start()

        # Update status
        device_info['status'] = "Running"
        self.devices_tree.set(device_name, "Status", "Running")

        # Enable Stop button
        self.stop_emulation_button.config(state=tk.NORMAL)

    def stop_emulation(self):
        """
        Stops packet emulation for the selected fake device.
        """
        selected = self.devices_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to stop emulation.")
            return

        device_name = selected[0]
        device_info = self.fake_devices.get(device_name)

        if device_info['status'] != "Running":
            messagebox.showwarning("Not Running", "Emulation is not running for this device.")
            return

        # Signal the thread to stop
        device_info['stop_event'].set()
        device_info['thread'].join()

        # Update status
        device_info['status'] = "Stopped"
        self.devices_tree.set(device_name, "Status", "Stopped")

        # Disable Stop button if no devices are running
        any_running = any(info['status'] == "Running" for info in self.fake_devices.values())
        if not any_running:
            self.stop_emulation_button.config(state=tk.DISABLED)

    def emulate_device(self, device_name, stop_event):
        """
        Sends crafted packets based on the device's configuration until stopped.
        """
        device_info = self.fake_devices.get(device_name)
        if not device_info:
            return

        mac = device_info['mac']
        ip = device_info['ip']
        protocol = device_info['protocol']
        dest_ip = device_info['dest_ip']
        dest_port = device_info['dest_port']

        while not stop_event.is_set():
            try:
                if protocol == "TCP":
                    pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=ip, dst=dest_ip) / TCP(dport=dest_port, flags="S")
                elif protocol == "UDP":
                    pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=ip, dst=dest_ip) / UDP(dport=dest_port)
                elif protocol == "ICMP":
                    pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=ip, dst=dest_ip) / ICMP()
                else:
                    continue  # Unsupported protocol

                send(pkt, verbose=False)
                time.sleep(1)  # Adjust the frequency as needed
            except Exception as e:
                messagebox.showerror("Emulation Error", f"Error in emulating device {device_name}:\n{e}")
                break

    # Additional methods can be implemented here if needed


# Example usage within a Tkinter application
def main():
    root = tk.Tk()
    root.title("Network Testing Tool")
    root.geometry("1200x800")

    # Create a Notebook (tabbed interface)
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)

    # Add LivePacketMonitor tab
    # Assuming LivePacketMonitor is implemented as per your previous code
    from tkinter import ttk  # Re-import in case it's needed
    class LivePacketMonitor(BaseFrame):
        """
        Placeholder for LivePacketMonitor implementation.
        Replace this with your actual implementation.
        """
        def __init__(self, parent):
            super().__init__(parent)
            label = ttk.Label(self, text="Live Packet Monitor - To Be Implemented")
            label.pack(padx=10, pady=10)

    live_packet_monitor = LivePacketMonitor(notebook)
    notebook.add(live_packet_monitor, text="Live Packet Monitor")

    # Add FakeDeviceManager tab
    fake_device_manager = FakeDeviceManager(notebook)
    notebook.add(fake_device_manager, text="Fake Device Manager")

    root.mainloop()


if __name__ == "__main__":
    main()
