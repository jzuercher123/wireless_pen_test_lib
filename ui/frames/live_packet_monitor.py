import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import StringVar, Text, Scrollbar, END, VERTICAL, HORIZONTAL, N, S, E, W

from scapy.all import sniff, wrpcap, rdpcap, Packet
from scapy.layers.l2 import Ether
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
import threading
import time
import queue
import os


# Assuming BaseFrame is a subclass of ttk.Frame
class BaseFrame(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)


class LivePacketMonitor(BaseFrame):
    """
    Wireshark-like live packet monitoring frame
    """
    def __init__(self, parent):
        """
        Initializes the LivePacketMonitor.
        """
        super().__init__(parent)
        self.parent = parent
        self.pack(fill=tk.BOTH, expand=True)

        # Initialize variables
        self.packet_list = []
        self.sniffing = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()

        # Create GUI components
        self.create_widgets()

        # Start a periodic GUI update
        self.parent.after(100, self.process_packet_queue)

    def create_widgets(self):
        """
        Creates and arranges all GUI components.
        """
        # Top Frame for buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        # Start Button
        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Stop Button
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Save Button
        self.save_button = ttk.Button(button_frame, text="Save", command=self.save_packets)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Load Button
        self.load_button = ttk.Button(button_frame, text="Load", command=self.load_packets)
        self.load_button.pack(side=tk.LEFT, padx=5)

        # Clear Button
        self.clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Filter Entry and Button
        self.filter_var = StringVar()
        self.filter_entry = ttk.Entry(button_frame, textvariable=self.filter_var)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.insert(0, "Filter (e.g., tcp, udp)")

        self.filter_button = ttk.Button(button_frame, text="Apply Filter", command=self.filter_packets)
        self.filter_button.pack(side=tk.LEFT, padx=5)

        # Treeview for packet list
        columns = ("No.", "Time", "Source", "Destination", "Protocol")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.W, stretch=True)

        # Vertical Scrollbar
        vsb = ttk.Scrollbar(self, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Horizontal Scrollbar
        hsb = ttk.Scrollbar(self, orient=HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscroll=hsb.set)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Bind selection
        self.tree.bind("<<TreeviewSelect>>", self.view_packet)

        # Text widget for packet details
        detail_frame = ttk.Frame(self)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        detail_label = ttk.Label(detail_frame, text="Packet Details:")
        detail_label.pack(anchor=tk.W)

        self.detail_text = Text(detail_frame, height=15, wrap=tk.NONE)
        self.detail_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Scrollbars for detail_text
        detail_vsb = Scrollbar(detail_frame, orient=VERTICAL, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_vsb.set)
        detail_vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def update_gui(self, packet_info):
        """
        Updates the GUI with the given data.
        Args:
            packet_info (Dict[str, Any]): The data to update the GUI with.
        """
        self.packet_list.append(packet_info)
        index = len(self.packet_list)
        self.tree.insert("", "end", iid=index, values=(
            index,
            packet_info['time'],
            packet_info['source'],
            packet_info['destination'],
            packet_info['protocol']
        ))

    def clear_gui(self):
        """
        Clears the GUI components.
        """
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail_text.delete(1.0, END)
        self.packet_list.clear()

    def start_sniffing(self):
        """
        Starts sniffing packets.
        """
        if not self.sniffing:
            self.sniffing = True
            self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffer_thread.start()
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            messagebox.showinfo("Sniffing Started", "Packet sniffing has started.")
        else:
            messagebox.showwarning("Warning", "Sniffing is already running.")

    def stop_sniffing(self):
        """
        Stops sniffing packets.
        """
        if self.sniffing:
            self.sniffing = False
            self.sniffer_thread.join()
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            messagebox.showinfo("Sniffing Stopped", "Packet sniffing has stopped.")
        else:
            messagebox.showwarning("Warning", "Sniffing is not running.")

    def sniff_packets(self):
        """
        Sniffs packets using Scapy and puts them into a queue for the GUI to process.
        """
        try:
            sniff(prn=self.packet_handler, store=False, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while sniffing packets:\n{e}")
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def packet_handler(self, pkt):
        """
        Handles packets captured by the sniffer.
        Args:
            pkt: The packet captured by the sniffer.
        """
        # Extract relevant information
        pkt_time = time.strftime("%H:%M:%S", time.localtime(pkt.time))
        src = "N/A"
        dst = "N/A"
        protocol = pkt.summary()

        if Ether in pkt:
            src = pkt[Ether].src
            dst = pkt[Ether].dst

        # Attempt to extract and decode payload
        payload = b""
        decoded_payload = "No Decodable Payload"

        # Check for Raw layer which contains the payload
        if pkt.haslayer("Raw"):
            payload = pkt.getlayer("Raw").load
            try:
                decoded_payload = payload.decode('utf-8', errors='replace')
            except Exception as e:
                decoded_payload = "Payload could not be decoded."

        # You can extend this to extract more details as needed

        packet_info = {
            'time': pkt_time,
            'source': src,
            'destination': dst,
            'protocol': protocol,
            'packet': pkt,  # Store the entire packet for detailed view
            'payload': payload,  # Raw payload
            'decoded_payload': decoded_payload  # Decoded payload
        }

        # Put the packet_info into the queue
        self.packet_queue.put(packet_info)

    def process_packet_queue(self):
        """
        Processes the packet queue and updates the GUI accordingly.
        """
        try:
            while True:
                packet_info = self.packet_queue.get_nowait()
                self.update_gui(packet_info)
        except queue.Empty:
            pass
        finally:
            # Schedule the next check
            self.parent.after(100, self.process_packet_queue)

    def save_packets(self):
        """
        Saves the captured packets to a file.
        """
        if not self.packet_list:
            messagebox.showwarning("No Packets", "There are no packets to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if file_path:
            try:
                packets = [pkt_info['packet'] for pkt_info in self.packet_list]
                wrpcap(file_path, packets)
                messagebox.showinfo("Success", f"Packets saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save packets:\n{e}")

    def load_packets(self):
        """
        Loads packets from a file.
        """
        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if file_path:
            try:
                loaded_packets = rdpcap(file_path)
                self.clear_packets()
                for pkt in loaded_packets:
                    pkt_time = time.strftime("%H:%M:%S", time.localtime(pkt.time))
                    src = "N/A"
                    dst = "N/A"
                    protocol = pkt.summary()

                    if Ether in pkt:
                        src = pkt[Ether].src
                        dst = pkt[Ether].dst

                    # Attempt to extract and decode payload
                    payload = b""
                    decoded_payload = "No Decodable Payload"

                    if pkt.haslayer("Raw"):
                        payload = pkt.getlayer("Raw").load
                        try:
                            decoded_payload = payload.decode('utf-8', errors='replace')
                        except Exception as e:
                            decoded_payload = "Payload could not be decoded."

                    packet_info = {
                        'time': pkt_time,
                        'source': src,
                        'destination': dst,
                        'protocol': protocol,
                        'packet': pkt,
                        'payload': payload,
                        'decoded_payload': decoded_payload
                    }

                    self.update_gui(packet_info)
                messagebox.showinfo("Success", f"Loaded {len(loaded_packets)} packets from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load packets:\n{e}")

    def clear_packets(self):
        """
        Clears the captured packets.
        """
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all captured packets?"):
            self.clear_gui()

    def filter_packets(self):
        """
        Filters the captured packets based on user input.
        """
        filter_text = self.filter_var.get().strip().lower()
        if not filter_text:
            # If no filter, show all packets
            for item in self.tree.get_children():
                self.tree.delete(item)
            for index, pkt_info in enumerate(self.packet_list, start=1):
                self.tree.insert("", "end", iid=index, values=(
                    index,
                    pkt_info['time'],
                    pkt_info['source'],
                    pkt_info['destination'],
                    pkt_info['protocol']
                ))
            return

        # Filter packets
        filtered_packets = []
        for pkt_info in self.packet_list:
            if filter_text in pkt_info['protocol'].lower():
                filtered_packets.append(pkt_info)

        # Update Treeview
        self.tree.delete(*self.tree.get_children())
        for index, pkt_info in enumerate(filtered_packets, start=1):
            self.tree.insert("", "end", iid=index, values=(
                index,
                pkt_info['time'],
                pkt_info['source'],
                pkt_info['destination'],
                pkt_info['protocol']
            ))

    def view_packet(self, event):
        """
        Views the details of a selected packet.
        """
        selected_items = self.tree.selection()
        if not selected_items:
            return

        selected_item = selected_items[0]
        index = int(selected_item) - 1
        if index < 0 or index >= len(self.packet_list):
            messagebox.showerror("Error", "Invalid packet selection.")
            return

        pkt_info = self.packet_list[index]
        pkt = pkt_info['packet']

        # Create a new window to display packet details
        detail_window = tk.Toplevel(self)
        detail_window.title(f"Packet #{index + 1} Details")
        detail_window.geometry("800x700")  # Increased height for payload

        # Create Notebook for organized tabs
        notebook = ttk.Notebook(detail_window)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Frame for Packet Summary
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="Summary")

        # Text widget for Packet Summary
        summary_text = Text(summary_frame, height=15, wrap=tk.NONE)
        summary_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Scrollbars for summary_text
        summary_vsb = Scrollbar(summary_frame, orient=VERTICAL, command=summary_text.yview)
        summary_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        summary_text.configure(yscrollcommand=summary_vsb.set)

        summary_hsb = Scrollbar(summary_frame, orient=HORIZONTAL, command=summary_text.xview)
        summary_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        summary_text.configure(xscrollcommand=summary_hsb.set)

        # Insert packet summary
        packet_summary = pkt.show(dump=True)
        summary_text.insert(END, packet_summary)
        summary_text.config(state=tk.DISABLED)

        # Frame for Decoded Payload
        payload_frame = ttk.Frame(notebook)
        notebook.add(payload_frame, text="Decoded Payload")

        # Text widget for Decoded Payload
        payload_text = Text(payload_frame, height=15, wrap=tk.NONE)
        payload_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Scrollbars for payload_text
        payload_vsb = Scrollbar(payload_frame, orient=VERTICAL, command=payload_text.yview)
        payload_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        payload_text.configure(yscrollcommand=payload_vsb.set)

        payload_hsb = Scrollbar(payload_frame, orient=HORIZONTAL, command=payload_text.xview)
        payload_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        payload_text.configure(xscrollcommand=payload_hsb.set)

        # Insert decoded payload
        decoded_payload = pkt_info.get('decoded_payload', "No Decodable Payload")
        payload_text.insert(END, decoded_payload)
        payload_text.config(state=tk.DISABLED)

    def export_packet(self):
        """
        Exports the details of a selected packet.
        """
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a packet to export.")
            return

        selected_item = selected_items[0]
        index = int(selected_item) - 1
        if index < 0 or index >= len(self.packet_list):
            messagebox.showerror("Error", "Invalid packet selection.")
            return

        pkt = self.packet_list[index]['packet']

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(pkt.show(dump=True))
                messagebox.showinfo("Success", f"Packet details exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export packet:\n{e}")

    def import_packet(self):
        """
        Imports a packet from a file.
        """
        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )

        if file_path:
            try:
                imported_packets = rdpcap(file_path)
                self.clear_packets()
                for pkt in imported_packets:
                    pkt_time = time.strftime("%H:%M:%S", time.localtime(pkt.time))
                    src = "N/A"
                    dst = "N/A"
                    protocol = pkt.summary()

                    if Ether in pkt:
                        src = pkt[Ether].src
                        dst = pkt[Ether].dst

                    # Attempt to extract and decode payload
                    payload = b""
                    decoded_payload = "No Decodable Payload"

                    if pkt.haslayer("Raw"):
                        payload = pkt.getlayer("Raw").load
                        try:
                            decoded_payload = payload.decode('utf-8', errors='replace')
                        except Exception as e:
                            decoded_payload = "Payload could not be decoded."

                    packet_info = {
                        'time': pkt_time,
                        'source': src,
                        'destination': dst,
                        'protocol': protocol,
                        'packet': pkt,
                        'payload': payload,
                        'decoded_payload': decoded_payload
                    }

                    self.update_gui(packet_info)
                messagebox.showinfo("Success", f"Imported {len(imported_packets)} packets from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load packets:\n{e}")


# Example usage within a Tkinter application
def main():
    root = tk.Tk()
    root.title("Live Packet Monitor")
    root.geometry("1000x700")

    app = LivePacketMonitor(root)

    root.mainloop()


if __name__ == "__main__":
    main()
S