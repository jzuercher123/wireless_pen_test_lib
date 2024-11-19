# ui/frames/network_map_frame.py

"""
NetworkMapFrame Module

This module defines the NetworkMapFrame class, a subclass of BaseFrame, which provides
graphical representations of discovered networks, devices, and their interconnections.
It utilizes NetworkX for graph management and Matplotlib for visualization, embedded within
a Tkinter GUI.

**⚠️ Important Note:**
Creating rogue access points and performing network penetration testing should only be done
with explicit permission on networks you own or have authorization to test. Unauthorized
access to networks is illegal and unethical.
"""

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from typing import Optional, Dict, Any

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from ui.frames.base_frame import BaseFrame  # Assuming BaseFrame is in ui/base_frame.py


class NetworkMapFrame(BaseFrame):
    """
    Frame for visualizing network topology, including networks, devices, and their interconnections.

    Attributes:
        graph (nx.Graph): NetworkX graph representing the network topology.
        figure (Figure): Matplotlib figure for plotting the graph.
        canvas (FigureCanvasTkAgg): Canvas widget to embed the Matplotlib figure into Tkinter.
    """

    def __init__(self, parent, **kwargs):
        """
        Initializes the NetworkMapFrame.

        Args:
            parent (ttk.Notebook): The parent Notebook widget to attach the frame.
            core_framework (Any): Instance of CoreFramework for accessing network data.
            **kwargs: Additional keyword arguments for the BaseFrame.
        """
        super().__init__(parent, **kwargs)
        self.parent = parent


        # Initialize the NetworkX graph
        self.graph: nx.Graph = nx.Graph()

        # Set up the GUI components
        self.create_widgets()

        # Initial load of network data
        self.load_network_data()

    def create_widgets(self):
        """
        Creates and arranges all GUI components within the NetworkMapFrame.
        """
        # Frame for controls (e.g., Refresh Button)
        controls_frame = ttk.Frame(self)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)

        # Refresh Button
        refresh_button = ttk.Button(controls_frame, text="Refresh Network Map", command=self.refresh_network_map)
        refresh_button.pack(side=tk.LEFT, padx=5)

        # Instructions Label
        instructions = ttk.Label(controls_frame, text="Click on a node to view details.")
        instructions.pack(side=tk.LEFT, padx=10)

        # Frame for the network graph
        graph_frame = ttk.Frame(self)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Initialize Matplotlib Figure
        self.figure: Figure = Figure(figsize=(8, 6), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.axis('off')  # Hide axes

        # Create a canvas to embed the Matplotlib figure
        self.canvas: FigureCanvasTkAgg = FigureCanvasTkAgg(self.figure, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Bind click event to the canvas
        self.canvas.mpl_connect("button_press_event", self.on_click)

    def load_network_data(self):
        """
        Loads network data from the CoreFramework and updates the graph visualization.
        """
        try:
            # Fetch network data from CoreFramework
            network_data = self.core_framework.get_network_data()  # Method to retrieve network info
            self.update_graph(network_data)
        except Exception as e:
            messagebox.showerror("Data Load Error", f"Failed to load network data: {e}")

    def refresh_network_map(self):
        """
        Refreshes the network map by reloading network data and updating the visualization.
        """
        self.load_network_data()

    def update_graph(self, network_data: Dict[str, Any]):
        """
        Updates the NetworkX graph based on the provided network data.

        Args:
            network_data (Dict[str, Any]): Dictionary containing network and device information.
        """
        # Clear the existing graph
        self.graph.clear()

        # Example structure of network_data:
        # {
        #     "networks": [
        #         {
        #             "SSID": "Network1",
        #             "BSSID": "00:11:22:33:44:55",
        #             "Devices": [
        #                 {"MAC": "AA:BB:CC:DD:EE:FF", "IP": "192.168.1.2", "Hostname": "Device1"},
        #                 ...
        #             ]
        #         },
        #         ...
        #     ]
        # }

        networks = network_data.get("networks", [])
        for network in networks:
            ssid = network.get("SSID")
            bssid = network.get("BSSID")
            if ssid and bssid:
                # Add network node
                self.graph.add_node(bssid, label=ssid, type='network')

                devices = network.get("Devices", [])
                for device in devices:
                    mac = device.get("MAC")
                    ip = device.get("IP")
                    hostname = device.get("Hostname", "Unknown")
                    if mac:
                        # Add device node
                        self.graph.add_node(mac, label=f"{hostname}\n{ip}", type='device')
                        # Connect device to network
                        self.graph.add_edge(bssid, mac)

        # Draw the updated graph
        self.draw_graph()

    def draw_graph(self):
        """
        Draws the NetworkX graph on the Matplotlib figure.
        """
        self.ax.clear()
        self.ax.axis('off')  # Hide axes

        # Define node colors based on type
        node_colors = []
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'network':
                node_colors.append('lightblue')
            elif data.get('type') == 'device':
                node_colors.append('lightgreen')
            else:
                node_colors.append('gray')

        # Define node sizes
        node_sizes = [800 if data.get('type') == 'network' else 500 for node, data in self.graph.nodes(data=True)]

        # Define labels
        labels = {node: data.get('label', node) for node, data in self.graph.nodes(data=True)}

        # Compute layout
        pos = nx.spring_layout(self.graph, k=0.5, iterations=50)

        # Draw nodes
        nx.draw_networkx_nodes(self.graph, pos, node_size=node_sizes, node_color=node_colors, ax=self.ax)

        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, ax=self.ax)

        # Draw labels
        nx.draw_networkx_labels(self.graph, pos, labels, font_size=8, ax=self.ax)

        # Refresh the canvas
        self.canvas.draw()

    def on_click(self, event):
        """
        Handles click events on the network graph.

        Args:
            event: Matplotlib event object containing event information.
        """
        # Check if the click was on a node
        if event.inaxes == self.ax:
            # Get the closest node to the click
            x_click, y_click = event.xdata, event.ydata
            closest_node = self.get_closest_node(x_click, y_click)
            if closest_node:
                self.show_node_details(closest_node)

    def get_closest_node(self, x: float, y: float) -> Optional[str]:
        """
        Finds the closest node in the graph to the given x and y coordinates.

        Args:
            x (float): X-coordinate of the click.
            y (float): Y-coordinate of the click.

        Returns:
            Optional[str]: The node identifier if a close node is found, else None.
        """
        threshold = 0.05  # Distance threshold for selecting a node
        closest_node = None
        min_distance = float('inf')

        for node, data in self.graph.nodes(data=True):
            pos = self.graph.nodes[node].get('pos', None)
            if pos is None:
                continue
            dx = x - pos[0]
            dy = y - pos[1]
            distance = dx**2 + dy**2
            if distance < min_distance and distance < threshold**2:
                min_distance = distance
                closest_node = node

        return closest_node

    def show_node_details(self, node: str):
        """
        Displays a popup window with details about the selected node.

        Args:
            node (str): The node identifier.
        """
        node_data = self.graph.nodes[node]
        label = node_data.get('label', 'N/A')
        node_type = node_data.get('type', 'Unknown')

        # Fetch additional details if available
        details = ""
        if node_type == 'network':
            details += f"Network SSID: {label}\n"
            details += f"BSSID: {node}\n"
            # Add more network-specific details if available
        elif node_type == 'device':
            details += f"Device Name: {label.splitlines()[0]}\n"
            details += f"IP Address: {label.splitlines()[1] if len(label.splitlines()) > 1 else 'N/A'}\n"
            details += f"MAC Address: {node}\n"
            # Add more device-specific details if available

        # Create a popup window
        popup = tk.Toplevel(self)
        popup.title(f"Details for {node}")
        popup.geometry("300x200")
        ttk.Label(popup, text=f"Node: {node}", font=("Helvetica", 12, "bold")).pack(pady=10)
        ttk.Label(popup, text=details, justify='left').pack(padx=10, pady=10)
        ttk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)

        # Make the popup modal
        popup.transient(self)
        popup.grab_set()
        self.wait_window(popup)


# ui/base_frame.py

"""
BaseFrame Module

This module defines the BaseFrame class, a subclass of ttk.Frame, which serves as a base
for all other frames in the WirelessPenTestLib GUI. It provides common functionalities
and a consistent structure for derived frames.

**⚠️ Important Note:**
Creating rogue access points and performing network penetration testing should only be done
with explicit permission on networks you own or have authorization to test. Unauthorized
access to networks is illegal and unethical.
"""

import tkinter as tk
from tkinter import ttk
from typing import Any


class BaseFrame(ttk.Frame):
    """
    BaseFrame class serving as the parent for all other frames in the GUI.

    Attributes:
        parent (ttk.Widget): The parent widget.
    """

    def __init__(self, parent: ttk.Widget, *args, **kwargs):
        """
        Initializes the BaseFrame.

        Args:
            parent (ttk.Widget): The parent widget.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        """
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
