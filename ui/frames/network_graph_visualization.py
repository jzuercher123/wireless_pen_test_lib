from tkinter import Tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from typing import Dict, Any
from core import CoreFramework
import logging

from ui.frames.base_frame import BaseFrame


class NetworkGraphVisualizationFrame(BaseFrame):
    def __init__(self, parent: Tk, core_framework: CoreFramework, *args, **kwargs):
        """
        Initializes the NetworkGraphVisualizationFrame.
        Args:
            parent (Tk): The parent Tkinter widget.
            core_framework (CoreFramework): An instance of CoreFramework.
        """
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.core_framework = core_framework
        self.pack(fill='both', expand=True)

        # Setup Logger
        self.logger = logging.getLogger(__name__)

        # Setup GUI Components
        self.create_widgets()

    def create_widgets(self):
        """
        Creates and arranges all GUI components.
        """
        self.figure = plt.Figure(figsize=(5, 5), dpi=100)
        self.subplot = self.figure.add_subplot(111)
        self.graph = FigureCanvasTkAgg(self.figure, self)
        self.graph.get_tk_widget().pack(side='top', fill='both', expand=True)

    def update_gui(self, data: Dict[str, Any]):
        """
        Updates the GUI with the given data.
        Args:
            data (Dict[str, Any]): The data to update the GUI with.
        """
        self.logger.info("Updating the GUI with the given data...")
        self.logger.debug(f"Data: {data}")

        # Clear the previous graph
        self.subplot.clear()

        # Update the graph with the new data
        x = data.get("x", [])
        y = data.get("y", [])
        self.subplot.plot(x, y)

        # Draw the updated graph
        self.graph.draw()

    def clear_gui(self):
        """
        Clears the GUI components.
        """
        self.logger.info("Clearing the GUI components...")
        self.subplot.clear()
        self.graph.draw()

