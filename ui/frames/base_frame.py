from abc import ABC, abstractmethod
from tkinter import Tk, Frame, Label, Button, Entry, StringVar, messagebox
from tkinter import ttk
from typing import Dict, Any
from core import CoreFramework


class BaseFrame(ttk.Frame, ABC):
    def __init__(self, parent: Tk, core_framework: CoreFramework, *args, **kwargs):
        """
        Initializes the BaseFrame.
        Args:
            parent (Tk): The parent Tkinter widget.
            core_framework (CoreFramework): An instance of CoreFramework.
        """
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.core_framework = core_framework

    @abstractmethod
    def create_widgets(self):
        """
        Creates and arranges all GUI components.
        """
        pass

    @abstractmethod
    def update_gui(self, data: Dict[str, Any]):
        """
        Updates the GUI with the given data.
        Args:
            data (Dict[str, Any]): The data to update the GUI with.
        """
        pass

    @abstractmethod
    def clear_gui(self):
        """
        Clears the GUI components.
        """
        pass