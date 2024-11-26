# ui/frames/signal_heatmap_frame.py

import tkinter as tk
from tkinter import ttk
from wireless_pen_test_lib.core import CoreFramework

class SignalHeatmapFrame(ttk.Frame):
    def __init__(self, parent, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self):
        self.start_button = ttk.Button(self, text="Start Signal Capture", command=self.start_capture)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(self, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack(pady=10)

        self.generate_button = ttk.Button(self, text="Generate Heatmap", command=self.generate_heatmap)
        self.generate_button.pack(pady=10)

    def start_capture(self):
        self.core.start_signal_heatmap()

    def stop_capture(self):
        self.core.stop_event.set()

    def generate_heatmap(self):
        self.core.generate_heatmap()
