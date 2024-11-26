# ui/frames/report_generation_frame.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from wireless_pen_test_lib.core import CoreFramework
from wireless_pen_test_lib.core import CoreFramework

class ReportGenerationFrame(ttk.Frame):
    def __init__(self, parent, core_framework: CoreFramework):
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()

    def create_widgets(self):
        # Generate Report Button
        generate_button = ttk.Button(self, text="Generate Detailed Report", command=self.generate_report)
        generate_button.pack(pady=20)

    def generate_report(self):
        # Fetch scan and exploit results from CoreFramework
        scan_results = self.core.get_scan_results()
        exploit_results = self.core.get_exploit_results()
        report_data = self.core.get_additional_report_data()

        # Ask user for export format
        export_format = tk.StringVar(value='pdf')
        format_window = tk.Toplevel(self)
        format_window.title("Select Export Format")
        ttk.Label(format_window, text="Choose Report Format:").pack(padx=10, pady=10)
        format_combo = ttk.Combobox(format_window, textvariable=export_format, state='readonly')
        format_combo['values'] = ['pdf', 'json', 'csv']
        format_combo.pack(padx=10, pady=5)
        format_combo.current(0)

        def confirm_export():
            selected_format = export_format.get()
            file_types = {
                'pdf': [('PDF Files', '*.pdf')],
                'json': [('JSON Files', '*.json')],
                'csv': [('CSV Files', '*.csv')]
            }
            file_path = filedialog.asksaveasfilename(defaultextension=f".{selected_format}",
                                                     filetypes=file_types[selected_format])
            if file_path:
                try:
                    self.core.generate_detailed_report(scan_results, exploit_results, report_data, selected_format, file_path)
                    messagebox.showinfo("Export Successful", f"Report exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export report: {e}")
            format_window.destroy()

        ttk.Button(format_window, text="Export", command=confirm_export).pack(pady=10)
