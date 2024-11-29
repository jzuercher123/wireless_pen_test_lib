# wireless_pen_test_lib/ui/frames/targets_tab.py

"""
TargetsTab Module

This module defines the TargetsTab class, which provides a centralized interface
for managing all discovered targets within the WirelessPenTestLib application.
Users can view, search, edit, and delete targets from this tab.

**⚠️ Important Note:**
Ensure you have the necessary permissions to manage and interact with the targets.
Unauthorized access or modification of network targets is illegal and unethical.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import List
from wireless_pen_test_lib.core.database import Target
from wireless_pen_test_lib.core.pool_manager import Pool


class TargetsTab(ttk.Frame):
    """
    TargetsTab Class

    Provides a user interface for viewing, searching, editing, and deleting
    saved network targets from the universal pool.
    """

    def __init__(self, parent: ttk.Notebook, core_framework):
        """
        Initializes the TargetsTab.

        Args:
            parent (ttk.Notebook): The parent Notebook widget.
            core_framework (CoreFramework): Instance of CoreFramework for backend operations.
        """
        super().__init__(parent)
        self.core = core_framework
        self.create_widgets()
        self.populate_targets()
        self.pool: Pool = self.core.pool  # Explicit type annotation


    def create_widgets(self):
        """
        Creates the widgets for the 'Targets' tab.
        """
        # Title
        title = ttk.Label(self, text="Saved Targets", font=("Helvetica", 16))
        title.pack(pady=10)

        # Search Bar
        search_frame = ttk.Frame(self)
        search_frame.pack(padx=10, pady=5, fill='x')

        search_label = ttk.Label(search_frame, text="Search:")
        search_label.pack(side='left')

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side='left', padx=5, fill='x', expand=True)
        search_entry.bind('<KeyRelease>', self.on_search)

        # Refresh Button
        refresh_button = ttk.Button(search_frame, text="Refresh", command=self.populate_targets)
        refresh_button.pack(side='left', padx=5)

        # Treeview for displaying targets
        columns = ("SSID", "BSSID", "IP", "MAC", "Hostname", "Signal", "Channel", "Security", "Last Seen", "Notes")
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor='center')

        self.tree.pack(padx=10, pady=10, fill='both', expand=True)

        # Context Menu
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Delete Target", command=self.delete_selected_target)
        self.menu.add_command(label="View Details", command=self.view_selected_target)

    def populate_targets(self):
        """
        Populates the Treeview with targets from the universal pool.
        """
        for row in self.tree.get_children():
            self.tree.delete(row)

        try:
            targets = self.core.get_all_targets()
            for target in targets:
                self.tree.insert("", "end", values=(
                    target.ssid,
                    target.bssid,
                    target.ip if target.ip else "N/A",
                    target.mac if target.mac else "N/A",
                    target.hostname if target.hostname else "N/A",
                    target.signal if target.signal else "N/A",
                    target.channel if target.channel else "N/A",
                    target.security if target.security else "N/A",
                    target.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    target.notes if target.notes else ""
                ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve targets: {e}")

    def on_search(self, event):
        """
        Filters the Treeview based on the search query.
        """
        query = self.search_var.get().lower()
        for row in self.tree.get_children():
            self.tree.delete(row)

        try:
            targets = self.core.get_all_targets()
            for target in targets:
                if (query in (target.ssid or "").lower() or
                    query in (target.bssid or "").lower() or
                    query in (target.ip or "").lower() or
                    query in (target.mac or "").lower() or
                    query in (target.hostname or "").lower()):
                    self.tree.insert("", "end", values=(
                        target.ssid,
                        target.bssid,
                        target.ip if target.ip else "N/A",
                        target.mac if target.mac else "N/A",
                        target.hostname if target.hostname else "N/A",
                        target.signal if target.signal else "N/A",
                        target.channel if target.channel else "N/A",
                        target.security if target.security else "N/A",
                        target.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                        target.notes if target.notes else ""
                    ))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to filter targets: {e}")

    def show_context_menu(self, event):
        """
        Displays the context menu on right-click.
        """
        selected_item = self.tree.identify_row(event.y)
        if selected_item:
            self.tree.selection_set(selected_item)
            self.menu.post(event.x_root, event.y_root)

    def delete_selected_target(self):
        """
        Deletes the selected target from the universal pool.
        """
        selected = self.tree.selection()
        if selected:
            target_bssid = self.tree.item(selected[0])['values'][1]
            confirm = messagebox.askyesno("Delete Target", f"Are you sure you want to delete target {target_bssid}?")
            if confirm:
                try:
                    self.core.db_manager.delete_target(target_bssid)
                    self.populate_targets()
                    messagebox.showinfo("Success", "Target deleted successfully.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete target: {e}")

    def view_selected_target(self):
        """
        Displays detailed information of the selected target.
        """
        selected = self.tree.selection()
        if selected:
            target_bssid = self.tree.item(selected[0])['values'][1]
            target = self.core.get_target_by_bssid(target_bssid)
            if target:
                details = (
                    f"SSID: {target.ssid}\n"
                    f"BSSID: {target.bssid}\n"
                    f"IP: {target.ip if target.ip else 'N/A'}\n"
                    f"MAC: {target.mac if target.mac else 'N/A'}\n"
                    f"Hostname: {target.hostname if target.hostname else 'N/A'}\n"
                    f"Signal: {target.signal if target.signal else 'N/A'} dBm\n"
                    f"Channel: {target.channel if target.channel else 'N/A'}\n"
                    f"Security: {target.security if target.security else 'N/A'}\n"
                    f"Last Seen: {target.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Notes: {target.notes if target.notes else 'N/A'}"
                )
                messagebox.showinfo("Target Details", details)
