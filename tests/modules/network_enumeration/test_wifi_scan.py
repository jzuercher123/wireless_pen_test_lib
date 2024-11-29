from wireless_pen_test_lib.modules.network_enumeration.wifi_scanner import WifiScanner
from wireless_pen_test_lib.core.pool_manager import Pool
from wireless_pen_test_lib.core.database import Target
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List
from wireless_pen_test_lib.core import CoreFramework


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

        # Targets List
        self.targets_list = tk.Listbox(self, height=10, selectmode='SINGLE')
        self.targets_list.pack(padx=10, pady=5, fill='both', expand=True)
        self.targets_list.bind('<Double-Button-1>', self.on_target_select)

        # Buttons Frame
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(pady=5)

        # Add Button
        add_button = ttk.Button(buttons_frame, text="Add", command=self.on_add)
        add_button.pack(side='left', padx=5)

        # Edit Button
        edit_button = ttk.Button(buttons_frame, text="Edit", command=self.on_edit)
        edit_button.pack(side='left', padx=5)

        # Delete Button
        delete_button = ttk.Button(buttons_frame, text= "Delete", command=self.on_delete)

        delete_button.pack(side='left', padx=5)

    def populate_targets(self):
        """
        Populates the targets list with saved targets.

        :return:
        """
        self.targets_list.delete(0, tk.END)
        targets = self.core.get_all_targets()
        for target in targets:
            self.targets_list.insert(tk.END, target.ssid)

    def on_search(self, event):
        """
        Filters the targets list based on the search query.

        :param event:
        :return:
        """
        query = self.search_var.get().lower()
        self.targets_list.delete(0, tk.END)
        for target in self.core.get_all_targets():
            if query in target.ssid.lower():
                self.targets_list.insert(tk.END, target.ssid)

    def on_target_select(self, event):
        """
        Opens the details view for the selected target.

        :param event:
        :return:
        """
        index = self.targets_list.curselection()
        if index:
            target = self.core.get_target_by_ssid(self.targets_list.get(index))
            self.core.show_target_details(target)

    def on_add(self):
        """
        Opens the add target dialog.

        :return:
        """
        self.core.show_add_target_dialog()

    def on_edit(self):
        """
        Opens the edit target dialog.


        :return:
        """
        index = self.targets_list.curselection()
        if index:
            target = self.core.get_target_by_ssid(self.targets_list.get(index))
            self.core.show_edit_target_dialog(target)

    def on_delete(self):
        """
        Deletes the selected target.

        :return:
        """
        index = self.targets_list.curselection()
        if index:
            target = self.core.get_target_by_ssid(self.targets_list.get(index))
            self.core.delete_target(target)
            self.populate_targets()


def main():
    """
    Main function for testing the TargetsTab class.
    """
    root = tk.Tk()
    root.title("Targets Tab Test")
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)
    core = CoreFramework()
    targets_tab = TargetsTab(notebook, core)
    notebook.add(targets_tab, text="Targets")
    root.mainloop()

if __name__ == "__main__":
    main()