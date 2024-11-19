import tkinter as tk
from tkinter import filedialog, messagebox
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class BaseFrame(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.configure(relief=tk.RAISED, borderwidth=2)
        self.init_ui()

    def init_ui(self):
        # Placeholder for any common UI setup across frames
        pass


class NetworkGraphVisualizationFrame(BaseFrame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.init_graph()
        self.init_ui()

    def init_graph(self):
        # Initialize an empty NetworkX graph
        self.G = nx.Graph()

    def init_ui(self):
        # Create and place the Matplotlib Figure
        self.figure = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title("Network Graph Visualization")
        self.ax.axis('off')  # Hide axes

        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Create and place control buttons
        button_frame = tk.Frame(self)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.load_button = tk.Button(button_frame, text="Load Graph", command=self.load_graph)
        self.load_button.pack(side=tk.LEFT, padx=5)

        self.plot_button = tk.Button(button_frame, text="Plot Graph", command=self.plot_graph)
        self.plot_button.pack(side=tk.LEFT, padx=5)

    def load_graph(self):
        # Open a file dialog to select a graph file (e.g., edge list)
        file_path = filedialog.askopenfilename(
            title="Open Graph File",
            filetypes=[("Edge List Files", "*.txt *.edgelist"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                # Load graph from an edge list file
                self.G = nx.read_edgelist(file_path)
                messagebox.showinfo("Success", f"Graph loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load graph:\n{e}")

    def plot_graph(self):
        if not self.G.nodes:
            messagebox.showwarning("Warning", "Graph is empty. Load a graph first.")
            return

        try:
            self.ax.clear()
            self.ax.set_title("Network Graph Visualization")
            self.ax.axis('off')  # Hide axes

            # Define layout for nodes
            pos = nx.spring_layout(self.G)

            # Draw nodes and edges
            nx.draw_networkx_nodes(self.G, pos, ax=self.ax, node_size=300, node_color='skyblue')
            nx.draw_networkx_edges(self.G, pos, ax=self.ax, width=1.0, alpha=0.7)
            nx.draw_networkx_labels(self.G, pos, ax=self.ax, font_size=10)

            self.canvas.draw()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to plot graph:\n{e}")
