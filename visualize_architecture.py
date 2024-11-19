import matplotlib.pyplot as plt
import networkx as nx

# Creating a directed graph to represent the project architecture
G = nx.DiGraph()

# Adding nodes representing major components of the project
components = [
    "CoreFramework", "CLI (Click Commands)", "Scanners (BaseScanner)",
    "LocalScanner", "Protocol Modules", "NetworkInterfaceManager",
    "DataStorageManager", "AuthenticationTools", "Logger", "Vulnerability Database",
    "Scapy", "Netifaces", "Exploit Modules", "Reports"
]

G.add_nodes_from(components)

# Adding edges to represent relationships and dependencies
edges = [
    ("CLI (Click Commands)", "CoreFramework"),
    ("CoreFramework", "Scanners (BaseScanner)"),
    ("CoreFramework", "Protocol Modules"),
    ("CoreFramework", "NetworkInterfaceManager"),
    ("CoreFramework", "DataStorageManager"),
    ("CoreFramework", "AuthenticationTools"),
    ("CoreFramework", "Logger"),
    ("Scanners (BaseScanner)", "LocalScanner"),
    ("LocalScanner", "Scapy"),
    ("LocalScanner", "Netifaces"),
    ("LocalScanner", "Logger"),
    ("CoreFramework", "Vulnerability Database"),
    ("CoreFramework", "Exploit Modules"),
    ("CoreFramework", "Reports"),
    ("Logger", "Reports"),
]

G.add_edges_from(edges)

# Drawing the graph
plt.figure(figsize=(15, 10))
pos = nx.spring_layout(G, seed=42)  # Set seed for consistent layout

# Draw nodes
nx.draw_networkx_nodes(G, pos, node_size=2000, node_color="skyblue", edgecolors="black")

# Draw edges
nx.draw_networkx_edges(G, pos, arrowstyle="->", arrowsize=20, edge_color="grey")

# Draw labels
nx.draw_networkx_labels(G, pos, font_size=10, font_color="black")

plt.title("Interconnection of Components in Wireless Pen Test Lib Project", fontsize=16)
plt.axis("off")
plt.show()
