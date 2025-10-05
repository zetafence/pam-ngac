import hypernetx as hnx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
from matplotlib.patches import Polygon
from matplotlib.patches import Ellipse
from collections import defaultdict
import networkx as nx

def create_sample_hypergraph():
    print("Creating sample Hypergraph")

    # Creating a new hypergraph using a dictionary of edges
    edges = {'e0': {'user1'}, 'e1': {'user2', 'user3'}}
    H = hnx.Hypergraph(edges)

    H.add_edge('e1', {'user2', 'user3'})  
    H.add_node('user99')

    # Displaying the nodes and edges
    print("Nodes in Hypergraph:", list(H.nodes))
    print("Edges in Hypergraph:", list(H.edges))
    g = len(H.nodes) + len(H.edges)
    print(f"graph size = {g}")

def create_permission_based_os_hypergraph():
    print("Creating permission-based hypergraph")

    users = ["Alice", "Bob", "Charlie", "David", "Root"]
    filesystems = ["ext4", "NFS", "SAN", "RAID"]

    # Step 1: Build permission map from scenario
    permission_map = {
        ("Alice", "ext4"): {"r", "w", "x"},
        ("Bob", "ext4"): {"r"},
        ("Bob", "NFS"): {"r", "w"},
        ("Alice", "NFS"): {"w"},
        ("Charlie", "NFS"): {"r"},
        ("Charlie", "SAN"): {"r", "x"},
        ("David", "SAN"): {"r", "w"},
        ("Bob", "SAN"): {"r", "w"},
        ("Alice", "RAID"): {"r", "w"},
        ("Charlie", "RAID"): {"r"},
        ("Bob", "RAID"): {"x"},
        ("Charlie", "ext4"): {"r"},
        ("Root", "ext4"): {"r", "w", "x"},
        ("Root", "NFS"): {"r", "w", "x"},
        ("Root", "SAN"): {"r", "w", "x"},
        ("Root", "RAID"): {"r", "w", "x"},
    }

    # Superadmin: Bob and Charlie get full access to all volumes
    for superadmin in ["Root"]:
        for fs in filesystems:
            permission_map[(superadmin, fs)] = {"r", "w", "x"}

    # Step 2: Group (user, fs) pairs by permission set
    perm_edges = defaultdict(set)
    for (user, fs), perms in permission_map.items():
        edge_label = ''.join(sorted(perms))  # e.g. "rw", "rx", "rwx"
        perm_edges[edge_label].add(user)
        perm_edges[edge_label].add(fs)

    # Step 3: Create hypergraph
    H = hnx.Hypergraph(perm_edges)

    # Step 4: Define bright edge border colors
    bright_colors = {
        "rw": "#1f77b4",   # blue
        "r": "#ff7f0e",    # orange
        "rx": "#2ca02c",   # green
        "rwx": "#d62728",  # red
    }

    # Assign colors to edges
    edge_color_map = {edge_name: bright_colors.get(edge_name, "#AAAAAA") for edge_name in H.edges}

    # Step 5: Get node positions
    pos = nx.spring_layout(H.bipartite())

    # Step 6: Draw hypergraph
    fig, ax = plt.subplots(figsize=(10, 8))
    hnx.draw(H,
             pos=pos,
             edges_kwargs={
                 "edgecolors": [edge_color_map[e] for e in H.edges],
                 "linewidths": [30] * len(H.edges),
             },
             nodes_kwargs={
                 "facecolors": "white",
                 "edgecolors": "black",
                 "linewidths": 0
             },
             with_edge_labels=True,
             ax=ax)

    # Step 7: Overlay custom node shapes
    for node in H.nodes:
        x, y = pos[node]
        if node in users:
            fcolor = 'orange'
            if node == 'Root':
                fcolor = 'red'
            ax.plot(x, y, marker='o', markersize=100/len(H.nodes),
                    markerfacecolor=fcolor, markeredgecolor='black', zorder=3)
        elif node in filesystems:
            ax.plot(x, y, marker='h', markersize=100/len(H.nodes),
                    markerfacecolor='green', markeredgecolor='black', zorder=3)

    #ax.set_title("Hypergraph Visualization of File System Access — Users + Volume", fontsize=14)
    ax.axis("off")

    # Step 8: Build legends
    permission_legend = [
        Patch(color=color, label=f"Permissions: {perm}")
        for perm, color in bright_colors.items()
    ]

    # Legend 2: User icon as oval
    user_icon = Line2D([0], [0], marker='o', color='w', label="Users",
        markerfacecolor='orange', markeredgecolor='black', markersize=10)

    root_icon = Line2D([0], [0], marker='o', color='w', label="Root",
        markerfacecolor='red', markeredgecolor='black', markersize=10)

    # Legend 3: Volume icon as gray oval
    volume_icon = Line2D([0], [0], marker='h', color='w', label="Volumes",
        markerfacecolor='green', markeredgecolor='black', markersize=10)

    # Combine all
    ax.legend(handles=permission_legend + [user_icon, root_icon, volume_icon],
          title="Hyperedges & Nodes", loc="lower right", bbox_to_anchor=(1, 0))

    plt.tight_layout()
    plt.show()

    return H

if __name__ == "__main__":
    create_sample_hypergraph()
    H = create_permission_based_os_hypergraph()
