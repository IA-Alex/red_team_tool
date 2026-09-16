"""Utilidades para análisis de grafos y búsqueda de caminos de ataque."""

from __future__ import annotations

import networkx as nx
from typing import List, Any

def find_attack_path(G: nx.Graph, source: str, target: str) -> List[str]:
    """Calcula el camino más corto entre dos nodos en el grafo de activos."""
    try:
        return nx.shortest_path(G, source=source, target=target)
    except nx.NetworkXNoPath:
        return []

def get_nodes_by_type(G: nx.Graph, node_type: str) -> List[str]:
    """Obtiene todos los nodos de un tipo específico (host, service)."""
    return [n for n, d in G.nodes(data=True) if d.get("type") == node_type]

def add_privilege_edge(G: nx.Graph, source: str, target: str, rel_type: str, metadata: dict[str, Any] = None) -> None:
    """Añade una relación de privilegio entre nodos."""
    if metadata is None:
        metadata = {}
    G.add_edge(source, target, type=rel_type, **metadata)

def add_identity_node(G: nx.Graph, node_id: str, node_type: str, props: dict[str, Any] = None) -> None:
    """Añade un nodo de identidad (user, group, credential)."""
    if props is None:
        props = {}
    G.add_node(node_id, type=node_type, **props)
