"""Graph pattern detection utilities."""

from typing import Any, Dict, List

import networkx as nx
from networkx.algorithms import isomorphism


class PatternDetector:
    """Detect known attack patterns inside a trace graph."""

    def _build_graph_from_trace(
        self, trace: Dict[str, List[Dict[str, Any]]]
    ) -> nx.DiGraph:
        """Convert the backtrack trace into a NetworkX graph."""
        graph = nx.DiGraph()

        for node in trace.get("nodes", []):
            node_id = f"{node['type']}_{node['id']}"
            graph.add_node(node_id, **node)

        for edge in trace.get("edges", []):
            src_id = f"{edge['src']['type']}_{edge['src']['id']}"
            dst_id = f"{edge['dst']['type']}_{edge['dst']['id']}"
            action_raw = (edge.get("action") or "").split(" ")[0]
            graph.add_edge(
                src_id,
                dst_id,
                action=action_raw,
                full_action=edge.get("action"),
            )

        return graph

    @staticmethod
    def _get_drop_execute_signature() -> nx.DiGraph:
        """Define the Drop & Execute pattern signature."""
        signature = nx.DiGraph()
        signature.add_node("downloader", type="proc")
        signature.add_node("payload_file", type="file")
        signature.add_node("malware_proc", type="proc")

        signature.add_edge("downloader", "payload_file", action="write")
        signature.add_edge("payload_file", "malware_proc", action="exec")
        return signature

    def detect(self, trace: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Return all pattern matches found in the trace."""
        if not trace:
            return []

        graph_trace = self._build_graph_from_trace(trace)
        graph_sig = self._get_drop_execute_signature()

        node_match = isomorphism.categorical_node_match("type", "unknown")
        edge_match = isomorphism.categorical_edge_match("action", "unknown")

        matcher = isomorphism.DiGraphMatcher(
            graph_trace, graph_sig, node_match=node_match, edge_match=edge_match
        )

        findings: List[Dict[str, Any]] = []
        for match in matcher.subgraph_isomorphisms_iter():
            inverted = {sig_label: trace_node for trace_node, sig_label in match.items()}
            if not {"downloader", "payload_file", "malware_proc"} <= inverted.keys():
                continue
            finding = {
                "pattern": "Drop & Execute",
                "details": {
                    "downloader": graph_trace.nodes[inverted["downloader"]].get(
                        "exe", "unknown"
                    ),
                    "file": graph_trace.nodes[inverted["payload_file"]].get(
                        "path", "unknown"
                    ),
                    "malware": graph_trace.nodes[inverted["malware_proc"]].get(
                        "exe", "unknown"
                    ),
                },
            }
            if finding not in findings:
                findings.append(finding)
        return findings

