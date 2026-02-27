"""Attack graph modeling for vulnerability relationship analysis."""

import logging
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

try:
    import networkx as nx
except ImportError:
    nx = None

from ..utils.models import Vulnerability
from ..utils.constants import VulnerabilityType


logger = logging.getLogger(__name__)


class AttackGraph:
    """
    Models attack paths and vulnerability relationships.
    
    Creates a directed graph of vulnerabilities showing how they could be
    chained together for exploitation.
    """
    
    # Vulnerability relationships
    VULNERABILITY_CHAINS = {
        # IDOR can lead to authentication bypass
        VulnerabilityType.IDOR: [
            VulnerabilityType.BROKEN_ACCESS_CONTROL,
            VulnerabilityType.PRIVILEGE_ESCALATION,
        ],
        # SQLi leads to data exfiltration
        VulnerabilityType.SQL_INJECTION: [
            VulnerabilityType.INFORMATION_DISCLOSURE,
        ],
        # XSS can lead to session hijacking
        VulnerabilityType.REFLECTED_XSS: [
            VulnerabilityType.MISSING_SECURITY_HEADERS,
        ],
        VulnerabilityType.STORED_XSS: [
            VulnerabilityType.MISSING_SECURITY_HEADERS,
        ],
        # Weak headers enable multiple attacks
        VulnerabilityType.MISSING_SECURITY_HEADERS: [
            VulnerabilityType.REFLECTED_XSS,
            VulnerabilityType.STORED_XSS,
            VulnerabilityType.OPEN_REDIRECT,
        ],
        # CORS misconfiguration enables attacks
        VulnerabilityType.CORS_MISCONFIGURATION: [
            VulnerabilityType.BROKEN_ACCESS_CONTROL,
        ],
    }
    
    def __init__(self):
        """Initialize attack graph."""
        if nx is None:
            logger.warning("networkx not installed, attack graph disabled")
            self.graph = None
        else:
            self.graph = nx.DiGraph()
            
        self.vulnerabilities: List[Vulnerability] = []
        self.chains: List[List[Vulnerability]] = []
        
    def add_vulnerability(self, vuln: Vulnerability):
        """Add vulnerability node to graph."""
        if self.graph is None:
            return
            
        self.vulnerabilities.append(vuln)
        node_id = f"{vuln.type.value}_{len(self.vulnerabilities)}"
        
        self.graph.add_node(
            node_id,
            vulnerability=vuln,
            severity=vuln.severity.value,
            cvss_score=vuln.cvss_score,
        )
        
    def connect_vulnerabilities(self):
        """Connect related vulnerabilities in graph."""
        if self.graph is None:
            return
            
        # Build vulnerability type map
        vuln_map = defaultdict(list)
        for node in self.graph.nodes():
            vuln = self.graph.nodes[node]['vulnerability']
            vuln_map[vuln.type].append(node)
            
        # Add edges based on chains
        for source_type, target_types in self.VULNERABILITY_CHAINS.items():
            if source_type not in vuln_map:
                continue
                
            for source_node in vuln_map[source_type]:
                for target_type in target_types:
                    if target_type in vuln_map:
                        for target_node in vuln_map[target_type]:
                            weight = self._calculate_chain_weight(
                                self.graph.nodes[source_node]['vulnerability'],
                                self.graph.nodes[target_node]['vulnerability'],
                            )
                            self.graph.add_edge(source_node, target_node, weight=weight)
                            
    def find_attack_paths(self, max_depth: int = 5) -> List[List[Vulnerability]]:
        """
        Find potential attack paths through vulnerability chain.
        
        Parameters
        ----------
        max_depth : int
            Maximum path length to explore.
            
        Returns
        -------
        List[List[Vulnerability]]
            List of potential attack paths.
        """
        if self.graph is None or len(self.graph.nodes()) == 0:
            return []
            
        paths = []
        
        # For each node, find all paths starting from it
        for start_node in self.graph.nodes():
            for end_node in self.graph.nodes():
                if start_node == end_node:
                    continue
                    
                try:
                    for path in nx.all_simple_paths(
                        self.graph, start_node, end_node, cutoff=max_depth
                    ):
                        vuln_path = [
                            self.graph.nodes[node]['vulnerability'] for node in path
                        ]
                        if len(vuln_path) >= 2:  # Only multi-vuln paths
                            paths.append(vuln_path)
                except nx.NetworkXNoPath:
                    continue
                    
        return paths
        
    def identify_critical_nodes(self, top_n: int = 5) -> List[Tuple[Vulnerability, float]]:
        """
        Identify critical vulnerabilities that enable many attack paths.
        
        Uses betweenness centrality to find high-impact vulnerabilities.
        
        Parameters
        ----------
        top_n : int
            Number of critical nodes to return.
            
        Returns
        -------
        List[Tuple[Vulnerability, float]]
            List of (vulnerability, criticality_score) tuples.
        """
        if self.graph is None or len(self.graph.nodes()) == 0:
            return []
            
        try:
            centrality = nx.betweenness_centrality(self.graph, weight='weight')
            critical = sorted(
                [(self.graph.nodes[node]['vulnerability'], score)
                 for node, score in centrality.items()],
                key=lambda x: x[1],
                reverse=True
            )
            return critical[:top_n]
        except Exception as e:
            logger.warning(f"Could not calculate centrality: {e}")
            return []
            
    def detect_privilege_escalation_chains(self) -> List[List[Vulnerability]]:
        """Detect chains that could lead to privilege escalation."""
        paths = self.find_attack_paths()
        
        # Filter for paths ending in privilege escalation
        privilege_chains = [
            path for path in paths
            if path[-1].type == VulnerabilityType.PRIVILEGE_ESCALATION
        ]
        
        return privilege_chains
        
    def export_graphml(self, output_file: str):
        """Export attack graph in GraphML format."""
        if self.graph is None:
            logger.warning("Cannot export, networkx not available")
            return
            
        try:
            nx.write_graphml(self.graph, output_file)
            logger.info(f"Attack graph exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting graph: {e}")
            
    def export_dot(self, output_file: str):
        """Export attack graph in DOT format (Graphviz)."""
        if self.graph is None:
            logger.warning("Cannot export, networkx not available")
            return
            
        try:
            from networkx.drawing.nx_agraph import to_agraph
            agraph = to_agraph(self.graph)
            agraph.layout(prog='dot')
            agraph.draw(output_file, prog='dot', format='svg')
            logger.info(f"Attack graph visualization exported to {output_file}")
        except ImportError:
            logger.warning("Graphviz/pygraphviz not installed, cannot export DOT")
        except Exception as e:
            logger.error(f"Error exporting graph: {e}")
            
    def get_summary(self) -> Dict[str, int]:
        """Get graph summary statistics."""
        if self.graph is None:
            return {}
            
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'connected_components': nx.number_connected_components(self.graph.to_undirected()),
            'potential_paths': len(self.find_attack_paths()),
            'privilege_escalation_paths': len(self.detect_privilege_escalation_chains()),
        }
        
    def _calculate_chain_weight(self, source: Vulnerability, target: Vulnerability) -> float:
        """Calculate weight (likelihood) of vulnerability chain."""
        # Higher weight = more likely/impactful chain
        # Consider: CVSS scores, types, etc.
        
        weight = 1.0
        
        # Same type/related vulnerabilities get higher weight
        if source.type == target.type:
            weight *= 1.5
            
        # High CVSS vulnerabilities leading to others = high weight
        if source.cvss_score > 8.0:
            weight *= (source.cvss_score / 10.0)
            
        return weight
