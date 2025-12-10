"""
Cross-Reference Mapper
Identifies clause interconnections and builds dependency graph
"""

import re
from typing import Dict, List, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class CrossReferenceMapper:
    """Maps cross-references between clauses to identify hidden dependencies."""
    
    def __init__(self):
        self.reference_patterns = [
            r'(?:Section|Clause|Article|Paragraph)\s+(\d+(?:\.\d+)?)',
            r'(?:pursuant|subject)\s+to\s+(?:Section|Clause)\s+(\d+(?:\.\d+)?)',
            r'as\s+defined\s+in\s+(?:Section|Clause)\s+(\d+(?:\.\d+)?)',
            r'See\s+(?:Section|Clause)\s+(\d+(?:\.\d+)?)',
        ]
    
    def map_references(self, text: str) -> Dict:
        """
        Build complete cross-reference map.
        
        Returns:
            Dictionary with clause dependencies and risk clusters
        """
        # Extract all clause numbers present in document
        clauses = self._extract_clause_structure(text)
        
        # Build reference map
        reference_map = self._build_reference_map(text, clauses)
        
        # Identify risk clusters (groups of interconnected clauses)
        clusters = self._identify_clusters(reference_map)
        
        # Find distant references (clauses far apart that reference each other)
        distant_refs = self._find_distant_references(reference_map, text)
        
        logger.info(f"✓ Mapped {len(reference_map)} clauses with {len(clusters)} risk clusters")
        
        return {
            'clause_count': len(clauses),
            'reference_map': reference_map,
            'risk_clusters': clusters,
            'distant_references': distant_refs,
            'highly_connected': self._find_highly_connected(reference_map)
        }
    
    def _extract_clause_structure(self, text: str) -> List[str]:
        """Extract all clause/section numbers from document."""
        clauses = set()
        
        # Pattern for section headers
        header_pattern = r'(?:Section|Clause|Article)\s+(\d+(?:\.\d+)?)'
        
        matches = re.finditer(header_pattern, text, re.IGNORECASE)
        for match in matches:
            clauses.add(match.group(1))
        
        return sorted(list(clauses))
    
    def _build_reference_map(self, text: str, clauses: List[str]) -> Dict[str, List[str]]:
        """Build map of which clauses reference which other clauses."""
        ref_map = {clause: [] for clause in clauses}
        
        # Split text into sections
        lines = text.split('\n')
        current_clause = None
        
        for line in lines:
            # Check if this line is a clause header
            header_match = re.search(r'(?:Section|Clause)\s+(\d+(?:\.\d+)?)', line, re.IGNORECASE)
            if header_match:
                current_clause = header_match.group(1)
                continue
            
            # If we're in a clause, look for references to other clauses
            if current_clause:
                for pattern in self.reference_patterns:
                    refs = re.findall(pattern, line, re.IGNORECASE)
                    for ref in refs:
                        if ref != current_clause and ref in ref_map:
                            if ref not in ref_map[current_clause]:
                                ref_map[current_clause].append(ref)
        
        return ref_map
    
    def _identify_clusters(self, ref_map: Dict[str, List[str]]) -> List[Dict]:
        """Identify clusters of interconnected clauses."""
        clusters = []
        visited = set()
        
        def dfs(clause: str, cluster: Set[str]):
            """Depth-first search to find connected clauses."""
            if clause in visited:
                return
            visited.add(clause)
            cluster.add(clause)
            
            # Add referenced clauses
            for ref in ref_map.get(clause, []):
                dfs(ref, cluster)
            
            # Add clauses that reference this one
            for other_clause, refs in ref_map.items():
                if clause in refs:
                    dfs(other_clause, cluster)
        
        # Find clusters
        for clause in ref_map.keys():
            if clause not in visited:
                cluster = set()
                dfs(clause, cluster)
                
                # Only consider clusters with 3+ clauses as risky
                if len(cluster) >= 3:
                    clusters.append({
                        'clauses': list(cluster),
                        'size': len(cluster),
                        'risk': 'HIGH' if len(cluster) >= 5 else 'MEDIUM'
                    })
        
        return sorted(clusters, key=lambda x: x['size'], reverse=True)
    
    def _find_distant_references(self, ref_map: Dict[str, List[str]], text: str) -> List[Dict]:
        """Find references between clauses that are far apart in document."""
        distant = []
        
        for clause, refs in ref_map.items():
            for ref in refs:
                try:
                    clause_num = float(clause)
                    ref_num = float(ref)
                    distance = abs(clause_num - ref_num)
                    
                    # Flag if clauses are more than 10 sections apart
                    if distance >= 10:
                        distant.append({
                            'from_clause': clause,
                            'to_clause': ref,
                            'distance': distance,
                            'risk': 'Easy to miss during review'
                        })
                except ValueError:
                    continue
        
        return distant
    
    def _find_highly_connected(self, ref_map: Dict[str, List[str]]) -> List[Dict]:
        """Find clauses that are referenced by many other clauses."""
        # Count incoming references
        incoming_refs = {}
        for clause, refs in ref_map.items():
            for ref in refs:
                incoming_refs[ref] = incoming_refs.get(ref, 0) + 1
        
        # Flag clauses with many incoming references
        highly_connected = []
        for clause, count in incoming_refs.items():
            if count >= 3:
                highly_connected.append({
                    'clause': clause,
                    'reference_count': count,
                    'risk': 'Central clause - changes affect many other clauses'
                })
        
        return sorted(highly_connected, key=lambda x: x['reference_count'], reverse=True)


def map_cross_references(document_text: str) -> Dict:
    """
    Convenience function to map cross-references.
    
    Args:
        document_text: Full document text
        
    Returns:
        Cross-reference analysis
    """
    mapper = CrossReferenceMapper()
    return mapper.map_references(document_text)