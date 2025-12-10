"""
Definition Section Analyzer
Extracts and analyzes definitions for overly broad or circular definitions
"""

import re
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


class DefinitionAnalyzer:
    """Analyzes definition sections for traps and overly broad language."""
    
    def __init__(self):
        self.definition_markers = [
            r'DEFINITIONS?',
            r'INTERPRETATION',
            r'MEANING OF TERMS',
            r'Section\s+1[\.:]?\s+Definitions',
        ]
        
        self.broad_indicators = [
            'any', 'all', 'every', 'including but not limited to',
            'without limitation', 'of any kind', 'whatsoever'
        ]
    
    def extract_definitions(self, text: str) -> Dict:
        """
        Extract all definitions from document.
        
        Returns:
            Dictionary with definitions and analysis
        """
        # Find definition section
        definition_section = self._find_definition_section(text)
        
        if not definition_section:
            logger.warning("⚠ No definitions section found")
            return {
                'found': False,
                'definitions': [],
                'risky_definitions': [],
                'circular_definitions': []
            }
        
        # Parse individual definitions
        definitions = self._parse_definitions(definition_section)
        
        # Analyze for risks
        risky_defs = self._identify_risky_definitions(definitions)
        circular_defs = self._identify_circular_definitions(definitions)
        
        logger.info(f"✓ Found {len(definitions)} definitions, {len(risky_defs)} risky")
        
        return {
            'found': True,
            'definitions': definitions,
            'risky_definitions': risky_defs,
            'circular_definitions': circular_defs,
            'definition_section_text': definition_section
        }
    
    def _find_definition_section(self, text: str) -> str:
        """Locate the definitions section in document."""
        lines = text.split('\n')
        
        for i, line in enumerate(lines):
            for marker in self.definition_markers:
                if re.search(marker, line, re.IGNORECASE):
                    # Found start of definitions, extract next 50 lines or until next major section
                    section_lines = []
                    for j in range(i, min(i + 100, len(lines))):
                        # Stop if we hit another major section
                        if j > i and re.search(r'^(?:SECTION|ARTICLE)\s+\d+', lines[j], re.IGNORECASE):
                            break
                        section_lines.append(lines[j])
                    
                    return '\n'.join(section_lines)
        
        return ""
    
    def _parse_definitions(self, section_text: str) -> List[Dict]:
        """Parse individual term definitions."""
        definitions = []
        
        # Pattern: "Term" means/refers to/includes...
        pattern = r'["""]([^"""]+)["""]?\s+(means|refers to|includes|shall mean)\s+(.+?)(?=\n["""]|\n\n|$)'
        matches = re.finditer(pattern, section_text, re.IGNORECASE | re.DOTALL)
        
        for match in matches:
            term = match.group(1).strip()
            definition_text = match.group(3).strip()
            
            definitions.append({
                'term': term,
                'definition': definition_text,
                'full_text': match.group(0)
            })
        
        # Alternative pattern: Term: Definition
        alt_pattern = r'^([A-Z][a-zA-Z\s]+):\s+(.+?)(?=\n[A-Z][a-zA-Z\s]+:|\n\n|$)'
        alt_matches = re.finditer(alt_pattern, section_text, re.MULTILINE | re.DOTALL)
        
        for match in alt_matches:
            term = match.group(1).strip()
            definition_text = match.group(2).strip()
            
            # Avoid duplicates
            if not any(d['term'].lower() == term.lower() for d in definitions):
                definitions.append({
                    'term': term,
                    'definition': definition_text,
                    'full_text': match.group(0)
                })
        
        return definitions
    
    def _identify_risky_definitions(self, definitions: List[Dict]) -> List[Dict]:
        """Identify overly broad or dangerous definitions."""
        risky = []
        
        for defn in definitions:
            text = defn['definition'].lower()
            risk_score = 0
            reasons = []
            
            # Check for broad indicators
            for indicator in self.broad_indicators:
                if indicator in text:
                    risk_score += 1
                    reasons.append(f"Contains '{indicator}'")
            
            # Check for specific risky patterns
            if 'any information' in text or 'all information' in text:
                risk_score += 2
                reasons.append("Extremely broad scope: 'any/all information'")
            
            if 'whether or not' in text:
                risk_score += 1
                reasons.append("Removes marking requirement")
            
            if 'including' in text and 'limited to' not in text:
                risk_score += 1
                reasons.append("Open-ended inclusion without limitation")
            
            # Flag if risky
            if risk_score >= 2:
                risky.append({
                    'term': defn['term'],
                    'definition': defn['definition'],
                    'risk_score': risk_score,
                    'reasons': reasons,
                    'severity': 'HIGH' if risk_score >= 3 else 'MEDIUM'
                })
        
        return risky
    
    def _identify_circular_definitions(self, definitions: List[Dict]) -> List[Dict]:
        """Identify circular or cross-referenced definitions."""
        circular = []
        
        # Build term list for cross-reference checking
        terms = [d['term'].lower() for d in definitions]
        
        for defn in definitions:
            text = defn['definition'].lower()
            
            # Check if definition references other defined terms
            referenced_terms = []
            for term in terms:
                if term != defn['term'].lower() and term in text:
                    referenced_terms.append(term)
            
            # Check for section references
            section_refs = re.findall(r'(?:section|clause)\s+\d+', text, re.IGNORECASE)
            
            if referenced_terms or section_refs:
                circular.append({
                    'term': defn['term'],
                    'definition': defn['definition'],
                    'references_terms': referenced_terms,
                    'references_sections': section_refs,
                    'risk': 'Circular/complex definition - may hide obligations'
                })
        
        return circular


def analyze_definitions(document_text: str) -> Dict:
    """
    Convenience function to analyze definitions.
    
    Args:
        document_text: Full document text
        
    Returns:
        Analysis results
    """
    analyzer = DefinitionAnalyzer()
    return analyzer.extract_definitions(document_text)