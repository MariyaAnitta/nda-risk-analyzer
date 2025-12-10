"""
Hidden Risk Pattern Detection Module
Provides regex-based pattern matching for identifying risky clauses
"""

import re
from typing import List, Dict, Tuple
import logging

logger = logging.getLogger(__name__)


class RiskPatternDetector:
    """Detects risky patterns in legal documents using regex and semantic analysis."""
    
    def __init__(self):
        """Initialize pattern libraries organized by risk category."""
        
        # Category 1: Unlimited Liability Patterns
        self.liability_patterns = {
            'unlimited_liability': [
                r'\bunlimited\s+(liability|indemnit)',
                r'\bno\s+cap\b',
                r'\bwithout\s+limitation\b',
                r'\bshall\s+indemnify.*without\s+limit',
                r'\bto\s+the\s+fullest\s+extent',
                r'\ball\s+(liability|damages|losses)',
            ],
            'broad_indemnity': [
                r'\bindemnify.*against\s+any\s+and\s+all',
                r'\bhold\s+harmless.*from\s+all',
                r'\bdefend.*indemnify.*hold\s+harmless',
            ]
        }
        
        # Category 2: Temporal/Duration Traps
        self.temporal_patterns = {
            'perpetual_obligations': [
                r'\bperpetual(ly)?\b',
                r'\bin\s+perpetuity\b',
                r'\bforever\b',
                r'\bwithout\s+time\s+limit',
                r'\bsurvive.*indefinitely',
            ],
            'auto_renewal': [
                r'\bauto(matic(ally)?)?[\s-]*renew',
                r'\brenew\s+automatically',
                r'\bshall\s+renew\s+unless',
                r'\bsuccessively\s+renew',
            ],
            'vague_duration': [
                r'\breasonable\s+period',
                r'\bas\s+long\s+as\s+necessary',
                r'\bpromptly\b',
                r'\bwithin\s+a\s+reasonable\s+time',
            ]
        }
        
        # Category 3: Broad Scope/Definition Patterns
        self.scope_patterns = {
            'overly_broad': [
                r'\ball\s+information',
                r'\bany\s+and\s+all\b',
                r'\bincluding\s+but\s+not\s+limited\s+to',
                r'\bwithout\s+limitation',
                r'\beverything\s+related\s+to',
                r'\ball\s+materials.*of\s+any\s+kind',
            ],
            'broad_confidentiality': [
                r'confidential.*means\s+any',
                r'confidential.*includes\s+all',
                r'\bany\s+information.*whether\s+or\s+not\s+marked',
            ]
        }
        
        # Category 4: Termination Restrictions
        self.termination_patterns = {
            'one_sided_termination': [
                r'\bmay\s+terminate\s+at\s+any\s+time',
                r'\bsole\s+discretion\s+to\s+terminate',
                r'\bwithout\s+cause.*terminate',
            ],
            'difficult_exit': [
                r'\b(\d+)\s+days?\s+notice\s+to\s+terminate',  # Captures notice period
                r'\bonly\s+for\s+material\s+breach',
                r'\bcure\s+period\s+of\s+(\d+)\s+days?',
            ]
        }
        
        # Category 5: IP/Ownership Traps
        self.ip_patterns = {
            'automatic_transfer': [
                r'\bautomatically\s+(transfer|assign|vest)',
                r'\bshall\s+become\s+the\s+property\s+of',
                r'\ball\s+rights.*transfer\s+to',
                r'\bwork\s+for\s+hire',
            ],
            'broad_ip_assignment': [
                r'\ball\s+intellectual\s+property',
                r'\bany\s+and\s+all.*IP',
                r'\bincluding\s+all\s+modifications',
            ]
        }
        
        # Category 6: Jurisdictional Risks
        self.jurisdiction_patterns = {
            'foreign_only_jurisdiction': [
                r'\bexclusive\s+jurisdiction.*(?!India)',
                r'\bcourts\s+of\s+(?!India|Bangalore|Mumbai|Delhi)',
                r'\bforeign\s+(court|jurisdiction)',
            ],
            'mandatory_arbitration': [
                r'\bshall\s+be\s+resolved.*arbitration',
                r'\bexclusively\s+by\s+arbitration',
                r'\bfinal\s+and\s+binding\s+arbitration',
            ]
        }
        
        # Category 7: One-Sided Obligations
        self.imbalance_patterns = {
            'asymmetric_rights': [
                r'\bParty\s+A\s+may.*Party\s+B\s+shall',
                r'\bVendor\s+may.*Company\s+shall',
                r'\bsole\s+discretion',
            ],
            'unilateral_modification': [
                r'\bmay\s+modify.*at\s+any\s+time',
                r'\breserves\s+the\s+right\s+to\s+change',
                r'\bwithout\s+prior\s+notice.*modify',
            ]
        }
        
        # Category 8: Definition Section Traps
        self.definition_patterns = {
            'circular_definition': [
                r'means.*as\s+defined\s+in',
                r'defined\s+in\s+Section\s+\d+',
            ],
            'undefined_terms': [
                r'\b(material\s+breach|reasonable|prompt|substantial)\b',
            ]
        }
        
        # Compile all patterns for performance
        self.compiled_patterns = self._compile_all_patterns()
        
    def _compile_all_patterns(self) -> Dict[str, List[Tuple[re.Pattern, str]]]:
        """Pre-compile all regex patterns for better performance."""
        compiled = {}
        
        all_categories = [
            self.liability_patterns,
            self.temporal_patterns,
            self.scope_patterns,
            self.termination_patterns,
            self.ip_patterns,
            self.jurisdiction_patterns,
            self.imbalance_patterns,
            self.definition_patterns
        ]
        
        for category_dict in all_categories:
            for risk_type, patterns in category_dict.items():
                compiled[risk_type] = [
                    (re.compile(pattern, re.IGNORECASE), pattern) 
                    for pattern in patterns
                ]
        
        return compiled
    
    def scan_document(self, text: str) -> List[Dict]:
        """
        Main scanning function - detects all risky patterns in document.
        
        Args:
            text: Full document text
            
        Returns:
            List of flagged sections with metadata
        """
        flagged_sections = []
        lines = text.split('\n')
        
        # Scan each risk type
        for risk_type, compiled_list in self.compiled_patterns.items():
            for compiled_pattern, original_pattern in compiled_list:
                matches = compiled_pattern.finditer(text)
                
                for match in matches:
                    # Find line number
                    line_num = text[:match.start()].count('\n') + 1
                    
                    # Extract context (3 lines before and after)
                    context_start = max(0, line_num - 4)
                    context_end = min(len(lines), line_num + 3)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    # Determine severity
                    severity = self._calculate_severity(risk_type)
                    
                    # Determine category
                    category = self._get_category(risk_type)
                    
                    flagged_sections.append({
                        'risk_type': risk_type,
                        'pattern': original_pattern,
                        'matched_text': match.group(0),
                        'line_number': line_num,
                        'context': context,
                        'severity': severity,
                        'category': category,
                        'confidence': 0.7  # Base confidence for regex matches
                    })
        
        # Remove duplicates (same line, similar matches)
        flagged_sections = self._deduplicate_flags(flagged_sections)
        
        logger.info(f"✓ Pattern scanner found {len(flagged_sections)} potential risks")
        return flagged_sections
    
    def _calculate_severity(self, risk_type: str) -> str:
        """Assign severity based on risk type."""
        critical_risks = [
            'unlimited_liability', 'perpetual_obligations', 
            'automatic_transfer', 'foreign_only_jurisdiction'
        ]
        high_risks = [
            'broad_indemnity', 'auto_renewal', 'one_sided_termination',
            'broad_ip_assignment', 'unilateral_modification'
        ]
        medium_risks = [
            'overly_broad', 'broad_confidentiality', 'difficult_exit',
            'mandatory_arbitration', 'asymmetric_rights'
        ]
        
        if risk_type in critical_risks:
            return 'CRITICAL'
        elif risk_type in high_risks:
            return 'HIGH'
        elif risk_type in medium_risks:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_category(self, risk_type: str) -> str:
        """Map risk type to category."""
        category_map = {
            'unlimited_liability': 'Liability',
            'broad_indemnity': 'Liability',
            'perpetual_obligations': 'Duration',
            'auto_renewal': 'Duration',
            'vague_duration': 'Duration',
            'overly_broad': 'Scope',
            'broad_confidentiality': 'Scope',
            'one_sided_termination': 'Termination',
            'difficult_exit': 'Termination',
            'automatic_transfer': 'IP Rights',
            'broad_ip_assignment': 'IP Rights',
            'foreign_only_jurisdiction': 'Jurisdiction',
            'mandatory_arbitration': 'Jurisdiction',
            'asymmetric_rights': 'Imbalance',
            'unilateral_modification': 'Imbalance',
            'circular_definition': 'Definitions',
            'undefined_terms': 'Definitions'
        }
        return category_map.get(risk_type, 'Other')
    
    def _deduplicate_flags(self, flags: List[Dict]) -> List[Dict]:
        """Remove duplicate flags (same line or very similar matches)."""
        seen = set()
        unique_flags = []
        
        for flag in flags:
            # Create unique key based on line and risk type
            key = (flag['line_number'], flag['risk_type'])
            
            if key not in seen:
                seen.add(key)
                unique_flags.append(flag)
        
        return unique_flags


def scan_risky_patterns(document_text: str) -> Dict:
    """
    Convenience function for scanning document.
    
    Args:
        document_text: Full document text
        
    Returns:
        Dictionary with flagged sections and summary
    """
    detector = RiskPatternDetector()
    flags = detector.scan_document(document_text)
    
    # Create summary by category
    category_summary = {}
    for flag in flags:
        category = flag['category']
        if category not in category_summary:
            category_summary[category] = []
        category_summary[category].append(flag)
    
    return {
        'total_flags': len(flags),
        'flags': flags,
        'by_category': category_summary,
        'severity_counts': {
            'CRITICAL': len([f for f in flags if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in flags if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in flags if f['severity'] == 'MEDIUM']),
            'LOW': len([f for f in flags if f['severity'] == 'LOW'])
        }
    }