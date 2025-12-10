"""
Extended JSON Schema for Hidden Risk Detection
Adds new fields to existing risk_schema.py
"""

HIDDEN_RISK_EXTENSION = {
    "hidden_risks_detected": {
        "type": "object",
        "properties": {
            "definitional_traps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "term": {"type": "string"},
                        "definition": {"type": "string"},
                        "risk_reason": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                        }
                    }
                }
            },

            "cross_reference_traps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "primary_clause": {"type": "string"},
                        "referenced_clauses": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "hidden_mechanism": {"type": "string"},
                        "real_meaning": {"type": "string"},
                        "severity": {"type": "string"}
                    }
                }
            },

            "regex_detected_risks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "risk_type": {"type": "string"},
                        "matched_text": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "context": {"type": "string"},
                        "severity": {"type": "string"},
                        "llm_confirmed": {"type": "boolean"}
                    }
                }
            },

            "combined_risks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "risk_combination": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "amplification_factor": {"type": "number"},
                        "explanation": {"type": "string"},
                        "overall_severity": {"type": "string"}
                    }
                }
            }
        }
    },

    "detection_methodology": {
        "type": "object",
        "properties": {
            "regex_matches": {"type": "integer"},
            "llm_confirmed": {"type": "integer"},
            "false_positives_filtered": {"type": "integer"},
            "definition_traps_found": {"type": "integer"},
            "cross_reference_clusters": {"type": "integer"}
        }
    }
}
