RISK_ANALYSIS_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://example.com/legal-risk-analysis.schema.json",
    "title": "Legal Document Risk Analysis Report",
    "description": "Schema for validating legal document risk assessment reports",
    "type": "object",
    "properties": {
        "metadata": {
            "type": "object",
            "description": "Metadata about the analysis",
            "properties": {
                "document_path": {"type": "string"},
                "analysis_date": {"type": "string", "format": "date-time"},
                "criteria": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1
                },
                "analysis_version": {"type": "string"}
            },
            "required": ["document_path", "analysis_date", "criteria"],
            "additionalProperties": True  # ✅ Changed from False
        },
        "summary": {
            "type": "string",
            "minLength": 1
        },
        "hidden_risks_detected": {
            "type": "array",
            "description": "Hidden traps and disguised risks found",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "primary_clause": {"type": "string"},
                    "real_meaning": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                    }
                },
                "required": ["name", "real_meaning", "severity"],
                "additionalProperties": True
            }
        },
        "detection_methodology": {
            "type": "object",
            "description": "Details about risk detection methods",
            "properties": {
                "regex_matches": {"type": "integer", "minimum": 0},
                "llm_confirmed": {"type": "integer", "minimum": 0},
                "false_positives_filtered": {"type": "integer", "minimum": 0},
                "definition_traps_found": {"type": "integer", "minimum": 0},
                "cross_reference_clusters": {"type": "integer", "minimum": 0}
            },
            "additionalProperties": True
        },
        "jurisdiction_intelligence": {
            "type": "object",
            "description": "Vendor and jurisdiction details",
            "additionalProperties": True
        },
        "indian_law_compliance": {
            "type": "object",
            "description": "Indian Contract Act compliance results",
            "properties": {
                "compliant_items": {"type": "array", "items": {"type": "string"}},
                "violations": {"type": "array", "items": {"type": "string"}},
                "risks": {"type": "array", "items": {"type": "string"}}
            },
            "additionalProperties": True
        },
        "company_policy_compliance": {
            "type": "object",
            "description": "10xds company policy compliance",
            "properties": {
                "blocking_violations": {"type": "array", "items": {"type": "string"}},
                "missing_protections": {"type": "array", "items": {"type": "string"}},
                "preference_gaps": {"type": "array", "items": {"type": "string"}}
            },
            "additionalProperties": True
        },
        "protections_found": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "clause": {"type": ["string", "null"]},
                    "evidence": {"type": ["string", "null"]}
                },
                "required": ["name"],
                "additionalProperties": True
            }
        },
        "protections_missing": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "risk": {"type": ["string", "null"]}
                },
                "required": ["name"],
                "additionalProperties": True
            }
        },
        "counter_proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "priority": {
                        "type": "string",
                        "enum": ["BLOCKING", "HIGH", "MEDIUM", "LOW"]
                    },
                    "current_issue": {"type": ["string", "null"]},
                    "suggested_clause": {"type": ["string", "null"]},
                    "benefit": {"type": ["string", "null"]}
                },
                "required": ["name"],
                "additionalProperties": True
            }
        },
        "risk_assessment": {
            "type": "object",
            "properties": {
                "risk_percentage": {"type": "integer", "minimum": 0, "maximum": 100},
                "risk_level": {
                    "type": "string",
                    "enum": ["LOW RISK", "MODERATE RISK", "HIGH RISK"]
                }
            },
            "required": ["risk_percentage", "risk_level"],
            "additionalProperties": True
        },
        "recommendation": {
            "type": "string",
            "minLength": 1
        },
        "validation": {
            "type": "object",
            "description": "Schema validation results",
            "properties": {
                "is_valid": {"type": "boolean"},
                "message": {"type": "string"}
            },
            "additionalProperties": True
        }
    },
    "required": [
        "metadata",
        "summary",
        "protections_found",
        "protections_missing",
        "counter_proposals",
        "risk_assessment",
        "recommendation"
    ],
    "additionalProperties": True 
}