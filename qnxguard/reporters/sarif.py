"""SARIF 2.1.0 reporter for GitHub Code Scanning & CI/CD pipelines."""
import json
from ..models import AuditReport

SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def to_sarif(report: AuditReport) -> str:
    rules_map = {}
    results = []
    for f in report.sorted_findings():
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "help": {"text": f.remediation},
                "helpUri": f.qnx_doc_ref or "https://www.qnx.com/developers/docs/8.0/",
                "properties": {"category": f.category, "severity": f.severity},
            }
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. {f.message} Fix: {f.remediation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "QNXGuard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/a415635511-alt/qnxguard",
                    "rules": list(rules_map.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
