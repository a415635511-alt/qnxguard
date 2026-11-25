"""Core finding & report data models for QNXGuard."""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_WEIGHT = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    file: str
    line: int
    snippet: str
    message: str
    remediation: str
    qnx_doc_ref: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    target_dir: str
    qnx_target_version: str = "8.0"
    files_scanned: int = 0
    buildfiles_scanned: int = 0
    c_files_scanned: int = 0
    toolchain_files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def counts_by_severity(self) -> Dict[str, int]:
        counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line, f.rule_id),
        )

    def max_severity_rank(self) -> int:
        if not self.findings:
            return -1
        return max(SEVERITY_ORDER.get(f.severity, 0) for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "QNXGuard",
            "version": "1.0.0",
            "qnx_target_version": self.qnx_target_version,
            "target_dir": self.target_dir,
            "score": self.score,
            "summary": {
                "files_scanned": self.files_scanned,
                "buildfiles_scanned": self.buildfiles_scanned,
                "c_files_scanned": self.c_files_scanned,
                "toolchain_files_scanned": self.toolchain_files_scanned,
                "total_findings": len(self.findings),
                "by_severity": self.counts_by_severity,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
