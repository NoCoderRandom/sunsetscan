"""
NetWatch Findings Module.

Central definition of the Finding dataclass, severity levels, and
the FindingRegistry that collects all findings across all scan modules.

Every security check in NetWatch produces Finding objects. These are
collected in the FindingRegistry and consumed by the report exporter.

Severity levels:
    CRITICAL - Immediate risk: default creds accepted, active CVE exploit
    HIGH     - Significant risk: Telnet open, expired cert, SMB guest access
    MEDIUM   - Notable risk: self-signed cert, UPnP exposed, directory listing
    LOW      - Minor concern: EOL approaching, non-standard open ports
    INFO     - Informational: device identified, OS detected, service banner
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Confidence(Enum):
    """How certain we are that a finding is a real issue.

    Used to prevent false positives and help analysts triage.
    CONFIRMED  — verified by direct evidence (e.g. redirect to dashboard after login)
    LIKELY     — multiple independent positive signals, no contradicting evidence
    SUSPECTED  — single weak indicator; manual verification recommended
    UNCONFIRMED — automated probe could not determine outcome
    """
    CONFIRMED   = "CONFIRMED"
    LIKELY      = "LIKELY"
    SUSPECTED   = "SUSPECTED"
    UNCONFIRMED = "UNCONFIRMED"

    @property
    def score(self) -> int:
        """Numeric confidence score (0-100)."""
        return {
            "CONFIRMED": 95,
            "LIKELY": 80,
            "SUSPECTED": 55,
            "UNCONFIRMED": 30,
        }[self.value]

    @property
    def css_class(self) -> str:
        return {
            "CONFIRMED": "confidence-confirmed",
            "LIKELY": "confidence-likely",
            "SUSPECTED": "confidence-suspected",
            "UNCONFIRMED": "confidence-unconfirmed",
        }[self.value]


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def order(self) -> int:
        """Lower number = higher severity (for sorting)."""
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    @property
    def css_class(self) -> str:
        return self.value.lower()

    @property
    def color_hex(self) -> str:
        return {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }[self.value]

    @property
    def bg_hex(self) -> str:
        return {
            "CRITICAL": "#fee2e2",
            "HIGH": "#ffedd5",
            "MEDIUM": "#fef3c7",
            "LOW": "#dbeafe",
            "INFO": "#f3f4f6",
        }[self.value]

    @property
    def label(self) -> str:
        return self.value


@dataclass
class Finding:
    """A single security finding from any check module.

    Attributes:
        severity:       Impact level of this finding.
        title:          Short one-line title (< 80 chars).
        host:           IP address this finding applies to.
        category:       Grouping label (Authentication, SSL/TLS, CVE, etc.).
        description:    Technical detail — what was found and where.
        explanation:    Plain English for non-technical readers.
        recommendation: Numbered action steps to remediate.
        port:           Port number (0 = host-level finding).
        protocol:       Protocol string (tcp/udp/http/https/etc.).
        evidence:       Raw evidence or data that triggered this finding.
        cve_ids:        Associated CVE identifiers.
        cvss_score:     CVSS base score if known.
        tags:           Extra labels for filtering (e.g. "insecure-protocol").
    """
    severity: Severity
    title: str
    host: str
    category: str
    description: str
    explanation: str
    recommendation: str
    port: int = 0
    protocol: str = ""
    evidence: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.CONFIRMED

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (for JSON export)."""
        return {
            "severity": self.severity.value,
            "title": self.title,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "category": self.category,
            "description": self.description,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "tags": self.tags,
            "confidence": self.confidence.value,
        }

    @property
    def port_display(self) -> str:
        """Human-readable port/protocol string."""
        if self.port and self.protocol:
            return f"{self.port}/{self.protocol.upper()}"
        if self.port:
            return str(self.port)
        return "—"


class FindingRegistry:
    """Central registry that collects all findings for a scan session.

    Usage:
        registry = FindingRegistry()
        registry.add(Finding(...))
        findings = registry.get_all()          # sorted by severity
        host_findings = registry.get_for_host("192.168.1.1")
        counts = registry.counts()             # {'CRITICAL': 2, 'HIGH': 5, ...}
    """

    def __init__(self):
        self._findings: List[Finding] = []

    def add(self, finding: Finding) -> None:
        """Add a single finding."""
        self._findings.append(finding)

    def add_all(self, findings: List[Finding]) -> None:
        """Add a list of findings."""
        self._findings.extend(findings)

    def get_all(self, sort: bool = True) -> List[Finding]:
        """Return all findings, optionally sorted by severity then host."""
        if sort:
            return sorted(self._findings, key=lambda f: (f.severity.order, f.host, f.port))
        return list(self._findings)

    def get_for_host(self, host: str) -> List[Finding]:
        """Return all findings for a specific host IP, sorted by severity."""
        findings = [f for f in self._findings if f.host == host]
        return sorted(findings, key=lambda f: f.severity.order)

    def get_by_severity(self, severity: Severity) -> List[Finding]:
        """Return all findings of a specific severity level."""
        return [f for f in self._findings if f.severity == severity]

    def get_by_category(self, category: str) -> List[Finding]:
        """Return all findings in a specific category."""
        return [f for f in self._findings if f.category == category]

    def counts(self) -> Dict[str, int]:
        """Return count of findings per severity level."""
        result: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._findings:
            result[f.severity.value] += 1
        return result

    def total(self) -> int:
        """Total number of findings."""
        return len(self._findings)

    def has_findings(self) -> bool:
        return len(self._findings) > 0

    def host_list(self) -> List[str]:
        """Sorted list of unique hosts that have findings."""
        return sorted(set(f.host for f in self._findings))

    def worst_severity_for_host(self, host: str) -> Optional[Severity]:
        """Return the worst (highest) severity level seen for a host."""
        host_findings = self.get_for_host(host)
        if not host_findings:
            return None
        return host_findings[0].severity  # Already sorted by severity.order

    def clear(self) -> None:
        self._findings.clear()

    def deduplicate(self) -> None:
        """Remove findings with duplicate (host, port, title) combinations."""
        seen = set()
        unique: List[Finding] = []
        for f in self._findings:
            key = (f.host, f.port, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self._findings = unique

    def __len__(self) -> int:
        return len(self._findings)

    def __repr__(self) -> str:
        counts = self.counts()
        return (
            f"FindingRegistry(total={self.total()}, "
            f"critical={counts['CRITICAL']}, high={counts['HIGH']}, "
            f"medium={counts['MEDIUM']}, low={counts['LOW']}, info={counts['INFO']})"
        )
