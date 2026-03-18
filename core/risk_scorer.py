"""
NetWatch Device Risk Scorer.

Calculates a 0-100 risk score for each scanned device based on its findings.
Weights are loaded from data/risk_weights.json so they can be tuned without
changing code.

Score formula per finding:
    contribution = min(severity_weight * category_multiplier, max_per_finding)
Total device score = min(sum of contributions, 100)

Exports:
    RiskScorer: Main class
    DeviceRisk: Dataclass with score + band + label
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from core.findings import Finding, FindingRegistry, Severity

logger = logging.getLogger(__name__)

_DEFAULT_WEIGHTS_PATH = Path(__file__).parent.parent / "data" / "risk_weights.json"


def _load_weights(path: Path = _DEFAULT_WEIGHTS_PATH) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load risk_weights.json: {e}. Using defaults.")
        return {
            "severity_weights": {
                "CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0
            },
            "category_multipliers": {},
            "caps": {"max_per_finding": 30, "max_total": 100, "min_total": 0},
            "risk_bands": {
                "CRITICAL": {"min": 75, "label": "Critical Risk",  "color": "#dc2626"},
                "HIGH":     {"min": 50, "label": "High Risk",      "color": "#ea580c"},
                "MEDIUM":   {"min": 25, "label": "Medium Risk",    "color": "#d97706"},
                "LOW":      {"min": 10, "label": "Low Risk",       "color": "#2563eb"},
                "MINIMAL":  {"min": 0,  "label": "Minimal Risk",   "color": "#16a34a"},
            },
        }


@dataclass
class DeviceRisk:
    """Risk score and band for a single device."""
    host: str
    score: int                  # 0-100
    band: str                   # MINIMAL / LOW / MEDIUM / HIGH / CRITICAL
    label: str                  # human-readable band label
    color: str                  # hex colour for HTML reports
    finding_count: int = 0
    top_findings: List[Finding] = field(default_factory=list)

    @property
    def score_str(self) -> str:
        return f"{self.score}/100"


class RiskScorer:
    """Calculate per-device risk scores from Finding objects.

    Usage:
        scorer = RiskScorer()
        risks = scorer.score_all(finding_registry)
        for host, risk in risks.items():
            print(f"{host}: {risk.score}/100 ({risk.label})")
    """

    def __init__(self, weights_path: Optional[Path] = None):
        self._weights = _load_weights(weights_path or _DEFAULT_WEIGHTS_PATH)
        self._sev_weights: Dict[str, int] = self._weights.get("severity_weights", {})
        self._cat_mult: Dict[str, float] = self._weights.get("category_multipliers", {})
        caps = self._weights.get("caps", {})
        self._max_per = caps.get("max_per_finding", 30)
        self._max_total = caps.get("max_total", 100)
        bands_raw = self._weights.get("risk_bands", {})
        # Sort bands descending by min threshold for lookup
        self._bands = sorted(
            [(b, v) for b, v in bands_raw.items()],
            key=lambda x: x[1]["min"],
            reverse=True,
        )

    # ------------------------------------------------------------------

    def score_device(self, findings: List[Finding]) -> int:
        """Compute a 0-100 risk score for a list of findings from one device."""
        total = 0
        for f in findings:
            base = self._sev_weights.get(f.severity.value, 0)
            mult = self._cat_mult.get(f.category, 1.0)
            contribution = min(int(base * mult), self._max_per)
            total += contribution
        return min(total, self._max_total)

    def _get_band(self, score: int) -> tuple:
        """Return (band_name, label, color) for a score."""
        for band_name, band_data in self._bands:
            if score >= band_data["min"]:
                return band_name, band_data["label"], band_data["color"]
        return "MINIMAL", "Minimal Risk", "#16a34a"

    def score_host(self, host: str, findings: List[Finding]) -> DeviceRisk:
        """Score a single host."""
        score = self.score_device(findings)
        band, label, color = self._get_band(score)
        # Top findings = highest severity first, up to 5
        top = sorted(findings, key=lambda f: f.severity.order)[:5]
        return DeviceRisk(
            host=host,
            score=score,
            band=band,
            label=label,
            color=color,
            finding_count=len(findings),
            top_findings=top,
        )

    def score_all(self, registry: FindingRegistry) -> Dict[str, DeviceRisk]:
        """Score every host that has findings in the registry.

        Returns:
            Dict mapping IP → DeviceRisk, sorted by score descending.
        """
        host_findings: Dict[str, List[Finding]] = {}
        for f in registry.get_all(sort=False):
            host_findings.setdefault(f.host, []).append(f)

        results = {}
        for host, findings in host_findings.items():
            results[host] = self.score_host(host, findings)

        # Sort by score descending
        return dict(sorted(results.items(), key=lambda x: x[1].score, reverse=True))

    def network_summary(self, risks: Dict[str, DeviceRisk]) -> dict:
        """Return aggregate stats for the whole network."""
        if not risks:
            return {"avg_score": 0, "max_score": 0, "high_risk_count": 0, "total_devices": 0}
        scores = [r.score for r in risks.values()]
        return {
            "avg_score": round(sum(scores) / len(scores)),
            "max_score": max(scores),
            "high_risk_count": sum(1 for s in scores if s >= 50),
            "total_devices": len(scores),
        }
