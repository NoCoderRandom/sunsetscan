from core.findings import Finding, FindingRegistry, Severity
from core.risk_scorer import RiskScorer


def test_device_risk_scores_skip_network_level_findings():
    registry = FindingRegistry()
    registry.add(
        Finding(
            severity=Severity.INFO,
            title="DNS responses match trusted resolver",
            host="local",
            category="DNS Security",
            description="Network-level DNS check.",
            explanation="Informational.",
            recommendation="No action required.",
            port=53,
            protocol="udp",
        )
    )
    registry.add(
        Finding(
            severity=Severity.HIGH,
            title="SMB signing disabled",
            host="10.0.0.61",
            category="SMB",
            description="SMB signing is not required.",
            explanation="Traffic can be modified.",
            recommendation="Require SMB signing.",
            port=445,
            protocol="tcp",
        )
    )

    scores = RiskScorer().score_all(registry)

    assert "local" not in scores
    assert list(scores) == ["10.0.0.61"]
