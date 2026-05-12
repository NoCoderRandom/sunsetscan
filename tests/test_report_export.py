from core.findings import Finding, FindingRegistry, Severity
from core.risk_scorer import RiskScorer
from core.scanner import HostInfo, PortInfo, ScanResult
from ui.export import ReportExporter


def test_html_report_includes_no_action_recommendations_section(tmp_path):
    scan = ScanResult(target="192.168.1.0/24", profile="PING")
    scan.hosts["192.168.1.1"] = HostInfo(ip="192.168.1.1", state="up")

    findings = FindingRegistry()
    findings.add(
        Finding(
            severity=Severity.INFO,
            title="Device identified",
            host="192.168.1.1",
            category="Device Identification",
            description="Device identity was detected.",
            explanation="Informational finding only.",
            recommendation="No action required.",
        )
    )

    path = tmp_path / "report.html"
    assert ReportExporter().export_html(scan, str(path), findings=findings)

    html = path.read_text(encoding="utf-8")
    assert "Recommended Actions" in html
    assert "No critical, high, or medium remediation actions were found" in html


def test_html_report_orders_hosts_and_ports_numerically(tmp_path):
    scan = ScanResult(target="192.168.1.0/24", profile="QUICK")
    scan.hosts["192.168.1.10"] = HostInfo(ip="192.168.1.10", state="up")
    scan.hosts["192.168.1.2"] = HostInfo(ip="192.168.1.2", state="up")
    scan.hosts["192.168.1.1"] = HostInfo(ip="192.168.1.1", state="up")
    scan.hosts["192.168.1.2"].ports[8080] = PortInfo(port=8080, service="http-alt")
    scan.hosts["192.168.1.2"].ports[22] = PortInfo(port=22, service="ssh")
    scan.hosts["192.168.1.2"].ports[80] = PortInfo(port=80, service="http")

    path = tmp_path / "report.html"
    assert ReportExporter().export_html(scan, str(path))

    html = path.read_text(encoding="utf-8")
    assert html.index('<div class="topo-device-ip">192.168.1.1</div>') < html.index(
        '<div class="topo-device-ip">192.168.1.2</div>'
    )
    assert html.index('<div class="topo-device-ip">192.168.1.2</div>') < html.index(
        '<div class="topo-device-ip">192.168.1.10</div>'
    )

    host_section = html[html.index('id="host-192-168-1-2"'):]
    assert host_section.index("<td>22</td>") < host_section.index("<td>80</td>")
    assert host_section.index("<td>80</td>") < host_section.index("<td>8080</td>")


def test_html_report_separates_network_level_checks_from_device_findings(tmp_path):
    scan = ScanResult(target="192.168.1.0/24", profile="SMB")
    scan.hosts["192.168.1.1"] = HostInfo(ip="192.168.1.1", state="up")

    findings = FindingRegistry()
    findings.add(
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

    path = tmp_path / "report.html"
    risk_scores = RiskScorer().score_all(findings)
    assert ReportExporter().export_html(
        scan,
        str(path),
        findings=findings,
        risk_scores=risk_scores,
    )

    html = path.read_text(encoding="utf-8")
    assert "found no device findings; 1 network-level check(s) were recorded" in html
    assert "Device Risk Scores" not in html
    assert 'title="Network-level finding"' in html
