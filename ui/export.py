"""
NetWatch Export Module.

Exports scan results to JSON and HTML formats.

HTML export uses a Jinja2 template (ui/templates/report.html.j2) to produce
a professional, self-contained report with:
  - Severity dashboard and summary badges
  - Per-host collapsible sections with finding cards
  - Plain-English descriptions and recommendations
  - Open ports table with EOL status
  - Prioritised recommendations summary

JSON export keeps the original structured format for machine-readable output.

Both formats remain backward-compatible with the existing scan pipeline.
New fields (findings) are additive — JSON export includes them in an
optional section.

Exports:
    ReportExporter: Main class (same interface as before, extended)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.settings import Settings, EOL_STATUS
from core.scanner import ScanResult, HostInfo
from eol.checker import EOLStatus, EOLStatusLevel

logger = logging.getLogger(__name__)


def _get_jinja_env():
    """Load Jinja2 environment pointing at ui/templates/."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        template_dir = Path(__file__).parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        return env
    except ImportError:
        return None


class ReportExporter:
    """Export scan results to JSON and HTML formats.

    Backward-compatible with existing netwatch.py calls.
    Extended to accept an optional FindingRegistry for enriched HTML reports.

    Example:
        exporter = ReportExporter()

        # Original usage (still works)
        exporter.export_json(scan_result, "report.json", eol_data=eol_results)
        exporter.export_html(scan_result, "report.html", eol_data=eol_results)

        # Extended usage with findings
        exporter.export_html(
            scan_result, "report.html",
            eol_data=eol_results,
            findings=finding_registry,
        )
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()

    # -------------------------------------------------------------------------
    # JSON Export (unchanged from original)
    # -------------------------------------------------------------------------

    def export_json(
        self,
        scan_result: ScanResult,
        filepath: str,
        eol_data: Optional[Dict[str, Dict[int, EOLStatus]]] = None,
        findings=None,  # Optional FindingRegistry
        device_identities=None,  # Optional Dict[str, DeviceIdentity]
    ) -> bool:
        """Export scan results to JSON format."""
        try:
            export_data = {
                "metadata": {
                    "tool": self.settings.tool_name,
                    "version": self.settings.version,
                    "generated_at": datetime.now().isoformat(),
                    "scan_target": scan_result.target,
                    "scan_profile": scan_result.profile,
                    "scan_duration_seconds": scan_result.duration,
                    "scan_start": scan_result.start_time.isoformat() if scan_result.start_time else None,
                    "scan_end": scan_result.end_time.isoformat() if scan_result.end_time else None,
                },
                "summary": {
                    "total_hosts": len(scan_result.hosts),
                    "hosts_up": sum(1 for h in scan_result.hosts.values() if h.state == "up"),
                    "total_ports": sum(len(h.ports) for h in scan_result.hosts.values()),
                },
                "hosts": [],
            }

            # EOL summary
            if eol_data:
                status_counts = {"CRITICAL": 0, "WARNING": 0, "OK": 0, "UNKNOWN": 0}
                for host_eol in eol_data.values():
                    for eol_status in host_eol.values():
                        status_counts[eol_status.level.value] += 1
                export_data["summary"]["eol_status"] = status_counts

            # Findings summary
            if findings is not None:
                export_data["summary"]["findings"] = findings.counts()
                export_data["findings"] = [f.to_dict() for f in findings.get_all()]

            # Device identities
            if device_identities:
                export_data["device_identities"] = {
                    ip: (did.to_dict() if hasattr(did, 'to_dict') else did)
                    for ip, did in device_identities.items()
                }

            # Host details
            for ip, host in scan_result.hosts.items():
                host_data = {
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "state": host.state,
                    "os_guess": host.os_guess,
                    "os_accuracy": host.os_accuracy,
                    "mac": host.mac,
                    "vendor": host.vendor,
                    "ports": [],
                }

                for port_num, port in sorted(host.ports.items()):
                    port_data = {
                        "port": port.port,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service": port.service,
                        "version": port.version,
                        "banner": port.banner,
                    }
                    if eol_data and ip in eol_data and port_num in eol_data[ip]:
                        eol = eol_data[ip][port_num]
                        port_data["eol"] = {
                            "status": eol.level.value,
                            "product": eol.product,
                            "version": eol.version,
                            "eol_date": eol.eol_date.isoformat() if eol.eol_date else None,
                            "days_remaining": eol.days_remaining,
                            "message": eol.message,
                        }
                    host_data["ports"].append(port_data)

                export_data["hosts"].append(host_data)

            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)

            logger.info(f"Exported JSON report to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Failed to export JSON: {e}")
            return False

    # -------------------------------------------------------------------------
    # HTML Export
    # -------------------------------------------------------------------------

    def export_html(
        self,
        scan_result: ScanResult,
        filepath: str,
        eol_data: Optional[Dict[str, Dict[int, EOLStatus]]] = None,
        findings=None,          # Optional FindingRegistry
        risk_scores=None,       # Optional Dict[str, DeviceRisk] from RiskScorer
        scan_diff=None,         # Optional ScanDiff from ScanHistory
        device_identities=None, # Optional Dict[str, DeviceIdentity]
    ) -> bool:
        """Export scan results to a professional HTML report.

        Uses Jinja2 template if available; falls back to legacy generator.
        """
        try:
            html = self._generate_html(scan_result, eol_data, findings,
                                       risk_scores=risk_scores, scan_diff=scan_diff,
                                       device_identities=device_identities)
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"Exported HTML report to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to export HTML: {e}")
            return False

    def _generate_html(
        self,
        scan_result: ScanResult,
        eol_data: Optional[Dict[str, Dict[int, EOLStatus]]],
        findings=None,
        risk_scores=None,
        scan_diff=None,
        device_identities=None,
    ) -> str:
        """Generate HTML. Uses Jinja2 template when available."""
        env = _get_jinja_env()
        if env:
            try:
                return self._render_jinja(env, scan_result, eol_data, findings,
                                          risk_scores=risk_scores, scan_diff=scan_diff,
                                          device_identities=device_identities)
            except Exception as e:
                logger.warning(f"Jinja2 render failed, falling back to legacy: {e}")

        return self._legacy_html(scan_result, eol_data)

    def _render_jinja(self, env, scan_result, eol_data, findings,
                      risk_scores=None, scan_diff=None, device_identities=None) -> str:
        """Render the Jinja2 report template."""
        template = env.get_template("report.html.j2")

        # Build metadata dict
        duration_secs = scan_result.duration
        if duration_secs >= 60:
            mins = int(duration_secs // 60)
            secs = int(duration_secs % 60)
            duration_str = f"{mins}m {secs}s"
        else:
            duration_str = f"{duration_secs:.1f}s"

        hosts_up = sum(1 for h in scan_result.hosts.values() if h.state == "up")
        total_open = sum(len(h.ports) for h in scan_result.hosts.values())

        # Build finding counts and per-host lookups
        from core.findings import Severity

        all_findings_sorted: List = []
        findings_by_host: Dict[str, List] = {}
        host_finding_counts: Dict[str, Dict[str, int]] = {}
        worst_severity: Dict[str, str] = {}
        counts: Dict[str, int] = {s.value: 0 for s in Severity}

        if findings is not None:
            all_findings_sorted = findings.get_all()
            counts = findings.counts()
            for host_ip in scan_result.hosts:
                hf = findings.get_for_host(host_ip)
                findings_by_host[host_ip] = hf
                hc = {s.value: 0 for s in Severity}
                for f in hf:
                    hc[f.severity.value] += 1
                host_finding_counts[host_ip] = hc
                ws = findings.worst_severity_for_host(host_ip)
                worst_severity[host_ip] = ws.value if ws else "INFO"
        else:
            # No findings registry — populate per-host empty
            for host_ip in scan_result.hosts:
                findings_by_host[host_ip] = []
                host_finding_counts[host_ip] = {s.value: 0 for s in Severity}
                worst_severity[host_ip] = "INFO"

        # Add port_display helper to findings via wrapper
        class FindingProxy:
            """Thin wrapper adding Jinja2-friendly properties."""
            def __init__(self, f):
                self._f = f
                for attr in ("severity", "title", "host", "port", "protocol",
                              "category", "description", "explanation",
                              "recommendation", "evidence", "cve_ids",
                              "cvss_score", "tags"):
                    setattr(self, attr, getattr(f, attr))
                # severity and confidence as strings for template
                self.severity = f.severity.value
                self.confidence = getattr(f, "confidence", None)
                if self.confidence is not None:
                    self.confidence = self.confidence.value
                self.port_display = f.port_display if f.port else ""

        wrapped_findings = [FindingProxy(f) for f in all_findings_sorted]
        wrapped_by_host = {
            ip: [FindingProxy(f) for f in flist]
            for ip, flist in findings_by_host.items()
        }

        metadata = {
            "network": scan_result.target,
            "scan_date": scan_result.start_time.strftime("%Y-%m-%d %H:%M:%S") if scan_result.start_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": duration_str,
            "profile": scan_result.profile,
            "version": self.settings.version,
            "total_hosts": len(scan_result.hosts),
            "hosts_up": hosts_up,
            "total_open_ports": total_open,
            "total_findings": sum(counts.values()),
        }

        # Build executive summary in plain English
        executive_summary = self._build_executive_summary(
            counts, scan_result, risk_scores,
            findings=findings, scan_diff=scan_diff,
        )

        # Build device identity proxies for template
        did_for_template = {}
        if device_identities:
            for ip, did in device_identities.items():
                did_for_template[ip] = did.to_dict() if hasattr(did, 'to_dict') else did

        return template.render(
            metadata=metadata,
            counts=counts,
            hosts=scan_result.hosts,
            all_findings=wrapped_findings,
            findings_by_host=wrapped_by_host,
            host_finding_counts=host_finding_counts,
            worst_severity=worst_severity,
            eol_data=eol_data or {},
            risk_scores=risk_scores or {},
            scan_diff=scan_diff,
            executive_summary=executive_summary,
            device_identities=did_for_template,
        )

    def _build_executive_summary(self, counts: dict, scan_result, risk_scores,
                                   findings=None, scan_diff=None) -> dict:
        """Generate plain-English executive summary from scan data."""
        hosts_up = sum(1 for h in scan_result.hosts.values() if h.state == "up")
        total = sum(counts.values())
        c = counts.get("CRITICAL", 0)
        h = counts.get("HIGH", 0)
        m = counts.get("MEDIUM", 0)
        lo = counts.get("LOW", 0)

        # Determine network posture
        if c > 0:
            headline = f"Immediate action required — {c} critical issue(s) detected"
            posture = "critical"
        elif h > 0:
            headline = f"High-risk issues found — {h} item(s) require prompt attention"
            posture = "high"
        elif m > 0:
            headline = f"Moderate security posture — {m} medium-risk issue(s) identified"
            posture = "medium"
        elif total > 0:
            headline = "Good security posture — only minor issues found"
            posture = "low"
        else:
            headline = "Network appears secure — no significant issues found"
            posture = "clean"

        # Device breakdown
        device_list = []
        for ip, host in scan_result.hosts.items():
            if host.state == "up":
                label = host.vendor or host.os_guess or ip
                device_list.append(f"{ip} ({label})" if label != ip else ip)

        overview = (
            f"NetWatch scanned {hosts_up} active device(s) on {scan_result.target} "
            f"using the {scan_result.profile} profile and found {total} security finding(s). "
        )
        if device_list:
            overview += f"Devices online: {', '.join(device_list[:5])}"
            if len(device_list) > 5:
                overview += f" and {len(device_list) - 5} more"
            overview += "."

        top_issues = []
        if c > 0:
            top_issues.append(f"{c} critical finding(s) — requires immediate remediation")
        if h > 0:
            top_issues.append(f"{h} high-severity finding(s) — remediate within 7 days")
        if m > 0:
            top_issues.append(f"{m} medium-severity finding(s) — schedule for next maintenance window")
        if lo > 0:
            top_issues.append(f"{lo} low-severity finding(s) — address when convenient")

        # Highlight specific critical/high finding types
        if findings is not None:
            from core.findings import Severity
            crit_cats = {}
            for f in findings.get_all():
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    crit_cats[f.category] = crit_cats.get(f.category, 0) + 1
            for cat, cnt in sorted(crit_cats.items(), key=lambda x: -x[1])[:3]:
                top_issues.append(f"Category with most issues: {cat} ({cnt} finding(s))")

        if risk_scores:
            worst_device = max(risk_scores.values(), key=lambda r: r.score)
            if worst_device.score >= 25:
                top_issues.append(
                    f"Highest-risk device: {worst_device.host} — Risk score {worst_device.score}/100 ({worst_device.label})"
                )

        # Changes since last scan
        fixed_count = 0
        new_count = 0
        if scan_diff:
            try:
                new_count = len(getattr(scan_diff, 'new_findings', []))
                fixed_count = len(getattr(scan_diff, 'resolved_findings', []))
            except Exception:
                pass
        if fixed_count > 0:
            top_issues.append(f"{fixed_count} finding(s) resolved since last scan")
        if new_count > 0:
            top_issues.append(f"{new_count} new finding(s) since last scan")

        if c > 0:
            recommendation = (
                "Immediately address critical findings: change default credentials, "
                "disable SMBv1, and apply available security patches. "
                "Isolate any device with a CRITICAL finding until remediated."
            )
        elif h > 0:
            recommendation = (
                "Review high-severity findings and apply firmware updates or configuration "
                "changes within the week. Focus on SMB signing, EOL software, and open admin interfaces."
            )
        elif m > 0:
            recommendation = (
                "Schedule medium-severity remediations for the next maintenance window. "
                "Review SSL/TLS configurations, disable unused services, and update firmware."
            )
        else:
            recommendation = (
                "Network security posture is good. Continue monitoring for new devices, "
                "apply firmware updates regularly, and re-scan monthly or after network changes."
            )

        return {
            "headline": headline,
            "posture": posture,
            "overview": overview,
            "top_issues": top_issues,
            "recommendation": recommendation,
            "fixed_count": fixed_count,
            "new_count": new_count,
        }

    def _legacy_html(self, scan_result: ScanResult, eol_data) -> str:
        """Fallback HTML generator used when Jinja2 is unavailable.

        Produces a simpler but still usable report.
        """
        css = """<style>
        body{font-family:sans-serif;color:#333;background:#f5f5f5;padding:20px;}
        .container{max-width:1200px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden;}
        header{background:linear-gradient(135deg,#1e3c72,#2a5298);color:#fff;padding:30px;text-align:center;}
        header h1{font-size:2em;margin-bottom:8px;}
        .meta{background:#f8f9fa;padding:16px 24px;border-bottom:1px solid #e9ecef;display:flex;flex-wrap:wrap;gap:20px;font-size:.85em;}
        .meta span b{display:block;font-size:1em;}
        .summary{padding:20px 24px;display:flex;flex-wrap:wrap;gap:12px;}
        .card{padding:16px 20px;border-radius:8px;text-align:center;min-width:100px;}
        .card .n{font-size:1.8em;font-weight:700;display:block;}
        .card.info{background:#e0e7ff;color:#4f46e5;}
        .card.critical{background:#fee2e2;color:#dc2626;}
        .card.warning{background:#fef3c7;color:#d97706;}
        .card.ok{background:#d1fae5;color:#059669;}
        .content{padding:24px;}
        h2{color:#1e3c72;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #e9ecef;}
        table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:.85em;}
        th{background:#f8f9fa;padding:10px 12px;text-align:left;font-weight:600;border-bottom:2px solid #dee2e6;}
        td{padding:10px 12px;border-bottom:1px solid #e9ecef;}
        tr:hover{background:#f8f9fa;}
        .status{padding:3px 10px;border-radius:12px;font-size:.8em;font-weight:700;}
        .status.critical{background:#fee2e2;color:#dc2626;}
        .status.warning{background:#fef3c7;color:#d97706;}
        .status.ok{background:#d1fae5;color:#059669;}
        .status.unknown{background:#f3f4f6;color:#6b7280;}
        footer{background:#f8f9fa;padding:16px;text-align:center;color:#6c757d;font-size:.85em;}
        </style>"""

        total_hosts = len(scan_result.hosts)
        hosts_up = sum(1 for h in scan_result.hosts.values() if h.state == "up")
        total_ports = sum(len(h.ports) for h in scan_result.hosts.values())
        eol_counts = {"CRITICAL": 0, "WARNING": 0, "OK": 0, "UNKNOWN": 0}
        if eol_data:
            for host_eol in eol_data.values():
                for eol_status in host_eol.values():
                    eol_counts[eol_status.level.value] += 1

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>NetWatch Report — {scan_result.target}</title>{css}</head><body>
<div class="container">
<header><h1>NetWatch Security Report</h1><p>{scan_result.target}</p></header>
<div class="meta">
  <span><b>{now}</b>Generated</span>
  <span><b>{scan_result.profile}</b>Profile</span>
  <span><b>{scan_result.duration:.1f}s</b>Duration</span>
  <span><b>v{self.settings.version}</b>NetWatch</span>
</div>
<div class="summary">
  <div class="card info"><span class="n">{total_hosts}</span>Hosts Scanned</div>
  <div class="card info"><span class="n">{hosts_up}</span>Online</div>
  <div class="card info"><span class="n">{total_ports}</span>Open Ports</div>
  <div class="card critical"><span class="n">{eol_counts['CRITICAL']}</span>EOL Critical</div>
  <div class="card warning"><span class="n">{eol_counts['WARNING']}</span>EOL Warning</div>
  <div class="card ok"><span class="n">{eol_counts['OK']}</span>EOL OK</div>
</div>
<div class="content"><h2>Scan Results</h2>
<table><thead><tr><th>IP</th><th>Hostname</th><th>Port</th><th>Service</th><th>Version</th><th>EOL Status</th><th>EOL Date</th></tr></thead><tbody>"""

        for ip, host in scan_result.hosts.items():
            if not host.ports:
                html += f"<tr><td>{ip}</td><td>{host.hostname or '—'}</td><td colspan='5'>Online — no open ports</td></tr>"
                continue
            for port_num, port in sorted(host.ports.items()):
                eol_status = None
                if eol_data and ip in eol_data and port_num in eol_data[ip]:
                    eol_status = eol_data[ip][port_num]
                if eol_status:
                    sc = eol_status.level.value.lower()
                    eol_date_str = eol_status.eol_date.strftime("%Y-%m-%d") if eol_status.eol_date else "—"
                    status_text = eol_status.level.value
                else:
                    sc, eol_date_str, status_text = "unknown", "—", "UNKNOWN"
                html += (
                    f"<tr><td>{ip}</td><td>{host.hostname or '—'}</td>"
                    f"<td>{port.port}</td><td>{port.service or '—'}</td>"
                    f"<td>{port.version or '—'}</td>"
                    f"<td><span class='status {sc}'>{status_text}</span></td>"
                    f"<td>{eol_date_str}</td></tr>"
                )

        html += f"""</tbody></table></div>
<footer>Generated by NetWatch v{self.settings.version} | {now} | This report is for authorised use only.</footer>
</div></body></html>"""
        return html

    # -------------------------------------------------------------------------
    # Generic export dispatcher
    # -------------------------------------------------------------------------

    def export(
        self,
        format_type: str,
        scan_result: ScanResult,
        filepath: str,
        eol_data: Optional[Dict[str, Dict[int, EOLStatus]]] = None,
        findings=None,
        risk_scores=None,
        scan_diff=None,
        device_identities=None,
    ) -> bool:
        """Export in the specified format (json or html)."""
        if format_type.lower() == "json":
            return self.export_json(scan_result, filepath, eol_data, findings,
                                    device_identities=device_identities)
        elif format_type.lower() == "html":
            return self.export_html(scan_result, filepath, eol_data, findings,
                                    risk_scores=risk_scores, scan_diff=scan_diff,
                                    device_identities=device_identities)
        else:
            logger.error(f"Unknown export format: {format_type}")
            return False
