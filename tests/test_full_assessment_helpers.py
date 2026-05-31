from datetime import datetime
from types import SimpleNamespace

from config.settings import Settings, load_user_settings, save_user_settings
from core.auth_tester import AuthTester
from core.findings import Finding, FindingRegistry, Severity
from core.risk_scorer import RiskScorer
from core.scanner import HostInfo, ScanResult
from ui.export import ReportExporter
from sunsetscan import SunsetScan


class _SilentConsole:
    def print(self, *args, **kwargs):
        pass


def test_full_assessment_scan_target_uses_discovered_hosts_only():
    hosts = SunsetScan._normalise_discovered_hosts(
        {"192.168.1.10", "192.168.1.2", "192.168.1.1"},
        excluded_hosts=("192.168.1.1",),
    )

    assert hosts == ["192.168.1.2", "192.168.1.10"]
    assert (
        SunsetScan._scan_target_for_discovered_hosts(hosts, "192.168.1.0/24")
        == "192.168.1.2 192.168.1.10"
    )


def test_discovery_only_scan_result_keeps_hosts_visible():
    result = SunsetScan._discovery_only_scan_result(
        target="192.168.1.0/24",
        profile="STEALTH",
        discovered_hosts=["192.168.1.2", "192.168.1.10"],
        start_time=datetime(2026, 5, 12, 7, 0, 0),
    )

    assert result.target == "192.168.1.0/24"
    assert result.profile == "STEALTH"
    assert sorted(result.hosts) == ["192.168.1.10", "192.168.1.2"]
    assert all(host.state == "up" for host in result.hosts.values())


def test_menu_full_assessment_can_enable_default_password_audit(monkeypatch):
    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings()
    app.console = _SilentConsole()
    app.auth_tester = None
    app.nse_scanner = None
    app.get_target = lambda: "192.168.1.0/24"

    captured = {}
    app.run_full_assessment = lambda target: captured.update(
        target=target,
        auth_enabled=app.auth_tester.enabled,
        nse_enabled=app.nse_scanner is not None,
    )

    monkeypatch.setattr("sunsetscan.Confirm.ask", lambda *a, **k: True)

    SunsetScan._run_full_assessment_from_menu(app)

    assert captured == {
        "target": "192.168.1.0/24",
        "auth_enabled": True,
        "nse_enabled": True,
    }


def test_menu_full_assessment_can_disable_existing_default_password_audit(monkeypatch):
    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings()
    app.console = _SilentConsole()
    app.auth_tester = type("EnabledAuth", (), {"enabled": True})()
    app.nse_scanner = None
    app.get_target = lambda: "192.168.1.0/24"

    captured = {}
    app.run_full_assessment = lambda target: captured.update(
        target=target,
        auth_enabled=app.auth_tester.enabled,
        nse_enabled=app.nse_scanner is not None,
    )

    def answer_no(*args, **kwargs):
        captured["prompt_default"] = kwargs["default"]
        return False

    monkeypatch.setattr("sunsetscan.Confirm.ask", answer_no)

    SunsetScan._run_full_assessment_from_menu(app)

    assert captured == {
        "prompt_default": True,
        "target": "192.168.1.0/24",
        "auth_enabled": False,
        "nse_enabled": True,
    }


def test_settings_preserves_custom_common_ports():
    settings = Settings(common_ports=[80, 443, 9443])

    assert settings.common_ports == [80, 443, 9443]


def test_get_target_prefers_saved_default_target(monkeypatch):
    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings(default_target="127.0.0.1")
    captured = {}

    def prompt_target(default):
        captured["default"] = default
        return default

    app.menu = SimpleNamespace(prompt_target=prompt_target)
    monkeypatch.setattr("sunsetscan.get_local_subnet", lambda: "192.168.50.0/24")

    assert SunsetScan.get_target(app) == "127.0.0.1"
    assert captured["default"] == "127.0.0.1"


def test_get_target_uses_local_subnet_for_factory_default(monkeypatch):
    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings()
    captured = {}

    def prompt_target(default):
        captured["default"] = default
        return default

    app.menu = SimpleNamespace(prompt_target=prompt_target)
    monkeypatch.setattr("sunsetscan.get_local_subnet", lambda: "192.168.50.0/24")

    assert SunsetScan.get_target(app) == "192.168.50.0/24"
    assert captured["default"] == "192.168.50.0/24"


def test_network_discovery_scope_detects_single_host_vs_network():
    assert SunsetScan._target_allows_network_discovery("127.0.0.1") is False
    assert SunsetScan._target_allows_network_discovery("192.168.50.80") is False
    assert SunsetScan._target_allows_network_discovery("192.168.50.0/24") is True
    assert SunsetScan._target_allows_network_discovery("192.168.50.*") is True


def test_scan_risk_scores_are_limited_to_scanned_hosts():
    app = SunsetScan.__new__(SunsetScan)
    app.finding_registry = FindingRegistry()
    app.risk_scorer = RiskScorer()

    app.finding_registry.add(Finding(
        severity=Severity.HIGH,
        title="Scanned host issue",
        host="127.0.0.1",
        category="Test",
        description="",
        explanation="",
        recommendation="",
    ))
    app.finding_registry.add(Finding(
        severity=Severity.HIGH,
        title="Out of scope issue",
        host="192.168.50.61",
        category="Test",
        description="",
        explanation="",
        recommendation="",
    ))

    scan = ScanResult(target="127.0.0.1", profile="QUICK")
    scan.hosts["127.0.0.1"] = HostInfo(ip="127.0.0.1", state="up")

    scores = SunsetScan._score_scan_risks(app, scan)

    assert list(scores) == ["127.0.0.1"]


def test_user_settings_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    settings = Settings(
        auto_export_html_reports=True,
        auto_export_html_dir=str(tmp_path / "reports"),
        default_password_audit_enabled=True,
        nse_scripts_enabled=True,
        common_ports=[80, 443, 9443],
        excluded_hosts=("127.0.0.2",),
    )

    save_user_settings(settings, path)
    loaded = load_user_settings(path)

    assert loaded.auto_export_html_reports is True
    assert loaded.auto_export_html_dir == str(tmp_path / "reports")
    assert loaded.default_password_audit_enabled is True
    assert loaded.nse_scripts_enabled is True
    assert loaded.common_ports == [80, 443, 9443]
    assert loaded.excluded_hosts == ("127.0.0.2",)


def test_settings_menu_can_toggle_password_audit(monkeypatch):
    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings()
    app.console = _SilentConsole()
    app.auth_tester = None
    app.args = SimpleNamespace(no_color=True)
    app.nse_scanner = None

    monkeypatch.setattr("sunsetscan.save_user_settings", lambda *a, **k: None)

    app._toggle_default_password_audit()

    assert app.auth_tester.enabled is True
    assert app.settings.default_password_audit_enabled is True

    app._toggle_default_password_audit()

    assert app.auth_tester.enabled is False
    assert app.settings.default_password_audit_enabled is False


def test_settings_menu_can_enable_auto_html_reports(monkeypatch):
    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings()
    app.console = _SilentConsole()
    app.args = SimpleNamespace(no_color=True)
    app.nse_scanner = None
    app.auth_tester = AuthTester(settings=app.settings, enabled=False)

    monkeypatch.setattr("sunsetscan.Confirm.ask", lambda *a, **k: True)
    monkeypatch.setattr("sunsetscan.save_user_settings", lambda *a, **k: None)

    app._prompt_update_setting("auto_export_html_reports")

    assert app.settings.auto_export_html_reports is True


def test_auto_html_report_writes_to_configured_directory(monkeypatch, tmp_path):
    scan = SunsetScan._discovery_only_scan_result(
        target="192.168.1.0/24",
        profile="QUICK",
        discovered_hosts=["192.168.1.2"],
        start_time=datetime(2026, 5, 12, 7, 0, 0),
    )

    app = SunsetScan.__new__(SunsetScan)
    app.settings = Settings(auto_export_html_reports=True, auto_export_html_dir=str(tmp_path))
    app.console = _SilentConsole()
    app.exporter = ReportExporter(settings=app.settings)
    app.last_eol_data = {}
    app.finding_registry = None
    app.last_risk_scores = {}
    app.last_device_identities = {}

    app._auto_export_html_report(scan)

    reports = list(tmp_path.glob("sunsetscan_quick_*.html"))
    assert len(reports) == 1
