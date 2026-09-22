from config.settings import Settings
from core.scanner import HostInfo, ScanResult
from core.port_scanner import PortScanOrchestrator
from eol.checker import EOLStatus, EOLStatusLevel
from ui.interactive_controller import DiscoveredHost, InteractiveController


def test_interactive_controller_uses_shared_port_orchestrator():
    controller = InteractiveController(settings=Settings(safe_mode=True), no_color=True)

    assert isinstance(controller.scanner, PortScanOrchestrator)
    assert controller.scanner._settings.safe_mode is True


def test_settings_menu_replaces_frozen_settings_and_rebuilds_components(monkeypatch):
    controller = InteractiveController(settings=Settings(), no_color=True)
    answers = iter(["3", "7"])

    monkeypatch.setattr(
        "ui.interactive_controller.Prompt.ask",
        lambda *args, **kwargs: next(answers),
    )

    controller.settings_menu()

    assert controller.settings.banner_timeout == 7
    assert controller.scanner._settings.banner_timeout == 7
    assert controller.banner_grabber.timeout == 7


def test_initial_target_prompt_accepts_quit(monkeypatch):
    controller = InteractiveController(settings=Settings(), no_color=True)

    monkeypatch.setattr(
        "ui.interactive_controller.Prompt.ask",
        lambda *args, **kwargs: "q",
    )

    assert controller.get_target_from_user() is False
    assert controller._user_requested_exit is True


def test_tui_full_assessment_preserves_safe_mode_flags(monkeypatch):
    import sunsetscan

    captured = {}

    class FakeSunsetScan:
        def __init__(self, args):
            captured["args"] = args

        def run_full_assessment(self, target):
            captured["target"] = target
            return 0

    monkeypatch.setattr(sunsetscan, "SunsetScan", FakeSunsetScan)
    monkeypatch.setattr("ui.interactive_controller.Confirm.ask", lambda *a, **k: True)
    controller = InteractiveController(settings=Settings(safe_mode=True), no_color=True)
    controller.current_target = "10.0.0.0/24"

    controller.run_full_assessment()

    assert captured["target"] == "10.0.0.0/24"
    assert captured["args"].safe_mode is True
    assert captured["args"].no_safe_mode is False
    assert captured["args"].nse is True
    assert captured["args"].check_defaults is True


def test_tui_full_assessment_preserves_no_safe_mode_flag(monkeypatch):
    import sunsetscan

    captured = {}

    class FakeSunsetScan:
        def __init__(self, args):
            captured["args"] = args

        def run_full_assessment(self, target):
            return 0

    monkeypatch.setattr(sunsetscan, "SunsetScan", FakeSunsetScan)
    monkeypatch.setattr("ui.interactive_controller.Confirm.ask", lambda *a, **k: False)
    controller = InteractiveController(
        settings=Settings(),
        disable_safe_mode=True,
        no_color=True,
    )
    controller.current_target = "192.168.1.0/24"

    controller.run_full_assessment()

    assert captured["args"].safe_mode is False
    assert captured["args"].no_safe_mode is True
    assert captured["args"].check_defaults is False


def test_guided_menu_remembers_full_assessment_and_exports_findings(monkeypatch, tmp_path):
    import sunsetscan

    captured = {}
    result = ScanResult(target="192.168.50.80", profile="FULL")
    result.hosts["192.168.50.80"] = HostInfo(ip="192.168.50.80", state="up")

    class FakeExporter:
        def export(self, *args, **kwargs):
            captured["export"] = (args, kwargs)
            return True

    class FakeSunsetScan:
        def __init__(self, args):
            self.last_scan_result = result
            self.last_eol_data = {"192.168.50.80": {}}
            self.finding_registry = object()
            self.last_risk_scores = {"192.168.50.80": object()}
            self.last_device_identities = {"192.168.50.80": object()}
            self.exporter = FakeExporter()

        def run_full_assessment(self, target):
            return 0

    monkeypatch.setattr(sunsetscan, "SunsetScan", FakeSunsetScan)
    monkeypatch.setattr("ui.interactive_controller.Confirm.ask", lambda *a, **k: False)
    monkeypatch.chdir(tmp_path)
    controller = InteractiveController(settings=Settings(), no_color=True)
    controller.current_target = "192.168.50.80"

    controller.run_full_assessment()
    controller.export_results("html")

    args, kwargs = captured["export"]
    assert args[0] == "html"
    assert args[1] is result
    assert kwargs["findings"] is controller._last_assessment_app.finding_registry
    assert kwargs["device_identities"] is controller._last_assessment_app.last_device_identities
    assert kwargs["eol_data"] is controller._last_assessment_app.last_eol_data


def test_guided_menu_keeps_all_scanned_hosts_for_export(monkeypatch):
    controller = InteractiveController(settings=Settings(), no_color=True)
    ips = ["192.168.50.30", "192.168.50.80"]

    def scan(ip):
        result = ScanResult(target=ip, profile="QUICK")
        result.hosts[ip] = HostInfo(ip=ip, state="up")
        return result

    monkeypatch.setattr(controller.scanner, "quick_scan", scan)
    monkeypatch.setattr(controller, "show_discovered_hosts", lambda: None)
    controller.quick_port_scan(ips)

    assert set(controller._last_scan_result.hosts) == set(ips)
    assert controller._last_scan_result.profile == "QUICK"
    assert controller._last_assessment_app is None


def test_guided_menu_does_not_report_failed_assessment_as_complete(monkeypatch, capsys):
    import sunsetscan

    class FakeSunsetScan:
        def __init__(self, args):
            pass

        def run_full_assessment(self, target):
            return 1

    monkeypatch.setattr(sunsetscan, "SunsetScan", FakeSunsetScan)
    monkeypatch.setattr("ui.interactive_controller.Confirm.ask", lambda *a, **k: False)
    controller = InteractiveController(settings=Settings(), no_color=True)
    controller.current_target = "192.168.50.80"
    controller.run_full_assessment()

    output = capsys.readouterr().out
    assert "Assessment failed (exit code 1)" in output
    assert "Full assessment complete" not in output


def test_guided_network_report_counts_actual_eol_levels(capsys):
    controller = InteractiveController(settings=Settings(), no_color=True)
    controller.discovered_hosts["192.168.50.80"] = DiscoveredHost(
        ip="192.168.50.80",
        eol_results={
            22: EOLStatus(product="a", version="", level=EOLStatusLevel.OK),
            80: EOLStatus(product="b", version="", level=EOLStatusLevel.WARNING),
            443: EOLStatus(product="c", version="", level=EOLStatusLevel.CRITICAL),
        },
    )

    controller.generate_network_report()

    output = capsys.readouterr().out
    assert "Supported:                1" in output
    assert "Approaching EOL:          1" in output
    assert "End of Life:              1" in output
