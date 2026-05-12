from config.settings import Settings
from core.port_scanner import PortScanOrchestrator
from ui.interactive_controller import InteractiveController


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
    controller.current_target = "192.168.50.0/24"

    controller.run_full_assessment()

    assert captured["target"] == "192.168.50.0/24"
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
