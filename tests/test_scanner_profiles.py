from config.settings import Settings
import core.port_scanner as port_scanner
from core.port_scanner import PortScanOrchestrator
from core.scanner import HostInfo, ScanResult
from core.scanner import NetworkScanner


def test_stealth_non_root_fallback_limits_ports():
    args = NetworkScanner._strip_root_flags("-sS -T2 -sV")

    assert "-sS" not in args
    assert "-sT" in args
    assert "-F" in args
    assert "-T2" not in args
    assert "-T3" in args
    assert "--version-intensity 2" in args


def test_syn_fallback_preserves_explicit_ports():
    args = NetworkScanner._strip_root_flags("-sS -T2 -sV -p 22,80")

    assert "-sT" in args
    assert "-F" not in args
    assert "-p 22,80" in args
    assert "-T3" in args


def test_safe_mode_bounds_root_stealth_scan():
    scanner = NetworkScanner(Settings(safe_mode=True))

    args = scanner._apply_safety("-sS -T2 -sV")

    assert "-sS" in args
    assert "-T2" in args
    assert "-F" in args
    assert "--version-intensity 2" in args


def test_safe_mode_bounds_full_scan_without_os_detection():
    scanner = NetworkScanner(Settings(safe_mode=True))

    args = scanner._apply_safety("-T4 -A -sV -O --osscan-guess")

    assert "-A" not in args
    assert "-O" not in args
    assert "--osscan-guess" not in args
    assert "-T3" in args
    assert "-sV" in args
    assert "-sC" in args
    assert "-F" in args
    assert "--version-intensity 2" in args


def test_safe_mode_preserves_explicit_ports():
    scanner = NetworkScanner(Settings(safe_mode=True))

    args = scanner._apply_safety("-sS -T2 -sV -p 22,80")

    assert "-sS" in args
    assert "-F" not in args
    assert "-p 22,80" in args
    assert "--version-intensity 2" in args


def test_safe_mode_does_not_exclude_explicit_single_host_target():
    scanner = NetworkScanner(Settings(
        safe_mode=True,
        excluded_hosts=("192.168.50.80", "192.168.50.1"),
    ))

    single_host_args = scanner._apply_safety(
        "-T4 -F -sV",
        target="192.168.50.80",
    )
    network_args = scanner._apply_safety(
        "-T4 -F -sV",
        target="192.168.50.0/24",
    )

    assert "--exclude" not in single_host_args
    assert "--exclude 192.168.50.80,192.168.50.1" in network_args


def test_safe_mode_skips_all_port_masscan(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    orchestrator = PortScanOrchestrator(Settings(safe_mode=True))

    called = {}

    def fake_scan(target, profile="QUICK", arguments=None):
        called["target"] = target
        called["profile"] = profile
        called["arguments"] = arguments
        return ScanResult(target=target, profile=profile)

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    orchestrator.scan("192.168.1.0/24", profile="STEALTH")

    assert called == {
        "target": "192.168.1.0/24",
        "profile": "STEALTH",
        "arguments": None,
    }


def test_stealth_profile_skips_masscan_even_when_available(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    monkeypatch.setattr(
        port_scanner,
        "_run_masscan",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("STEALTH should not run masscan")
        ),
    )
    orchestrator = PortScanOrchestrator(Settings())

    called = {}

    def fake_scan(target, profile="QUICK", arguments=None):
        called["target"] = target
        called["profile"] = profile
        called["arguments"] = arguments
        return ScanResult(target=target, profile=profile)

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    orchestrator.scan("127.0.0.1", profile="STEALTH")

    assert called == {
        "target": "127.0.0.1",
        "profile": "STEALTH",
        "arguments": None,
    }


def test_masscan_single_host_uses_existing_discovery(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    calls = {"masscan": 0}

    def fake_masscan(*args, **kwargs):
        calls["masscan"] += 1
        return {"192.168.1.10": [445]}

    monkeypatch.setattr(port_scanner, "_run_masscan", fake_masscan)
    orchestrator = PortScanOrchestrator(Settings())

    captured = {}

    def fake_scan(target, profile="QUICK", arguments=None):
        captured["target"] = target
        captured["profile"] = profile
        captured["arguments"] = arguments
        return ScanResult(target=target, profile=profile)

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    orchestrator.scan("192.168.1.0/24", profile="SMB")

    assert calls["masscan"] == 1
    assert captured["target"] == "192.168.1.10"
    assert captured["profile"] == "SMB"
    assert "-p 445" in captured["arguments"]


def test_masscan_does_not_exclude_explicit_single_host_target(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    captured = {}

    def fake_masscan(*args, **kwargs):
        captured["excluded_hosts"] = kwargs["excluded_hosts"]
        return {"192.168.50.80": [445]}

    monkeypatch.setattr(port_scanner, "_run_masscan", fake_masscan)
    orchestrator = PortScanOrchestrator(Settings(
        excluded_hosts=("192.168.50.80", "192.168.50.1"),
    ))

    def fake_scan(target, profile="QUICK", arguments=None):
        result = ScanResult(target=target, profile=profile)
        result.hosts[target] = HostInfo(ip=target, state="up")
        return result

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    result = orchestrator.scan("192.168.50.80", profile="SMB")

    assert captured["excluded_hosts"] == ()
    assert sorted(result.hosts) == ["192.168.50.80"]


def test_masscan_single_host_rate_is_capped(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    captured = {}

    def fake_masscan(target, rate, **kwargs):
        captured["target"] = target
        captured["rate"] = rate
        return {"192.168.50.212": [5000]}

    monkeypatch.setattr(port_scanner, "_run_masscan", fake_masscan)
    orchestrator = PortScanOrchestrator(Settings())

    def fake_scan(target, profile="QUICK", arguments=None):
        result = ScanResult(target=target, profile=profile)
        result.hosts[target] = HostInfo(ip=target, state="up")
        return result

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    orchestrator.scan("192.168.50.212", profile="FULL")

    assert captured == {
        "target": "192.168.50.212",
        "rate": port_scanner._MASSCAN_SINGLE_HOST_RATE_CAP,
    }


def test_masscan_network_rate_is_not_single_host_capped(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    captured = {}

    def fake_masscan(target, rate, **kwargs):
        captured["target"] = target
        captured["rate"] = rate
        return {"192.168.50.212": [5000]}

    monkeypatch.setattr(port_scanner, "_run_masscan", fake_masscan)
    orchestrator = PortScanOrchestrator(Settings())

    def fake_scan(target, profile="QUICK", arguments=None):
        result = ScanResult(target=target, profile=profile)
        result.hosts[target] = HostInfo(ip=target, state="up")
        return result

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    orchestrator.scan("192.168.50.0/24", profile="FULL")

    assert captured == {
        "target": "192.168.50.0/24",
        "rate": 2000,
    }


def test_masscan_parallel_combines_hosts_without_duration_assignment(monkeypatch):
    monkeypatch.setattr(port_scanner, "_masscan_available", lambda: True)
    monkeypatch.setattr(
        port_scanner,
        "_run_masscan",
        lambda *args, **kwargs: {
            "192.168.1.10": [80],
            "192.168.1.11": [443],
        },
    )
    orchestrator = PortScanOrchestrator(Settings())

    def fake_scan(target, profile="QUICK", arguments=None):
        result = ScanResult(target=target, profile=profile)
        result.hosts[target] = HostInfo(ip=target, state="up")
        return result

    monkeypatch.setattr(orchestrator._nmap, "scan", fake_scan)

    result = orchestrator.scan("192.168.1.0/24", profile="SMB")

    assert sorted(result.hosts) == ["192.168.1.10", "192.168.1.11"]
    assert result.duration >= 0
