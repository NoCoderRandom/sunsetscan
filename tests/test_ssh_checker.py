from core import ssh_checker
from core.findings import Severity


def test_ssh_findings_use_server_advertised_algorithms(monkeypatch):
    monkeypatch.setattr(ssh_checker, "_grab_ssh_banner", lambda *args: "SSH-2.0-OpenSSH_9.2p1")
    monkeypatch.setattr(
        ssh_checker,
        "_get_ssh_algorithms_raw",
        lambda *args: (["curve25519-sha256"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256"]),
    )
    monkeypatch.setattr(ssh_checker, "_get_ssh_host_key", lambda *args: ("ssh-ed25519", 256))

    findings = ssh_checker.check_ssh("192.0.2.10", 22)

    assert not any("weak" in finding.title.lower() for finding in findings)
    assert not any(finding.severity == Severity.HIGH for finding in findings)


def test_ssh_findings_report_weak_algorithms_advertised_by_server(monkeypatch):
    monkeypatch.setattr(ssh_checker, "_grab_ssh_banner", lambda *args: "SSH-2.0-Test_1.0")
    monkeypatch.setattr(
        ssh_checker,
        "_get_ssh_algorithms_raw",
        lambda *args: (["diffie-hellman-group1-sha1"], ["3des-cbc"], ["hmac-md5"]),
    )
    monkeypatch.setattr(ssh_checker, "_get_ssh_host_key", lambda *args: None)

    findings = ssh_checker.check_ssh("192.0.2.10", 22)

    assert sum(finding.severity == Severity.HIGH for finding in findings) == 3


def test_ssh_unknown_algorithms_do_not_become_confirmed_weak_findings(monkeypatch):
    monkeypatch.setattr(ssh_checker, "_grab_ssh_banner", lambda *args: "SSH-2.0-Test_1.0")
    monkeypatch.setattr(ssh_checker, "_get_ssh_algorithms_raw", lambda *args: None)

    findings = ssh_checker.check_ssh("192.0.2.10", 22)

    assert any(finding.severity == Severity.LOW for finding in findings)
    assert not any(finding.severity == Severity.HIGH for finding in findings)
