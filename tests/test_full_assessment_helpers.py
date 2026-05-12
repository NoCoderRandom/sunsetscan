from datetime import datetime

from netwatch import NetWatch


def test_full_assessment_scan_target_uses_discovered_hosts_only():
    hosts = NetWatch._normalise_discovered_hosts(
        {"192.168.1.10", "192.168.1.2", "192.168.1.1"},
        excluded_hosts=("192.168.1.1",),
    )

    assert hosts == ["192.168.1.2", "192.168.1.10"]
    assert (
        NetWatch._scan_target_for_discovered_hosts(hosts, "192.168.1.0/24")
        == "192.168.1.2 192.168.1.10"
    )


def test_discovery_only_scan_result_keeps_hosts_visible():
    result = NetWatch._discovery_only_scan_result(
        target="192.168.1.0/24",
        profile="STEALTH",
        discovered_hosts=["192.168.1.2", "192.168.1.10"],
        start_time=datetime(2026, 5, 12, 7, 0, 0),
    )

    assert result.target == "192.168.1.0/24"
    assert result.profile == "STEALTH"
    assert sorted(result.hosts) == ["192.168.1.10", "192.168.1.2"]
    assert all(host.state == "up" for host in result.hosts.values())
