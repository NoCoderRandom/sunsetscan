from core.scanner import NetworkScanner


def test_nmap_aggressive_os_guess_is_not_reported_as_exact():
    scanner = NetworkScanner.__new__(NetworkScanner)
    scanner.nm = {
        "192.0.2.10": {
            "status": {"state": "up"},
            "hostnames": [{"name": ""}],
            "osmatch": [{"name": "Linux 4.15 - 5.8", "accuracy": "97"}],
        }
    }

    host = scanner._parse_host("192.0.2.10")

    assert host.os_guess == ""
    assert host.os_accuracy == ""


def test_nmap_exact_os_match_is_retained():
    scanner = NetworkScanner.__new__(NetworkScanner)
    scanner.nm = {
        "192.0.2.10": {
            "status": {"state": "up"},
            "hostnames": [{"name": ""}],
            "osmatch": [{"name": "Linux", "accuracy": "100"}],
        }
    }

    host = scanner._parse_host("192.0.2.10")

    assert host.os_guess == "Linux"
    assert host.os_accuracy == "100"
