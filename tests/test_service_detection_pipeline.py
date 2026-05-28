from core.banner_grabber import BannerGrabber
from core.cve_checker import CVEChecker
from core.scanner import HostInfo, PortInfo
from core.http_fingerprinter import HttpFingerprint
from core import web_checker
from eol.product_map import get_product_slug
from sunsetscan import SunsetScan, _check_insecure_protocols


class FakeCVECache:
    def __init__(self):
        self.calls = []
        self.data = {
            ("apache-http-server", "2.4.49"): [
                {"id": "CVE-TEST-APACHE", "summary": "test apache vuln", "cvss_v3": 9.8}
            ],
            ("redis", "5.0"): [
                {"id": "CVE-TEST-REDIS", "summary": "test redis vuln", "cvss_v3": 7.5}
            ],
        }

    def get_cve(self, product, version):
        self.calls.append((product, version))
        return self.data.get((product, version))


def test_product_slug_keeps_apache_when_version_is_in_name():
    assert get_product_slug("apache 2.4.49") == "apache-http-server"
    assert get_product_slug("Apache/2.4.49") == "apache-http-server"


def test_cve_lookup_normalizes_product_and_cleans_version():
    cache = FakeCVECache()
    findings = CVEChecker(cache).check(
        host="192.0.2.10",
        product="apache",
        version="2.4.49)",
        port=8089,
    )

    assert [finding.cve_ids[0] for finding in findings] == ["CVE-TEST-APACHE"]
    assert ("apache-http-server", "2.4.49") in cache.calls


def test_cve_lookup_falls_back_to_major_minor_version():
    cache = FakeCVECache()
    findings = CVEChecker(cache).check(
        host="192.0.2.10",
        product="Redis key-value store",
        version="5.0.14",
        port=6379,
    )

    assert [finding.cve_ids[0] for finding in findings] == ["CVE-TEST-REDIS"]
    assert ("redis", "5.0.14") in cache.calls
    assert ("redis", "5.0") in cache.calls


def test_banner_grabber_uses_service_hint_for_http_probe():
    grabber = BannerGrabber(enable_http_fingerprinting=False)

    assert grabber._get_probe(8089, service_hint="Apache httpd") == grabber.PROBES["http"]


def test_banner_grabber_parses_redis_and_busybox_login_banners():
    grabber = BannerGrabber(enable_http_fingerprinting=False)

    assert grabber._parse_banner("# Server\r\nredis_version:5.0.14\r\n", 5555) == (
        "redis",
        "5.0.14",
    )
    assert grabber._parse_banner("BusyBox v1.19.4 built-in shell\r\nlogin: ", 2323) == (
        "busybox",
        "1.19.4",
    )


def test_telnet_like_detection_uses_banner_and_service_on_any_port():
    host_info = HostInfo(ip="192.0.2.10")
    host_info.ports[2323] = PortInfo(
        port=2323,
        state="open",
        service="busybox",
        banner="BusyBox v1.19.4 built-in shell\r\nlogin: ",
    )

    findings = _check_insecure_protocols("192.0.2.10", [2323], host_info=host_info)

    assert any(finding.port == 2323 and "Telnet-like" in finding.title for finding in findings)


def test_http_header_product_versions_include_server_and_powered_by():
    port = PortInfo(port=8090, state="open", service="apache")
    port.http_fingerprint = HttpFingerprint(
        host="192.0.2.10",
        port=8090,
        raw_headers={
            "Server": "Apache/2.4.49 (Debian)",
            "X-Powered-By": "PHP/7.2.34",
        },
    )

    assert SunsetScan._iter_http_product_versions(port) == [
        ("apache", "2.4.49"),
        ("php", "7.2.34"),
    ]


def test_web_checks_use_http_service_hint_on_non_standard_port(monkeypatch):
    calls = []

    def fake_check_web_interface(host, port, is_https=False, timeout=5.0):
        calls.append((host, port, is_https, timeout))
        return []

    monkeypatch.setattr(web_checker, "check_web_interface", fake_check_web_interface)

    web_checker.run_web_checks(
        "192.0.2.10",
        [8089],
        timeout=1.5,
        services_by_port={8089: "Apache httpd"},
    )

    assert calls == [("192.0.2.10", 8089, False, 1.5)]
