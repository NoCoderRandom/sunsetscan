from types import SimpleNamespace

from core import web_checker


def test_admin_paths_ignore_router_catch_all_page(monkeypatch):
    monkeypatch.setattr(web_checker, "ADMIN_PATHS", ["/admin/", "/wp-admin/"])

    def page(_session, url, timeout, method="GET"):
        return SimpleNamespace(status_code=200, content=b"generic router page")

    monkeypatch.setattr(web_checker, "_get_page", page)

    findings = web_checker._check_admin_paths(
        "192.0.2.1", 80, "http", "http://192.0.2.1:80", object(), 1.0
    )

    assert findings == []


def test_admin_paths_report_distinct_accessible_page(monkeypatch):
    monkeypatch.setattr(web_checker, "ADMIN_PATHS", ["/admin/"])

    def page(_session, url, timeout, method="GET"):
        content = b"admin login" if url.endswith("/admin/") else b"generic router page"
        return SimpleNamespace(status_code=200, content=content)

    monkeypatch.setattr(web_checker, "_get_page", page)

    findings = web_checker._check_admin_paths(
        "192.0.2.1", 80, "http", "http://192.0.2.1:80", object(), 1.0
    )

    assert len(findings) == 1
    assert "/admin/ [accessible]" in findings[0].evidence


def test_asus_httpd_banner_does_not_match_apache(monkeypatch):
    monkeypatch.setattr(
        web_checker,
        "_load_wappalyzer",
        lambda: {"Apache HTTP Server": {"headers": {"Server": "httpd"}}},
    )
    response = SimpleNamespace(text="", headers={"Server": "httpd/2.0"})

    findings = web_checker._run_wappalyzer_checks(
        "192.0.2.1", 80, "http", response
    )

    assert findings == []
