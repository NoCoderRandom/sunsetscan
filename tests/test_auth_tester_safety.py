from config.settings import Settings
from core.auth_tester import AuthTester, AuthTestResult


def test_default_credentials_require_exact_model_match():
    tester = AuthTester(settings=Settings(), enabled=True)

    assert tester.get_credentials_for_device("TP-Link", model="RE305") == [("admin", "admin")]
    assert tester.get_credentials_for_device("TP-Link") == []
    assert tester.get_credentials_for_device("Unknown Router", model="Unknown") == []


def test_non_static_label_passwords_are_not_tested():
    tester = AuthTester(settings=Settings(), enabled=True)

    assert tester.get_credentials_for_device("HP", model="LaserJet Pro 4001") == []


def test_auth_attempt_cap_limits_credential_bearing_tests(monkeypatch):
    tester = AuthTester(
        settings=Settings(
            auth_delay_seconds=0,
            auth_max_attempts_per_host=1,
            auth_max_attempts_per_service=1,
        ),
        enabled=True,
    )
    calls = []

    def fake_test_device_defaults(host, port, device_type, test_method="basic", model=None, candidates=None):
        calls.append((port, test_method, len(candidates or [])))
        return [
            AuthTestResult(
                host=host,
                port=port,
                service="http",
                username="admin",
                password="admin",
                method=test_method,
                credential_sent=True,
            )
        ]

    monkeypatch.setattr(tester, "test_device_defaults", fake_test_device_defaults)

    results = tester.check_all_services(
        "192.168.1.2",
        [80, 443],
        device_type="TP-Link",
        model="RE305",
    )

    assert list(results) == [80]
    assert calls == [(80, "basic", 1)]


def test_auth_stops_after_lockout_signal(monkeypatch):
    tester = AuthTester(
        settings=Settings(auth_delay_seconds=0),
        enabled=True,
    )
    calls = []

    def fake_test_device_defaults(host, port, device_type, test_method="basic", model=None, candidates=None):
        calls.append((port, test_method))
        return [
            AuthTestResult(
                host=host,
                port=port,
                service="http",
                username="admin",
                password="admin",
                method=test_method,
                credential_sent=True,
                lockout_suspected=True,
            )
        ]

    monkeypatch.setattr(tester, "test_device_defaults", fake_test_device_defaults)

    results = tester.check_all_services(
        "192.168.1.2",
        [80, 443],
        device_type="TP-Link",
        model="RE305",
    )

    assert list(results) == [80]
    assert calls == [(80, "basic")]
