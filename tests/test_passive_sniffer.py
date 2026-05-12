import builtins

from core.passive_sniffer import PassiveSniffer


def test_passive_sniffer_start_handles_permission_error(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "scapy.all":
            raise PermissionError("raw sockets unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert PassiveSniffer().start() is False
