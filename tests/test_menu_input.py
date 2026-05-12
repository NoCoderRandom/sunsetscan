import sys

from ui.menu import _read_key


class _NonTTY:
    def isatty(self):
        return False


def test_read_key_uses_line_fallback_for_piped_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _NonTTY())
    monkeypatch.setattr("builtins.input", lambda: "q")

    assert _read_key() == "q"
