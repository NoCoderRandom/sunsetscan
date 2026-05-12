from pathlib import Path

import core.module_manager as module_manager
from core.module_manager import ModuleManager


def _redirect_module_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "data" / "cache"
    monkeypatch.setattr(module_manager, "_PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(module_manager, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(module_manager, "_MODULES_META_PATH", cache_dir / "modules.json")
    return cache_dir


def test_download_reports_unwritable_cache_before_network(monkeypatch, tmp_path, capsys):
    cache_dir = _redirect_module_cache(monkeypatch, tmp_path)
    cache_dir.mkdir(parents=True)
    monkeypatch.setenv("USER", "pi")
    monkeypatch.delenv("SUDO_USER", raising=False)

    def fake_access(path, mode):
        return Path(path) != cache_dir

    monkeypatch.setattr(module_manager.os, "access", fake_access)

    manager = ModuleManager()

    assert manager.download("credentials-full") is False
    output = capsys.readouterr().out
    assert "Permission error: SunsetScan cannot write module cache files." in output
    assert str(cache_dir) in output
    assert f"sudo chown -R pi:pi {cache_dir}" in output
    assert "Downloading credentials-full" not in output


def test_download_all_reports_unwritable_cache_once(monkeypatch, tmp_path, capsys):
    cache_dir = _redirect_module_cache(monkeypatch, tmp_path)
    cache_dir.mkdir(parents=True)

    def fake_access(path, mode):
        return Path(path) != cache_dir

    monkeypatch.setattr(module_manager.os, "access", fake_access)

    manager = ModuleManager()

    assert manager.download_all() == 0
    output = capsys.readouterr().out
    assert output.count("Permission error: SunsetScan cannot write module cache files.") == 1
    assert "Downloading credentials-mini" not in output
