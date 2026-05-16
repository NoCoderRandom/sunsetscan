import json
from datetime import datetime, timedelta

import core.update_manager as update_manager
from core.update_manager import UpdateManager


def test_cache_status_uses_module_metadata_for_downloaded_databases(
    monkeypatch,
    tmp_path,
    capsys,
):
    cache_dir = tmp_path / "data" / "cache"
    cache_dir.mkdir(parents=True)
    monkeypatch.setattr(update_manager, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(update_manager, "_META_FILE", cache_dir / "cache_meta.json")

    (cache_dir / "wappalyzer_tech.json").write_text("{}", encoding="utf-8")
    (cache_dir / "ja3_signatures.json").write_text("[]", encoding="utf-8")
    (cache_dir / "modules.json").write_text(
        json.dumps(
            {
                "wappalyzer-full": {"installed_at": datetime.now().isoformat()},
                "ja3-signatures": {"installed_at": datetime.now().isoformat()},
            }
        ),
        encoding="utf-8",
    )

    UpdateManager().show_cache_status()

    output = capsys.readouterr().out
    wappalyzer_line = next(line for line in output.splitlines() if "Wappalyzer" in line)
    ja3_line = next(line for line in output.splitlines() if "JA3 signatures" in line)
    assert "last updated: never" not in wappalyzer_line
    assert "last updated: never" not in ja3_line


def test_cache_status_clamps_small_future_naive_timestamps(
    monkeypatch,
    tmp_path,
    capsys,
):
    cache_dir = tmp_path / "data" / "cache"
    cache_dir.mkdir(parents=True)
    monkeypatch.setattr(update_manager, "_CACHE_DIR", cache_dir)
    monkeypatch.setattr(update_manager, "_META_FILE", cache_dir / "cache_meta.json")

    future = datetime.now() + timedelta(seconds=30)
    (cache_dir / "cache_meta.json").write_text(
        json.dumps({"eol_last_updated": future.isoformat()}),
        encoding="utf-8",
    )

    UpdateManager().show_cache_status()

    output = capsys.readouterr().out
    assert "-1h ago" not in output
    assert "last updated: just now" in output
