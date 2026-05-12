from pathlib import Path

import core.hardware_eol as hardware_eol
from core.hardware_eol import HardwareEOLDatabase
from core.module_manager import _parse_hardware_eol, _parse_hardware_eol_shard


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HARDWARE_EOL_DIR = PROJECT_ROOT / "data" / "hardware_eol"
INDEX_PATH = HARDWARE_EOL_DIR / "netwatch_hardware_eol_index.json.gz"


def test_split_database_artifacts_are_compressed_and_consistent():
    assert INDEX_PATH.exists()
    assert not (HARDWARE_EOL_DIR / "netwatch_hardware_eol_index.json").exists()
    assert not list((HARDWARE_EOL_DIR / "records").glob("*.json"))

    index = _parse_hardware_eol(INDEX_PATH.read_bytes())

    assert index["metadata"]["artifact_layout"]["format"] == "split"
    assert "records" not in index

    shard_total = 0
    for category, info in index["record_shards"].items():
        shard_path = HARDWARE_EOL_DIR / info["path"]
        assert shard_path.suffix == ".gz"
        assert shard_path.exists()

        shard = _parse_hardware_eol_shard(shard_path.read_bytes())
        assert shard["category"] == category
        assert len(shard["records"]) == info["record_count"]
        shard_total += info["record_count"]

    assert shard_total == index["summary"]["total_records"]


def test_compressed_split_database_loads_expected_hardware_findings():
    db = HardwareEOLDatabase(INDEX_PATH)

    moxa = db.lookup("Moxa", "EDS-P308 Series")
    assert moxa is not None
    assert moxa.status == "lifecycle_review"
    assert moxa.review_required is True

    westermo = db.lookup("Westermo", "1100-0432")
    assert westermo is not None
    assert westermo.status == "lifecycle_review"
    assert westermo.review_required is True

    calix = db.lookup("Calix", "100-03719")
    assert calix is not None
    assert calix.status == "unsupported"
    assert calix.receives_security_updates is False

    assert db.lookup("Fortinet", "FortiGate 100F") is None


def test_developer_split_index_preferred_over_legacy_cache_monolith(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache" / "hardware_eol"
    repo_dir = tmp_path / "repo" / "hardware_eol"
    cache_dir.mkdir(parents=True)
    repo_dir.mkdir(parents=True)

    legacy_cache_monolith = cache_dir / "netwatch_hardware_eol.json"
    developer_split_index = repo_dir / "netwatch_hardware_eol_index.json.gz"
    legacy_cache_monolith.write_text("{}", encoding="utf-8")
    developer_split_index.write_bytes(b"placeholder")

    monkeypatch.setattr(hardware_eol, "_DEFAULT_DB_PATH", legacy_cache_monolith)
    monkeypatch.setattr(hardware_eol, "_DEFAULT_INDEX_PATH", cache_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_PATH", repo_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_GZ_PATH", developer_split_index)
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_PATH", repo_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_monolith.json.gz")

    assert HardwareEOLDatabase()._candidate_path() == developer_split_index
