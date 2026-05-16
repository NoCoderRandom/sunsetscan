from pathlib import Path
import gzip
import hashlib
import json

import requests

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


def test_hardware_eol_smart_profile_installed_requires_manifest_index_and_shards(monkeypatch, tmp_path):
    _redirect_module_cache(monkeypatch, tmp_path)
    hardware_dir = tmp_path / "data" / "cache" / "hardware_eol"
    index_path = hardware_dir / "indexes" / "home.json"
    shard_path = hardware_dir / "records" / "home" / "network_infrastructure.json"
    index_path.parent.mkdir(parents=True)
    shard_path.parent.mkdir(parents=True)
    index_path.write_text("{}", encoding="utf-8")
    shard_path.write_text("{}", encoding="utf-8")
    (hardware_dir / "manifest.json").write_text(
        json.dumps(
            {
                "metadata": {"schema": "sunsetscan.hardware_eol.smart_packs.v1"},
                "profiles": {"hardware-eol-home": {"packs": ["home"]}},
                "packs": {
                    "home": {
                        "record_count": 1,
                        "index": {"path": "indexes/home.json"},
                        "shards": {
                            "network_infrastructure": {
                                "path": "records/home/network_infrastructure.json"
                            }
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    manager = ModuleManager()

    assert manager.is_installed("hardware-eol-home") is True
    assert manager.is_installed("hardware-eol-office") is False


def test_download_all_uses_full_smart_hardware_eol_profile_and_legacy(monkeypatch, tmp_path):
    _redirect_module_cache(monkeypatch, tmp_path)
    manager = ModuleManager()
    attempted = []

    def fake_is_installed(module_name):
        return False

    def fake_download(module_name, quiet=False):
        attempted.append(module_name)
        return True

    monkeypatch.setattr(manager, "is_installed", fake_is_installed)
    monkeypatch.setattr(manager, "download", fake_download)

    manager.download_all(quiet=True)

    assert "hardware-eol" in attempted
    assert "hardware-eol-home" not in attempted
    assert "hardware-eol-office" not in attempted
    assert "hardware-eol-full" in attempted


def test_download_defaults_uses_home_smart_hardware_eol_profile(monkeypatch, tmp_path):
    _redirect_module_cache(monkeypatch, tmp_path)
    manager = ModuleManager()
    attempted = []

    def fake_is_installed(module_name):
        return False

    def fake_download(module_name, quiet=False):
        attempted.append(module_name)
        return True

    monkeypatch.setattr(manager, "is_installed", fake_is_installed)
    monkeypatch.setattr(manager, "download", fake_download)

    manager.download_defaults(quiet=True)

    assert "hardware-eol-home" in attempted
    assert "hardware-eol" not in attempted
    assert "hardware-eol-full" not in attempted


def test_hardware_eol_smart_profile_download_installs_only_selected_packs(
    monkeypatch,
    tmp_path,
):
    _redirect_module_cache(monkeypatch, tmp_path)

    def gz_json(data):
        return gzip.compress(json.dumps(data).encode("utf-8"))

    def pack_artifacts(pack):
        category = "network_infrastructure"
        record_id = f"hw_{pack}_001"
        index = {
            "metadata": {"schema": "sunsetscan.hardware_eol.v1"},
            "summary": {"total_records": 1},
            "indexes": {"vendor_aliases": {}},
            "model_summaries": [],
            "record_locations": {record_id: category},
            "record_shards": {
                category: {
                    "path": f"../records/{pack}/{category}.json.gz",
                    "record_count": 1,
                }
            },
        }
        shard = {
            "category": category,
            "records": [{"id": record_id, "vendor_slug": pack}],
            "positions": {record_id: 0},
        }
        return gz_json(index), gz_json(shard)

    pack_bytes = {
        pack: pack_artifacts(pack)
        for pack in ("home", "office", "enterprise")
    }
    manifest = {
        "metadata": {"schema": "sunsetscan.hardware_eol.smart_packs.v1"},
        "profiles": {
            "hardware-eol-office": {"packs": ["home", "office"]},
            "hardware-eol-enterprise": {"packs": ["home", "office", "enterprise"]},
        },
        "packs": {},
    }
    for pack, (index_bytes, shard_bytes) in pack_bytes.items():
        manifest["packs"][pack] = {
            "record_count": 1,
            "index": {
                "path": f"indexes/{pack}.json.gz",
                "sha256": hashlib.sha256(index_bytes).hexdigest(),
            },
            "shards": {
                "network_infrastructure": {
                    "path": f"records/{pack}/network_infrastructure.json.gz",
                    "sha256": hashlib.sha256(shard_bytes).hexdigest(),
                }
            },
        }

    manifest_url = module_manager.MODULE_REGISTRY["hardware-eol-office"]["url"]
    base_url = manifest_url.rsplit("/", 1)[0] + "/"
    payloads = {manifest_url: gz_json(manifest)}
    for pack, (index_bytes, shard_bytes) in pack_bytes.items():
        payloads[f"{base_url}indexes/{pack}.json.gz"] = index_bytes
        payloads[f"{base_url}records/{pack}/network_infrastructure.json.gz"] = shard_bytes

    requested = []

    class FakeResponse:
        def __init__(self, content=b"", status_code=200):
            self.content = content
            self.status_code = status_code

    class FakeSession:
        def __init__(self):
            self.headers = {}

        def get(self, url, timeout=30):
            requested.append(url)
            if url not in payloads:
                return FakeResponse(status_code=404)
            return FakeResponse(payloads[url])

    monkeypatch.setattr(requests, "Session", FakeSession)

    manager = ModuleManager()

    assert manager.download("hardware-eol-office", quiet=True) is True
    assert manager.is_installed("hardware-eol-home") is True
    assert manager.is_installed("hardware-eol-office") is True
    assert manager.is_installed("hardware-eol-enterprise") is False

    hardware_dir = tmp_path / "data" / "cache" / "hardware_eol"
    assert (hardware_dir / "manifest.json").exists()
    assert (hardware_dir / "indexes" / "home.json").exists()
    assert (hardware_dir / "indexes" / "office.json").exists()
    assert not (hardware_dir / "indexes" / "enterprise.json").exists()
    assert (hardware_dir / "records" / "home" / "network_infrastructure.json").exists()
    assert (hardware_dir / "records" / "office" / "network_infrastructure.json").exists()
    assert not (
        hardware_dir / "records" / "enterprise" / "network_infrastructure.json"
    ).exists()

    assert f"{base_url}indexes/home.json.gz" in requested
    assert f"{base_url}indexes/office.json.gz" in requested
    assert f"{base_url}indexes/enterprise.json.gz" not in requested


def test_full_hardware_eol_profile_records_implied_profile_metadata(
    monkeypatch,
    tmp_path,
):
    _redirect_module_cache(monkeypatch, tmp_path)

    def gz_json(data):
        return gzip.compress(json.dumps(data).encode("utf-8"))

    def pack_artifacts(pack):
        category = "network_infrastructure"
        record_id = f"hw_{pack}_001"
        index = {
            "metadata": {"schema": "sunsetscan.hardware_eol.v1"},
            "summary": {"total_records": 1},
            "indexes": {"vendor_aliases": {}},
            "model_summaries": [],
            "record_locations": {record_id: category},
            "record_shards": {
                category: {
                    "path": f"../records/{pack}/{category}.json.gz",
                    "record_count": 1,
                }
            },
        }
        shard = {
            "category": category,
            "records": [{"id": record_id, "vendor_slug": pack}],
            "positions": {record_id: 0},
        }
        return gz_json(index), gz_json(shard)

    packs = ("home", "office", "enterprise", "industrial_ot", "service_provider")
    pack_bytes = {pack: pack_artifacts(pack) for pack in packs}
    manifest = {
        "metadata": {"schema": "sunsetscan.hardware_eol.smart_packs.v1"},
        "profiles": {
            "hardware-eol-home": {"packs": ["home"]},
            "hardware-eol-office": {"packs": ["home", "office"]},
            "hardware-eol-enterprise": {"packs": ["home", "office", "enterprise"]},
            "hardware-eol-industrial": {"packs": ["home", "office", "industrial_ot"]},
            "hardware-eol-service-provider": {
                "packs": ["home", "office", "enterprise", "service_provider"]
            },
            "hardware-eol-full": {
                "packs": ["home", "office", "enterprise", "industrial_ot", "service_provider"]
            },
        },
        "packs": {},
    }
    for pack, (index_bytes, shard_bytes) in pack_bytes.items():
        manifest["packs"][pack] = {
            "record_count": 1,
            "index": {
                "path": f"indexes/{pack}.json.gz",
                "sha256": hashlib.sha256(index_bytes).hexdigest(),
            },
            "shards": {
                "network_infrastructure": {
                    "path": f"records/{pack}/network_infrastructure.json.gz",
                    "sha256": hashlib.sha256(shard_bytes).hexdigest(),
                }
            },
        }

    manifest_url = module_manager.MODULE_REGISTRY["hardware-eol-full"]["url"]
    base_url = manifest_url.rsplit("/", 1)[0] + "/"
    payloads = {manifest_url: gz_json(manifest)}
    for pack, (index_bytes, shard_bytes) in pack_bytes.items():
        payloads[f"{base_url}indexes/{pack}.json.gz"] = index_bytes
        payloads[f"{base_url}records/{pack}/network_infrastructure.json.gz"] = shard_bytes

    class FakeResponse:
        def __init__(self, content=b"", status_code=200):
            self.content = content
            self.status_code = status_code

    class FakeSession:
        def __init__(self):
            self.headers = {}

        def get(self, url, timeout=30):
            if url not in payloads:
                return FakeResponse(status_code=404)
            return FakeResponse(payloads[url])

    monkeypatch.setattr(requests, "Session", FakeSession)

    manager = ModuleManager()

    assert manager.download("hardware-eol-full", quiet=True) is True
    for profile_name in (
        "hardware-eol-home",
        "hardware-eol-office",
        "hardware-eol-enterprise",
        "hardware-eol-industrial",
        "hardware-eol-service-provider",
        "hardware-eol-full",
    ):
        assert manager.is_installed(profile_name) is True
        assert manager.get_installed_at(profile_name)
        assert manager.is_expired(profile_name) is False


def test_hardware_eol_smart_profile_hash_mismatch_leaves_profile_uninstalled(
    monkeypatch,
    tmp_path,
):
    _redirect_module_cache(monkeypatch, tmp_path)

    def gz_json(data):
        return gzip.compress(json.dumps(data).encode("utf-8"))

    def pack_artifacts(pack):
        category = "network_infrastructure"
        record_id = f"hw_{pack}_001"
        index = {
            "metadata": {"schema": "sunsetscan.hardware_eol.v1"},
            "summary": {"total_records": 1},
            "indexes": {"vendor_aliases": {}},
            "model_summaries": [],
            "record_locations": {record_id: category},
            "record_shards": {
                category: {
                    "path": f"../records/{pack}/{category}.json.gz",
                    "record_count": 1,
                }
            },
        }
        shard = {
            "category": category,
            "records": [{"id": record_id, "vendor_slug": pack}],
            "positions": {record_id: 0},
        }
        return gz_json(index), gz_json(shard)

    pack_bytes = {
        pack: pack_artifacts(pack)
        for pack in ("home", "office")
    }
    manifest = {
        "metadata": {"schema": "sunsetscan.hardware_eol.smart_packs.v1"},
        "profiles": {"hardware-eol-office": {"packs": ["home", "office"]}},
        "packs": {},
    }
    for pack, (index_bytes, shard_bytes) in pack_bytes.items():
        shard_hash = hashlib.sha256(shard_bytes).hexdigest()
        if pack == "office":
            shard_hash = hashlib.sha256(b"not the office shard").hexdigest()
        manifest["packs"][pack] = {
            "record_count": 1,
            "index": {
                "path": f"indexes/{pack}.json.gz",
                "sha256": hashlib.sha256(index_bytes).hexdigest(),
            },
            "shards": {
                "network_infrastructure": {
                    "path": f"records/{pack}/network_infrastructure.json.gz",
                    "sha256": shard_hash,
                }
            },
        }

    manifest_url = module_manager.MODULE_REGISTRY["hardware-eol-office"]["url"]
    base_url = manifest_url.rsplit("/", 1)[0] + "/"
    payloads = {manifest_url: gz_json(manifest)}
    for pack, (index_bytes, shard_bytes) in pack_bytes.items():
        payloads[f"{base_url}indexes/{pack}.json.gz"] = index_bytes
        payloads[f"{base_url}records/{pack}/network_infrastructure.json.gz"] = shard_bytes

    requested = []

    class FakeResponse:
        def __init__(self, content=b"", status_code=200):
            self.content = content
            self.status_code = status_code

    class FakeSession:
        def __init__(self):
            self.headers = {}

        def get(self, url, timeout=30):
            requested.append(url)
            if url not in payloads:
                return FakeResponse(status_code=404)
            return FakeResponse(payloads[url])

    monkeypatch.setattr(requests, "Session", FakeSession)

    manager = ModuleManager()

    assert manager.download("hardware-eol-office", quiet=True) is False
    assert manager.is_installed("hardware-eol-office") is False

    hardware_dir = tmp_path / "data" / "cache" / "hardware_eol"
    assert not (hardware_dir / "manifest.json").exists()
    assert not (hardware_dir / "indexes" / "home.json").exists()
    assert not (hardware_dir / "indexes" / "office.json").exists()
    assert not (
        hardware_dir / "records" / "home" / "network_infrastructure.json"
    ).exists()
    assert not (
        hardware_dir / "records" / "office" / "network_infrastructure.json"
    ).exists()
    assert f"{base_url}records/office/network_infrastructure.json.gz" in requested
