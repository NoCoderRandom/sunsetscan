from pathlib import Path
import json

import core.hardware_eol as hardware_eol
from core.hardware_eol import HardwareEOLDatabase
from core.module_manager import _parse_hardware_eol, _parse_hardware_eol_shard


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HARDWARE_EOL_DIR = PROJECT_ROOT / "data" / "hardware_eol"
INDEX_PATH = HARDWARE_EOL_DIR / "sunsetscan_hardware_eol_index.json.gz"


def test_split_database_artifacts_are_compressed_and_consistent():
    assert INDEX_PATH.exists()
    assert not (HARDWARE_EOL_DIR / "sunsetscan_hardware_eol_index.json").exists()
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
    developer_split_index = repo_dir / "sunsetscan_hardware_eol_index.json.gz"
    legacy_cache_monolith.write_text("{}", encoding="utf-8")
    developer_split_index.write_bytes(b"placeholder")

    monkeypatch.setattr(hardware_eol, "_DEFAULT_DB_PATH", legacy_cache_monolith)
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_PATH", cache_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_GZ_PATH", cache_dir / "missing_manifest.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_INDEX_PATH", cache_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_DB_PATH", legacy_cache_monolith)
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_INDEX_PATH", cache_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_PATH", repo_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_GZ_PATH", repo_dir / "missing_manifest.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_PATH", repo_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_GZ_PATH", developer_split_index)
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_PATH", repo_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_monolith.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_PATH", repo_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_GZ_PATH", repo_dir / "missing_legacy_index.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_PATH", repo_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_legacy_monolith.json.gz")

    assert HardwareEOLDatabase()._candidate_path() == developer_split_index


def test_developer_smart_pack_manifest_preferred_over_developer_split_index(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache" / "hardware_eol"
    repo_dir = tmp_path / "repo" / "hardware_eol"
    cache_dir.mkdir(parents=True)
    repo_dir.mkdir(parents=True)

    developer_manifest = repo_dir / "manifest.json.gz"
    developer_split_index = repo_dir / "sunsetscan_hardware_eol_index.json.gz"
    developer_manifest.write_bytes(b"placeholder")
    developer_split_index.write_bytes(b"placeholder")

    monkeypatch.setattr(hardware_eol, "_DEFAULT_DB_PATH", cache_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_PATH", cache_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_GZ_PATH", cache_dir / "missing_manifest.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_INDEX_PATH", cache_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_DB_PATH", cache_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_INDEX_PATH", cache_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_PATH", repo_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_GZ_PATH", developer_manifest)
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_PATH", repo_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_GZ_PATH", developer_split_index)
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_PATH", repo_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_monolith.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_PATH", repo_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_GZ_PATH", repo_dir / "missing_legacy_index.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_PATH", repo_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_legacy_monolith.json.gz")

    assert HardwareEOLDatabase()._candidate_path() == developer_manifest


def test_cache_smart_pack_manifest_preferred_over_cache_split_index_and_developer_manifest(
    tmp_path,
    monkeypatch,
):
    cache_dir = tmp_path / "cache" / "hardware_eol"
    repo_dir = tmp_path / "repo" / "hardware_eol"
    cache_dir.mkdir(parents=True)
    repo_dir.mkdir(parents=True)

    cache_manifest = cache_dir / "manifest.json"
    cache_split_index = cache_dir / "sunsetscan_hardware_eol_index.json"
    developer_manifest = repo_dir / "manifest.json.gz"
    cache_manifest.write_text("{}", encoding="utf-8")
    cache_split_index.write_text("{}", encoding="utf-8")
    developer_manifest.write_bytes(b"placeholder")

    monkeypatch.setattr(hardware_eol, "_DEFAULT_DB_PATH", cache_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_PATH", cache_manifest)
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_GZ_PATH", cache_dir / "missing_manifest.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_INDEX_PATH", cache_split_index)
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_DB_PATH", cache_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_INDEX_PATH", cache_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_PATH", repo_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_GZ_PATH", developer_manifest)
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_PATH", repo_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_GZ_PATH", repo_dir / "missing_index.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_PATH", repo_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_monolith.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_PATH", repo_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_GZ_PATH", repo_dir / "missing_legacy_index.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_PATH", repo_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_legacy_monolith.json.gz")

    assert HardwareEOLDatabase()._candidate_path() == cache_manifest


def test_cache_split_index_preferred_over_bundled_developer_manifest(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache" / "hardware_eol"
    repo_dir = tmp_path / "repo" / "hardware_eol"
    cache_dir.mkdir(parents=True)
    repo_dir.mkdir(parents=True)

    cache_split_index = cache_dir / "sunsetscan_hardware_eol_index.json"
    developer_manifest = repo_dir / "manifest.json.gz"
    cache_split_index.write_text("{}", encoding="utf-8")
    developer_manifest.write_bytes(b"placeholder")

    monkeypatch.setattr(hardware_eol, "_DEFAULT_DB_PATH", cache_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_PATH", cache_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_MANIFEST_GZ_PATH", cache_dir / "missing_manifest.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEFAULT_INDEX_PATH", cache_split_index)
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_DB_PATH", cache_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEFAULT_INDEX_PATH", cache_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_PATH", repo_dir / "missing_manifest.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_MANIFEST_GZ_PATH", developer_manifest)
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_PATH", repo_dir / "missing_index.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_INDEX_GZ_PATH", repo_dir / "missing_index.json.gz")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_PATH", repo_dir / "missing_monolith.json")
    monkeypatch.setattr(hardware_eol, "_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_monolith.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_PATH", repo_dir / "missing_legacy_index.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_INDEX_GZ_PATH", repo_dir / "missing_legacy_index.json.gz")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_PATH", repo_dir / "missing_legacy_monolith.json")
    monkeypatch.setattr(hardware_eol, "_LEGACY_DEVELOPER_DB_GZ_PATH", repo_dir / "missing_legacy_monolith.json.gz")

    assert HardwareEOLDatabase()._candidate_path() == cache_split_index


def _smart_pack_record(record_id, vendor, vendor_slug, model):
    model_key = model.lower().replace("-", " ")
    return {
        "id": record_id,
        "vendor": vendor,
        "vendor_slug": vendor_slug,
        "model": model,
        "model_key": model_key,
        "product_name": f"{vendor} {model}",
        "part_number": model,
        "hardware_version": None,
        "region": None,
        "device_type": "Router",
        "device_class": "router",
        "description": None,
        "dates": {
            "announcement": None,
            "last_sale": None,
            "end_of_sale": None,
            "end_of_life": "2025-01-01",
            "end_of_support": "2025-01-01",
            "end_of_service": None,
            "end_of_vulnerability": None,
            "end_of_security_updates": "2025-01-01",
        },
        "lifecycle": {
            "status": "unsupported",
            "risk": "critical",
            "receives_security_updates": False,
            "replacement_recommended": True,
            "confidence": "high",
            "reason": "Security/support updates ended on 2025-01-01.",
            "days_to_security_eol": -1,
        },
        "replacement": None,
        "match": {
            "aliases": [model, f"{vendor} {model}"],
            "alias_keys": [model_key, f"{vendor_slug} {model_key}"],
            "vendor_model_key": f"{vendor_slug}|{model_key}",
        },
        "source": {
            "url": "https://example.test/eol",
            "raw_file": "test.json",
            "status_text": "End of Support",
            "source_hint": "test source",
        },
        "sunsetscan": {
            "match_priority": 90,
            "finding_title": f"{vendor} {model} no longer receives security updates",
        },
    }


def _write_smart_pack(tmp_path, pack, record):
    index_dir = tmp_path / "indexes"
    shard_dir = tmp_path / "records" / pack
    index_dir.mkdir(parents=True, exist_ok=True)
    shard_dir.mkdir(parents=True, exist_ok=True)

    category = "network_infrastructure"
    shard_path = shard_dir / f"{category}.json"
    shard_path.write_text(
        json.dumps(
            {
                "category": category,
                "records": [record],
                "indexes": {"by_id": {record["id"]: 0}},
            }
        ),
        encoding="utf-8",
    )

    index_path = index_dir / f"{pack}.json"
    index_path.write_text(
        json.dumps(
            {
                "metadata": {"schema": "sunsetscan.hardware_eol.v1"},
                "summary": {"total_records": 1},
                "indexes": {
                    "vendor_aliases": {record["vendor_slug"]: record["vendor_slug"]},
                    "by_id": {record["id"]: 0},
                    "by_vendor_model_key": {
                        record["match"]["vendor_model_key"]: [record["id"]]
                    },
                    "by_part_key": {},
                    "by_alias_key": {},
                },
                "model_summaries": [
                    {
                        "id": f"model_{record['id']}",
                        "vendor": record["vendor"],
                        "vendor_slug": record["vendor_slug"],
                        "model": record["model"],
                        "model_key": record["model_key"],
                        "record_ids": [record["id"]],
                        "record_count": 1,
                        "device_type": record["device_type"],
                        "overall_status": "unsupported",
                        "receives_security_updates": False,
                        "strongest_risk": "critical",
                        "status_counts": {"unsupported": 1},
                        "risk_counts": {"critical": 1},
                        "earliest_security_eol": "2025-01-01",
                        "latest_security_eol": "2025-01-01",
                        "sunsetscan_note": "Test summary",
                    }
                ],
                "record_shards": {
                    category: {
                        "path": f"../records/{pack}/{category}.json",
                        "record_count": 1,
                    }
                },
                "record_locations": {record["id"]: category},
            }
        ),
        encoding="utf-8",
    )


def test_hardware_lookup_loads_multiple_smart_pack_indexes(tmp_path):
    asus = _smart_pack_record("hw_asus_home", "ASUS", "asus", "RT-AX92U")
    cisco = _smart_pack_record("hw_cisco_enterprise", "Cisco", "cisco", "ISR-4321")
    _write_smart_pack(tmp_path, "home", asus)
    _write_smart_pack(tmp_path, "enterprise", cisco)

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "schema": "sunsetscan.hardware_eol.smart_packs.v1",
                    "source_schema": "sunsetscan.hardware_eol.v1",
                },
                "profiles": {
                    "hardware-eol-enterprise": {
                        "packs": ["home", "enterprise"],
                    }
                },
                "vendor_pack_hints": {
                    "asus": {
                        "packs": {"home": 1},
                        "primary_pack": "home",
                        "recommended_profile": "hardware-eol-home",
                    },
                    "cisco": {
                        "packs": {"enterprise": 1},
                        "primary_pack": "enterprise",
                        "recommended_profile": "hardware-eol-enterprise",
                    },
                },
                "packs": {
                    "home": {
                        "record_count": 1,
                        "index": {"path": "indexes/home.json"},
                        "shards": {
                            "network_infrastructure": {
                                "path": "records/home/network_infrastructure.json"
                            }
                        },
                    },
                    "enterprise": {
                        "record_count": 1,
                        "index": {"path": "indexes/enterprise.json"},
                        "shards": {
                            "network_infrastructure": {
                                "path": "records/enterprise/network_infrastructure.json"
                            }
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    db = HardwareEOLDatabase(manifest_path)

    home_match = db.lookup("ASUS", "RT-AX92U")
    enterprise_match = db.lookup("Cisco", "ISR-4321")

    assert home_match is not None
    assert [record["id"] for record in home_match.records] == ["hw_asus_home"]
    assert enterprise_match is not None
    assert [record["id"] for record in enterprise_match.records] == ["hw_cisco_enterprise"]
    assert db.missing_profile_hint("Cisco") is None


def test_hardware_lookup_reports_missing_smart_pack_profile_hint(tmp_path):
    asus = _smart_pack_record("hw_asus_home", "ASUS", "asus", "RT-AX92U")
    _write_smart_pack(tmp_path, "home", asus)

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "schema": "sunsetscan.hardware_eol.smart_packs.v1",
                    "source_schema": "sunsetscan.hardware_eol.v1",
                },
                "profiles": {
                    "hardware-eol-home": {
                        "packs": ["home"],
                    }
                },
                "vendor_pack_hints": {
                    "asus": {
                        "packs": {"home": 1},
                        "primary_pack": "home",
                        "recommended_profile": "hardware-eol-home",
                    },
                    "cisco": {
                        "packs": {"enterprise": 5, "service_provider": 1},
                        "primary_pack": "enterprise",
                        "recommended_profile": "hardware-eol-enterprise",
                    },
                },
                "packs": {
                    "home": {
                        "record_count": 1,
                        "index": {"path": "indexes/home.json"},
                        "shards": {
                            "network_infrastructure": {
                                "path": "records/home/network_infrastructure.json"
                            }
                        },
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    db = HardwareEOLDatabase(manifest_path)

    hint = db.missing_profile_hint("Cisco")

    assert hint == {
        "vendor_slug": "cisco",
        "missing_pack": "enterprise",
        "recommended_profile": "hardware-eol-enterprise",
        "known_packs": ["enterprise", "service_provider"],
        "installed_packs": ["home"],
    }


def test_hardware_pipeline_emits_info_for_missing_smart_pack_profile():
    import sunsetscan
    from core.device_identifier import DeviceIdentity
    from core.findings import Severity
    from core.scanner import ScanResult

    class FakeHardwareEOL:
        def available(self):
            return True

        def lookup(self, **kwargs):
            return None

        def missing_profile_hint(self, vendor):
            assert vendor == "Cisco"
            return {
                "missing_pack": "enterprise",
                "recommended_profile": "hardware-eol-enterprise",
                "known_packs": ["enterprise"],
                "installed_packs": ["home"],
            }

    app = sunsetscan.SunsetScan.__new__(sunsetscan.SunsetScan)
    app.hardware_eol = FakeHardwareEOL()
    app.last_device_identities = {
        "192.0.2.10": DeviceIdentity(vendor="Cisco", model="ISR-4321")
    }

    findings = app._run_hardware_eol_pipeline(ScanResult(target="192.0.2.0/24", profile="TEST"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.INFO
    assert finding.category == "Hardware Lifecycle Coverage"
    assert "This is not an end-of-life finding" in finding.explanation
    assert "hardware-eol-enterprise" in finding.recommendation
    assert "missing-hardware-eol-pack" in finding.tags


def test_hardware_pipeline_emits_confirmed_eol_finding_without_lan_scan():
    import sunsetscan
    from core.device_identifier import DeviceIdentity
    from core.findings import Severity
    from core.hardware_eol import HardwareEOLMatch
    from core.scanner import ScanResult

    record = {
        "id": "hw_test_router_001",
        "dates": {"end_of_security_updates": "2025-01-01"},
        "lifecycle": {
            "reason": "Security/support updates ended on 2025-01-01.",
        },
        "source": {"url": "https://vendor.example/eol"},
    }

    class FakeHardwareEOL:
        def available(self):
            return True

        def lookup(self, **kwargs):
            assert kwargs["vendor"] == "TestVendor"
            assert kwargs["model"] == "Router 1000"
            return HardwareEOLMatch(
                vendor="TestVendor",
                model="Router 1000",
                canonical_vendor="testvendor",
                model_key="router 1000",
                match_type="vendor_model",
                status="unsupported",
                risk="critical",
                finding_title="TestVendor Router 1000 no longer receives security updates",
                receives_security_updates=False,
                records=[record],
                selected_record=record,
                confidence="high",
            )

        def missing_profile_hint(self, vendor):
            raise AssertionError("No profile hint should be requested after a match")

    app = sunsetscan.SunsetScan.__new__(sunsetscan.SunsetScan)
    app.hardware_eol = FakeHardwareEOL()
    app.last_device_identities = {
        "192.0.2.20": DeviceIdentity(vendor="TestVendor", model="Router 1000")
    }

    findings = app._run_hardware_eol_pipeline(ScanResult(target="192.0.2.0/24", profile="TEST"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.category == "Hardware Lifecycle"
    assert finding.host == "192.0.2.20"
    assert "no longer receives security updates" in finding.title
    assert "2025-01-01" in finding.evidence
    assert "hardware-eol" in finding.tags
