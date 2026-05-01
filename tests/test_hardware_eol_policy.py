from core.hardware_eol import HardwareEOLDatabase
from tools.apply_hardware_eol_policy import apply_policy, rebuild_model_summaries, rebuild_summary


def _record(status, receives_updates, source_hint):
    return {
        "id": "hw_asus_test",
        "vendor": "ASUS",
        "vendor_slug": "asus",
        "model": "RT-AX92U",
        "model_key": "rt ax92u",
        "product_name": "ASUS RT-AX92U",
        "part_number": "RT-AX92U",
        "hardware_version": None,
        "region": None,
        "device_type": "Wireless Router",
        "device_class": "router",
        "dates": {
            "end_of_security_updates": "2025-02-28",
            "end_of_support": "2025-02-28",
            "end_of_life": "2025-02-28",
        },
        "lifecycle": {
            "status": status,
            "risk": "critical" if receives_updates is False else "low",
            "receives_security_updates": receives_updates,
            "replacement_recommended": receives_updates is False,
            "confidence": "high",
            "reason": "Security/support updates ended on 2025-02-28.",
            "days_to_security_eol": -400,
        },
        "replacement": None,
        "match": {
            "aliases": ["RT-AX92U", "ASUS RT-AX92U"],
            "alias_keys": ["rt ax92u", "asus rt ax92u"],
            "vendor_model_key": "asus|rt ax92u",
        },
        "source": {
            "url": "https://www.asus.com/event/network/eol-product/",
            "raw_file": "output/RawData/asus/extracted.json",
            "status_text": None,
            "source_hint": source_hint,
        },
        "netwatch": {
            "match_priority": 90,
            "finding_title": "ASUS RT-AX92U no longer receives security updates",
        },
    }


def _database(record):
    return {
        "metadata": {
            "schema": "netwatch.hardware_eol.v1",
            "status_definitions": {},
        },
        "summary": {},
        "records": [record],
        "model_summaries": [
            {
                "id": "model_asus_test",
                "vendor": "ASUS",
                "vendor_slug": "asus",
                "model": "RT-AX92U",
                "model_key": "rt ax92u",
                "record_ids": [record["id"]],
                "record_count": 1,
                "device_type": "Wireless Router",
                "overall_status": record["lifecycle"]["status"],
                "receives_security_updates": record["lifecycle"]["receives_security_updates"],
                "strongest_risk": record["lifecycle"]["risk"],
                "status_counts": {record["lifecycle"]["status"]: 1},
                "risk_counts": {record["lifecycle"]["risk"]: 1},
                "earliest_security_eol": "2025-02-28",
                "latest_security_eol": "2025-02-28",
                "netwatch_note": "Test summary",
            }
        ],
        "indexes": {
            "vendor_aliases": {"asus": "asus"},
            "by_id": {record["id"]: 0},
            "by_vendor_model_key": {"asus|rt ax92u": [record["id"]]},
            "by_part_key": {
                "asus|rt ax92u": [record["id"]],
                "rt ax92u": [record["id"]],
            },
            "by_alias_key": {},
        },
    }


def test_cautious_policy_downgrades_ambiguous_asus_security_claim():
    db = _database(_record("unsupported", False, "ASUS RawData extracted records"))

    changed = apply_policy(db)
    rebuild_model_summaries(db)
    rebuild_summary(db)

    assert len(changed) == 1
    lifecycle = db["records"][0]["lifecycle"]
    assert lifecycle["status"] == "lifecycle_review"
    assert lifecycle["receives_security_updates"] is None
    assert lifecycle["risk"] == "low"
    assert db["summary"]["records_not_receiving_security_updates"] == 0
    assert db["summary"]["lifecycle_statuses"]["lifecycle_review"] == 1


def test_hardware_lookup_returns_lifecycle_review_match(tmp_path):
    db = _database(_record("unsupported", False, "ASUS RawData extracted records"))
    apply_policy(db)
    rebuild_model_summaries(db)
    rebuild_summary(db)

    path = tmp_path / "hardware_eol.json"
    import json

    path.write_text(json.dumps(db), encoding="utf-8")

    match = HardwareEOLDatabase(path).lookup("ASUS", "RT-AX92U")

    assert match is not None
    assert match.status == "lifecycle_review"
    assert match.receives_security_updates is None
    assert match.review_required is True
    assert "lifecycle review needed" in match.finding_title


def test_hardware_lookup_keeps_strong_unsupported_match(tmp_path):
    db = _database(_record("unsupported", False, "Cisco RawData extracted records"))
    rebuild_model_summaries(db)
    rebuild_summary(db)

    path = tmp_path / "hardware_eol.json"
    import json

    path.write_text(json.dumps(db), encoding="utf-8")

    match = HardwareEOLDatabase(path).lookup("ASUS", "RT-AX92U")

    assert match is not None
    assert match.status == "unsupported"
    assert match.receives_security_updates is False
    assert match.review_required is False
    assert "no longer receives security updates" in match.finding_title
