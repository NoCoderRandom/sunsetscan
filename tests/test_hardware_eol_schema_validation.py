import json

from tools.validate_hardware_eol_database import (
    validate_monolithic_database,
    validate_record_schema,
    validate_split_database,
)


def _sample_record():
    return {
        "id": "hw_example_abc",
        "vendor": "Example",
        "vendor_slug": "example",
        "model": "ABC-1",
        "model_key": "abc 1",
        "product_name": "Example ABC-1",
        "part_number": "ABC-1",
        "hardware_version": None,
        "region": None,
        "device_type": "Network Switch",
        "device_class": "network_switch",
        "description": "Network Switch",
        "dates": {
            "announcement": None,
            "last_sale": None,
            "end_of_sale": None,
            "end_of_life": None,
            "end_of_support": "2024-01-01",
            "end_of_service": None,
            "end_of_vulnerability": None,
            "end_of_security_updates": "2024-01-01",
        },
        "lifecycle": {
            "status": "unsupported",
            "risk": "critical",
            "receives_security_updates": False,
            "replacement_recommended": True,
            "confidence": "high",
            "reason": "Security/support updates ended on 2024-01-01.",
            "days_to_security_eol": -864,
        },
        "replacement": None,
        "match": {
            "aliases": ["ABC-1", "Example ABC-1"],
            "alias_keys": ["abc 1", "example abc 1"],
            "vendor_model_key": "example|abc 1",
        },
        "source": {
            "url": "https://example.invalid/lifecycle",
            "raw_file": "output/RawData/example/raw/lifecycle.html",
            "status_text": "end of support",
            "source_hint": "Example lifecycle table import",
        },
        "sunsetscan": {
            "match_priority": 90,
            "finding_title": "Example ABC-1 no longer receives security updates",
        },
    }


def _sample_index(record):
    return {
        "metadata": {
            "schema": "sunsetscan.hardware_eol.v1",
            "artifact_layout": {"format": "split", "version": 1},
        },
        "summary": {"total_records": 1},
        "indexes": {
            "by_id": {record["id"]: 0},
            "by_vendor": {"example": [record["id"]]},
            "by_model_key": {"abc 1": [record["id"]]},
            "by_vendor_model_key": {"example|abc 1": [record["id"]]},
            "by_part_key": {
                "example|abc 1": [record["id"]],
                "abc 1": [record["id"]],
            },
            "by_alias_key": {"abc 1": [record["id"]]},
            "vendor_aliases": {"example": "example"},
        },
        "model_summaries": [
            {
                "id": "model_example_abc_1",
                "vendor": "Example",
                "vendor_slug": "example",
                "model": "ABC-1",
                "model_key": "abc 1",
                "record_ids": [record["id"]],
                "record_count": 1,
                "device_type": "Network Switch",
                "overall_status": "unsupported",
                "receives_security_updates": False,
                "strongest_risk": "critical",
                "status_counts": {"unsupported": 1},
                "risk_counts": {"critical": 1},
                "earliest_security_eol": "2024-01-01",
                "latest_security_eol": "2024-01-01",
                "sunsetscan_note": "All known records for this model are unsupported.",
            }
        ],
        "record_shards": {
            "network_infrastructure": {
                "label": "Network Infrastructure",
                "path": "records/network_infrastructure.json",
                "record_count": 1,
            }
        },
        "record_locations": {record["id"]: "network_infrastructure"},
    }


def test_valid_split_database_matches_current_schema(tmp_path):
    record = _sample_record()
    records_dir = tmp_path / "records"
    records_dir.mkdir()
    (records_dir / "network_infrastructure.json").write_text(
        json.dumps(
            {
                "category": "network_infrastructure",
                "records": [record],
                "indexes": {"by_id": {record["id"]: 0}},
            }
        ),
        encoding="utf-8",
    )

    issues = validate_split_database(_sample_index(record), index_path=tmp_path / "index.json")

    assert issues == []


def test_record_schema_rejects_old_netwatch_shape():
    record = _sample_record()
    record["netwatch"] = {
        "match_priority": 90,
        "finding_title": "old shape",
    }

    issues = validate_record_schema(record, path="record")

    assert any("unexpected keys: netwatch" in str(issue) for issue in issues)


def test_record_schema_rejects_security_date_precedence_change():
    record = _sample_record()
    record["dates"]["end_of_support"] = "2024-01-01"
    record["dates"]["end_of_life"] = "2025-01-01"
    record["dates"]["end_of_security_updates"] = "2025-01-01"

    issues = validate_record_schema(record, path="record")

    assert any("must follow existing precedence" in str(issue) for issue in issues)


def test_monolithic_database_rejects_unknown_model_summary_record_id():
    record = _sample_record()
    database = _sample_index(record)
    database["records"] = [record]
    database.pop("record_shards")
    database.pop("record_locations")
    database["model_summaries"][0]["record_ids"] = ["missing"]

    issues = validate_monolithic_database(database)

    assert any("unknown record ids: missing" in str(issue) for issue in issues)
