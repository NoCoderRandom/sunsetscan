#!/usr/bin/env python3
"""Validate SunsetScan hardware EOL database schema and split artifacts."""

from __future__ import annotations

import argparse
import gzip
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


REQUIRED_RECORD_KEYS = {
    "id",
    "vendor",
    "vendor_slug",
    "model",
    "model_key",
    "product_name",
    "part_number",
    "hardware_version",
    "region",
    "device_type",
    "device_class",
    "description",
    "dates",
    "lifecycle",
    "replacement",
    "match",
    "source",
    "sunsetscan",
}
OPTIONAL_RECORD_KEYS = {"quality"}

DATE_KEYS = {
    "announcement",
    "last_sale",
    "end_of_sale",
    "end_of_life",
    "end_of_support",
    "end_of_service",
    "end_of_vulnerability",
    "end_of_security_updates",
}
LIFECYCLE_KEYS = {
    "status",
    "risk",
    "receives_security_updates",
    "replacement_recommended",
    "confidence",
    "reason",
    "days_to_security_eol",
}
MATCH_KEYS = {"aliases", "alias_keys", "vendor_model_key"}
SOURCE_KEYS = {"url", "raw_file", "status_text", "source_hint"}
SUNSETSCAN_KEYS = {"match_priority", "finding_title"}
QUALITY_KEYS = {"interpretation_policy", "previous_lifecycle", "review_required"}

VALID_LIFECYCLE_STATUSES = {
    "unsupported",
    "unsupported_status_only",
    "support_ending_soon",
    "lifecycle_review",
    "end_of_sale",
    "vendor_eol_but_supported",
    "supported",
    "supported_status_only",
    "unknown",
}
VALID_RISKS = {"critical", "high", "medium", "low", "info", "unknown"}
VALID_CONFIDENCE = {"high", "medium", "low"}
SECURITY_DATE_PRECEDENCE = (
    "end_of_support",
    "end_of_vulnerability",
    "end_of_service",
    "end_of_life",
)


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def load_json(path: Path) -> Any:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _issue(path: str, message: str) -> ValidationIssue:
    return ValidationIssue(path=path, message=message)


def _validate_exact_keys(
    value: Any,
    *,
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> list[ValidationIssue]:
    optional = optional or set()
    if not isinstance(value, dict):
        return [_issue(path, "must be an object")]

    keys = set(value)
    issues = []
    missing = sorted(required - keys)
    unexpected = sorted(keys - required - optional)
    if missing:
        issues.append(_issue(path, f"missing keys: {', '.join(missing)}"))
    if unexpected:
        issues.append(_issue(path, f"unexpected keys: {', '.join(unexpected)}"))
    return issues


def _validate_iso_date(value: Any, path: str) -> list[ValidationIssue]:
    if value is None:
        return []
    if not isinstance(value, str):
        return [_issue(path, "date value must be null or ISO date string")]
    try:
        date.fromisoformat(value)
    except ValueError:
        return [_issue(path, f"invalid ISO date: {value!r}")]
    return []


def _first_date(dates: dict[str, Any]) -> Any:
    for key in SECURITY_DATE_PRECEDENCE:
        if dates.get(key):
            return dates[key]
    return None


def validate_record_schema(record: Any, *, path: str) -> list[ValidationIssue]:
    issues = _validate_exact_keys(
        record,
        path=path,
        required=REQUIRED_RECORD_KEYS,
        optional=OPTIONAL_RECORD_KEYS,
    )
    if issues or not isinstance(record, dict):
        return issues

    if "netwatch" in record:
        issues.append(_issue(f"{path}.netwatch", "old scraper-only field is not allowed"))

    dates = record.get("dates")
    issues.extend(_validate_exact_keys(dates, path=f"{path}.dates", required=DATE_KEYS))
    if isinstance(dates, dict):
        for key in DATE_KEYS:
            issues.extend(_validate_iso_date(dates.get(key), f"{path}.dates.{key}"))
        expected_security = _first_date(dates)
        if dates.get("end_of_security_updates") != expected_security:
            issues.append(
                _issue(
                    f"{path}.dates.end_of_security_updates",
                    "must follow existing precedence: end_of_support, "
                    "end_of_vulnerability, end_of_service, end_of_life",
                )
            )

    lifecycle = record.get("lifecycle")
    issues.extend(
        _validate_exact_keys(
            lifecycle,
            path=f"{path}.lifecycle",
            required=LIFECYCLE_KEYS,
        )
    )
    if isinstance(lifecycle, dict):
        if lifecycle.get("status") not in VALID_LIFECYCLE_STATUSES:
            issues.append(_issue(f"{path}.lifecycle.status", "unknown lifecycle status"))
        if lifecycle.get("risk") not in VALID_RISKS:
            issues.append(_issue(f"{path}.lifecycle.risk", "unknown risk value"))
        if lifecycle.get("confidence") not in VALID_CONFIDENCE:
            issues.append(_issue(f"{path}.lifecycle.confidence", "unknown confidence value"))
        if lifecycle.get("receives_security_updates") not in {True, False, None}:
            issues.append(
                _issue(
                    f"{path}.lifecycle.receives_security_updates",
                    "must be true, false, or null",
                )
            )
        if not isinstance(lifecycle.get("replacement_recommended"), bool):
            issues.append(
                _issue(f"{path}.lifecycle.replacement_recommended", "must be a boolean")
            )

    issues.extend(
        _validate_exact_keys(record.get("match"), path=f"{path}.match", required=MATCH_KEYS)
    )
    issues.extend(
        _validate_exact_keys(record.get("source"), path=f"{path}.source", required=SOURCE_KEYS)
    )
    issues.extend(
        _validate_exact_keys(
            record.get("sunsetscan"),
            path=f"{path}.sunsetscan",
            required=SUNSETSCAN_KEYS,
        )
    )

    if "quality" in record:
        issues.extend(
            _validate_exact_keys(
                record.get("quality"),
                path=f"{path}.quality",
                required=QUALITY_KEYS,
            )
        )

    return issues


def _record_ids_from_index(index: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    indexes = index.get("indexes") or {}
    for index_name, index_value in indexes.items():
        if index_name == "vendor_aliases" or not isinstance(index_value, dict):
            continue
        for key, value in index_value.items():
            if index_name == "by_id":
                ids.add(str(key))
            elif isinstance(value, list):
                ids.update(str(item) for item in value)
    for summary in index.get("model_summaries") or []:
        ids.update(str(item) for item in summary.get("record_ids") or [])
    ids.update(str(item) for item in (index.get("record_locations") or {}))
    return ids


def _validate_record_references(
    database: dict[str, Any],
    record_ids: set[str],
    *,
    path: str,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    for index_name, index_value in (database.get("indexes") or {}).items():
        if index_name == "vendor_aliases" or not isinstance(index_value, dict):
            continue
        for key, value in index_value.items():
            if index_name == "by_id":
                if str(key) not in record_ids:
                    issues.append(_issue(f"{path}.indexes.by_id.{key}", "unknown record id"))
            elif isinstance(value, list):
                missing = sorted(str(item) for item in value if str(item) not in record_ids)
                if missing:
                    issues.append(
                        _issue(
                            f"{path}.indexes.{index_name}.{key}",
                            f"unknown record ids: {', '.join(missing[:5])}",
                        )
                    )

    for pos, summary in enumerate(database.get("model_summaries") or []):
        missing = sorted(
            str(item)
            for item in summary.get("record_ids") or []
            if str(item) not in record_ids
        )
        if missing:
            issues.append(
                _issue(
                    f"{path}.model_summaries[{pos}].record_ids",
                    f"unknown record ids: {', '.join(missing[:5])}",
                )
            )

    return issues


def validate_monolithic_database(database: Any, *, path: str = "database") -> list[ValidationIssue]:
    if not isinstance(database, dict):
        return [_issue(path, "must be an object")]
    records = database.get("records")
    if not isinstance(records, list):
        return [_issue(f"{path}.records", "must be a list")]

    issues: list[ValidationIssue] = []
    record_ids: set[str] = set()
    for pos, record in enumerate(records):
        record_path = f"{path}.records[{pos}]"
        issues.extend(validate_record_schema(record, path=record_path))
        if isinstance(record, dict):
            record_id = record.get("id")
            if not record_id:
                issues.append(_issue(f"{record_path}.id", "must not be empty"))
            elif record_id in record_ids:
                issues.append(_issue(f"{record_path}.id", f"duplicate id: {record_id}"))
            else:
                record_ids.add(str(record_id))

    issues.extend(_validate_record_references(database, record_ids, path=path))
    summary_total = (database.get("summary") or {}).get("total_records")
    if isinstance(summary_total, int) and summary_total != len(records):
        issues.append(
            _issue(
                f"{path}.summary.total_records",
                f"expected {len(records)}, got {summary_total}",
            )
        )
    return issues


def _resolve_related_path(index_path: Path, rel_path: str) -> Path:
    path = Path(rel_path)
    candidates = [path] if path.is_absolute() else [index_path.parent / path]
    extra = []
    for candidate in candidates:
        if candidate.suffix == ".gz":
            extra.append(candidate.with_suffix(""))
        else:
            extra.append(Path(f"{candidate}.gz"))
    candidates.extend(extra)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def validate_split_database(index: Any, *, index_path: Path) -> list[ValidationIssue]:
    if not isinstance(index, dict):
        return [_issue(str(index_path), "must be an object")]

    issues: list[ValidationIssue] = []
    if "records" in index:
        issues.append(_issue("index.records", "split index must not contain records"))

    layout = (index.get("metadata") or {}).get("artifact_layout") or {}
    if layout.get("format") != "split":
        issues.append(_issue("index.metadata.artifact_layout.format", "must be 'split'"))

    record_shards = index.get("record_shards")
    record_locations = index.get("record_locations")
    if not isinstance(record_shards, dict):
        return issues + [_issue("index.record_shards", "must be an object")]
    if not isinstance(record_locations, dict):
        return issues + [_issue("index.record_locations", "must be an object")]

    all_record_ids: set[str] = set()
    shard_total = 0
    for category, info in sorted(record_shards.items()):
        if not isinstance(info, dict):
            issues.append(_issue(f"index.record_shards.{category}", "must be an object"))
            continue
        rel_path = info.get("path")
        if not rel_path:
            issues.append(_issue(f"index.record_shards.{category}.path", "must not be empty"))
            continue
        shard_path = _resolve_related_path(index_path, str(rel_path))
        if not shard_path.exists():
            issues.append(_issue(str(shard_path), "shard file does not exist"))
            continue

        try:
            shard = load_json(shard_path)
        except Exception as exc:
            issues.append(_issue(str(shard_path), f"could not parse shard: {exc}"))
            continue

        if not isinstance(shard, dict):
            issues.append(_issue(str(shard_path), "shard must be an object"))
            continue
        if shard.get("category") != category:
            issues.append(
                _issue(str(shard_path), f"category mismatch: expected {category!r}")
            )

        records = shard.get("records")
        if not isinstance(records, list):
            issues.append(_issue(f"{shard_path}.records", "must be a list"))
            continue
        shard_total += len(records)
        expected_count = info.get("record_count")
        if expected_count != len(records):
            issues.append(
                _issue(
                    f"index.record_shards.{category}.record_count",
                    f"expected {len(records)}, got {expected_count}",
                )
            )

        shard_positions = ((shard.get("indexes") or {}).get("by_id") or {})
        for pos, record in enumerate(records):
            record_path = f"{shard_path}.records[{pos}]"
            issues.extend(validate_record_schema(record, path=record_path))
            if not isinstance(record, dict):
                continue
            record_id = str(record.get("id") or "")
            if not record_id:
                issues.append(_issue(f"{record_path}.id", "must not be empty"))
                continue
            if record_id in all_record_ids:
                issues.append(_issue(f"{record_path}.id", f"duplicate id: {record_id}"))
            all_record_ids.add(record_id)
            if record_locations.get(record_id) != category:
                issues.append(
                    _issue(
                        f"index.record_locations.{record_id}",
                        f"expected {category!r}, got {record_locations.get(record_id)!r}",
                    )
                )
            if shard_positions.get(record_id) != pos:
                issues.append(
                    _issue(
                        f"{shard_path}.indexes.by_id.{record_id}",
                        f"expected position {pos}, got {shard_positions.get(record_id)!r}",
                    )
                )

    location_ids = {str(key) for key in record_locations}
    missing_from_shards = sorted(location_ids - all_record_ids)
    missing_locations = sorted(all_record_ids - location_ids)
    if missing_from_shards:
        issues.append(
            _issue(
                "index.record_locations",
                f"ids not found in shards: {', '.join(missing_from_shards[:5])}",
            )
        )
    if missing_locations:
        issues.append(
            _issue(
                "index.record_locations",
                f"shard ids missing locations: {', '.join(missing_locations[:5])}",
            )
        )

    summary_total = (index.get("summary") or {}).get("total_records")
    if isinstance(summary_total, int) and summary_total != shard_total:
        issues.append(
            _issue("index.summary.total_records", f"expected {shard_total}, got {summary_total}")
        )

    referenced_ids = _record_ids_from_index(index)
    unknown_refs = sorted(referenced_ids - all_record_ids)
    if unknown_refs:
        issues.append(
            _issue("index.indexes", f"unknown referenced ids: {', '.join(unknown_refs[:5])}")
        )
    issues.extend(_validate_record_references(index, all_record_ids, path="index"))
    return issues


def validate_database_path(path: Path) -> list[ValidationIssue]:
    database = load_json(path)
    if isinstance(database, dict) and database.get("record_shards"):
        return validate_split_database(database, index_path=path)
    return validate_monolithic_database(database, path=str(path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--max-issues", type=int, default=50)
    args = parser.parse_args()

    issues = validate_database_path(args.input)
    if issues:
        print(f"validation_failed issues={len(issues)}")
        for issue in issues[: args.max_issues]:
            print(issue)
        if len(issues) > args.max_issues:
            print(f"... {len(issues) - args.max_issues} more issues")
        return 1

    print("validation_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
