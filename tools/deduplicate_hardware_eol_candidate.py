#!/usr/bin/env python3
"""Deduplicate a staged hardware EOL candidate by importer identity key."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

_LOCAL_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_LOCAL_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_LOCAL_PROJECT_ROOT))

from tools.apply_hardware_eol_policy import rebuild_model_summaries, rebuild_summary
from tools.ingest_raw_hardware_eol_sources import (
    import_builder,
    import_dedupe_key,
    record_date_score,
)


ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))


def date_values(record: dict[str, Any]) -> list[str]:
    return [
        value
        for value in (record.get("dates") or {}).values()
        if isinstance(value, str) and ISO_DATE_RE.match(value)
    ]


def source_authority_score(record: dict[str, Any]) -> int:
    source = record.get("source") or {}
    source_text = " ".join(
        str(source.get(key) or "")
        for key in ("url", "raw_file", "source_hint", "source_table")
    ).casefold()
    score = 0
    if "cisco.com/" in source_text:
        score += 30
    if "-fr." in source_text or source_text.endswith("-fr.html"):
        score -= 40
    if "downloads1.netgear.com" in source_text:
        score += 30
    if "nfb_eol_product_list" in source_text:
        score += 20
    if "downloads.netgear.com/files/netgear/pdfs/eol.pdf" in source_text:
        score += 5
    if "supportannouncement.us.dlink.com" in source_text:
        score += 20
    if "support.juniper.net" in source_text:
        score += 20
    if "netwifiworks.com" in source_text:
        score -= 20
    return score


def clean_identity_score(record: dict[str, Any]) -> int:
    score = 0
    for field in ("part_number", "model"):
        value = str(record.get(field) or "")
        if value and not value.startswith("#"):
            score += 2
        if value and not re.search(r"[=#)]\s*$", value):
            score += 2
    return score


def lifecycle_score(record: dict[str, Any]) -> int:
    lifecycle = record.get("lifecycle") or {}
    score = 0
    if lifecycle.get("receives_security_updates") is not None:
        score += 2
    if lifecycle.get("status") not in (None, "unknown"):
        score += 1
    return score


def record_rank(record: dict[str, Any]) -> tuple[Any, ...]:
    dates = date_values(record)
    return (
        record_date_score(record),
        len(dates),
        source_authority_score(record),
        max(dates) if dates else "",
        clean_identity_score(record),
        lifecycle_score(record),
        str(record.get("id") or ""),
    )


def compact_record(record: dict[str, Any]) -> dict[str, Any]:
    source = record.get("source") or {}
    dates = {key: value for key, value in (record.get("dates") or {}).items() if value}
    lifecycle = record.get("lifecycle") or {}
    return {
        "id": record.get("id"),
        "vendor_slug": record.get("vendor_slug"),
        "model": record.get("model"),
        "part_number": record.get("part_number"),
        "hardware_version": record.get("hardware_version"),
        "region": record.get("region"),
        "dates": dates,
        "status": lifecycle.get("status"),
        "receives_security_updates": lifecycle.get("receives_security_updates"),
        "source_url": source.get("url"),
        "source_hint": source.get("source_hint"),
    }


def deduplicate_records(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[import_dedupe_key(record)].append(record)

    kept: list[dict[str, Any]] = []
    duplicate_groups = []
    removed_by_vendor = Counter()
    duplicate_records_removed = 0

    for key, group in grouped.items():
        if len(group) == 1:
            kept.append(group[0])
            continue
        chosen = max(group, key=record_rank)
        kept.append(chosen)
        removed = [record for record in group if record is not chosen]
        duplicate_records_removed += len(removed)
        removed_by_vendor.update(str(record.get("vendor_slug") or "") for record in removed)
        duplicate_groups.append(
            {
                "import_key": list(key),
                "group_size": len(group),
                "kept": compact_record(chosen),
                "removed": [compact_record(record) for record in removed],
            }
        )

    kept.sort(
        key=lambda record: (
            str(record.get("vendor_slug") or ""),
            str(record.get("model_key") or ""),
            str(record.get("part_number") or ""),
            str(record.get("region") or ""),
            str(record.get("id") or ""),
        )
    )
    report = {
        "duplicate_groups_before": len(duplicate_groups),
        "duplicate_records_removed": duplicate_records_removed,
        "removed_by_vendor": dict(sorted(removed_by_vendor.items())),
        "duplicate_groups": duplicate_groups,
    }
    return kept, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--scraper-root", required=True, type=Path)
    args = parser.parse_args()

    database = load_json(args.input)
    records = list(database.get("records") or [])
    if not records:
        raise SystemExit("input database has no records")

    deduped, report = deduplicate_records(records)
    builder = import_builder(args.scraper_root)
    database["records"] = deduped
    database["model_summaries"] = builder.build_model_summaries(deduped)
    database["indexes"] = builder.build_indexes(deduped)
    database["summary"] = builder.build_summary(deduped, database["model_summaries"])
    rebuild_model_summaries(database)
    rebuild_summary(database)
    metadata = database.setdefault("metadata", {})
    metadata["dedupe_correction"] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_stage": args.input.name,
        "policy": (
            "Collapse duplicate importer identity keys by keeping the strongest "
            "row-level vendor evidence and removing weaker duplicate records."
        ),
        "duplicate_groups_before": report["duplicate_groups_before"],
        "duplicate_records_removed": report["duplicate_records_removed"],
        "removed_by_vendor": report["removed_by_vendor"],
    }

    output_report = {
        "input": str(args.input),
        "output": str(args.output),
        "input_records": len(records),
        "output_records": len(deduped),
        **report,
    }
    write_json(args.output, database)
    write_json(args.report, output_report)
    print(f"input_records={len(records)}")
    print(f"output_records={len(deduped)}")
    print(f"duplicate_groups_before={report['duplicate_groups_before']}")
    print(f"duplicate_records_removed={report['duplicate_records_removed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
