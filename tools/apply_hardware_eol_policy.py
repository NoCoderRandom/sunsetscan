#!/usr/bin/env python3
"""Apply NetWatch's cautious hardware EOL interpretation policy.

The raw database can contain official vendor lifecycle signals that are useful
but ambiguous. For example, "EOL", "discontinued", and "replacement available"
do not always prove that firmware/security updates have stopped. This tool
keeps the raw source data but downgrades known ambiguous source classes to
`lifecycle_review` so NetWatch does not overclaim.
"""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


AMBIGUOUS_SOURCE_HINTS = {
    "ASUS RawData extracted records": {
        "policy": "asus_eol_compliance_conflict_risk",
        "confidence": "medium",
        "reason": (
            "ASUS source data lists this model on an EOL/compliance source, "
            "but ASUS firmware pages can still publish newer firmware/security "
            "releases after the listed date. Treat as lifecycle review until a "
            "product-specific firmware feed confirms security updates have stopped."
        ),
    },
    "Brother replacement/discontinued model PDF": {
        "policy": "discontinued_not_security_eol",
    },
    "Canon archive/discontinued printer page": {
        "policy": "discontinued_not_security_eol",
    },
    "Cudy product page with EOL/discontinued signal": {
        "policy": "discontinued_not_security_eol",
    },
    "Edimax legacy/discontinued product page": {
        "policy": "discontinued_not_security_eol",
    },
    "Epson product history discontinued date": {
        "policy": "discontinued_not_security_eol",
    },
    "MikroTik product page discontinued/active status": {
        "policy": "discontinued_or_active_not_security_eol",
    },
    "TotoLink discontinued product page": {
        "policy": "discontinued_not_security_eol",
    },
    "Ubiquiti EOL/discontinued reseller list": {
        "policy": "third_party_or_discontinued_not_security_eol",
    },
}

GENERIC_REVIEW_REASON = (
    "Source shows EOL, discontinued, replacement, reseller, or product-history "
    "status, but it does not prove that firmware/security updates have stopped. "
    "Treat as lifecycle review, not confirmed unsupported."
)

RISK_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def load_database(path: Path) -> dict[str, Any]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write_gzip_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


def apply_policy(database: dict[str, Any]) -> list[dict[str, Any]]:
    changed = []
    for record in database.get("records", []):
        lifecycle = record.get("lifecycle") or {}
        source = record.get("source") or {}
        hint = source.get("source_hint") or ""
        policy = AMBIGUOUS_SOURCE_HINTS.get(hint)
        if not policy or lifecycle.get("receives_security_updates") is not False:
            continue

        record.setdefault("quality", {})["interpretation_policy"] = policy["policy"]
        record["quality"]["previous_lifecycle"] = {
            "status": lifecycle.get("status"),
            "risk": lifecycle.get("risk"),
            "receives_security_updates": False,
            "reason": lifecycle.get("reason"),
        }
        record["quality"]["review_required"] = True

        lifecycle["status"] = "lifecycle_review"
        lifecycle["risk"] = "low"
        lifecycle["receives_security_updates"] = None
        lifecycle["replacement_recommended"] = False
        lifecycle["confidence"] = policy.get("confidence", "low")
        lifecycle["reason"] = policy.get("reason", GENERIC_REVIEW_REASON)
        lifecycle["days_to_security_eol"] = None

        vendor = record.get("vendor") or record.get("vendor_slug") or ""
        model = record.get("model") or record.get("model_key") or ""
        record.setdefault("netwatch", {})["finding_title"] = (
            f"{vendor} {model} lifecycle review needed".strip()
        )
        changed.append(record)

    return changed


def rebuild_indexes(database: dict[str, Any]) -> None:
    records = database.get("records", [])
    indexes = database.setdefault("indexes", {})
    indexes["by_id"] = {
        record["id"]: pos
        for pos, record in enumerate(records)
        if record.get("id")
    }


def strongest_risk(counter: Counter) -> str:
    for risk in RISK_ORDER:
        if counter.get(risk):
            return risk
    return "unknown"


def rebuild_model_summaries(database: dict[str, Any]) -> None:
    records = database.get("records", [])
    old_summaries = {
        (summary.get("vendor_slug"), summary.get("model_key")): summary
        for summary in database.get("model_summaries", [])
    }
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        vendor_slug = record.get("vendor_slug")
        model_key = record.get("model_key")
        if vendor_slug and model_key:
            grouped.setdefault((vendor_slug, model_key), []).append(record)

    summaries = []
    for key, items in sorted(grouped.items()):
        vendor_slug, model_key = key
        statuses = Counter(item["lifecycle"]["status"] for item in items)
        risks = Counter(item["lifecycle"]["risk"] for item in items)
        update_values = [
            item["lifecycle"]["receives_security_updates"]
            for item in items
        ]
        if all(value is False for value in update_values):
            overall_updates = False
            overall_status = "unsupported"
        elif any(value is False for value in update_values):
            overall_updates = None
            overall_status = "mixed"
        elif all(value is True for value in update_values):
            overall_updates = True
            overall_status = "supported"
        elif statuses.get("lifecycle_review"):
            overall_updates = None
            overall_status = "lifecycle_review"
        else:
            overall_updates = None
            overall_status = "unknown"

        support_dates = sorted(
            date_value
            for date_value in (
                item["dates"].get("end_of_security_updates")
                for item in items
            )
            if date_value
        )
        model_names = Counter(item["model"] for item in items if item.get("model"))
        device_types = Counter(
            item["device_type"] for item in items if item.get("device_type")
        )
        old = old_summaries.get(key, {})
        note = old.get("netwatch_note") or "Lifecycle status is unknown."
        if overall_status == "lifecycle_review":
            note = (
                "Lifecycle source needs review before claiming security updates "
                "have stopped."
            )

        summaries.append(
            {
                "id": old.get("id") or f"model_{vendor_slug}_{model_key}",
                "vendor": items[0].get("vendor") or vendor_slug,
                "vendor_slug": vendor_slug,
                "model": (
                    model_names.most_common(1)[0][0]
                    if model_names else model_key
                ),
                "model_key": model_key,
                "record_ids": sorted(item["id"] for item in items),
                "record_count": len(items),
                "device_type": (
                    device_types.most_common(1)[0][0]
                    if device_types else "Network Device"
                ),
                "overall_status": overall_status,
                "receives_security_updates": overall_updates,
                "strongest_risk": strongest_risk(risks),
                "status_counts": dict(sorted(statuses.items())),
                "risk_counts": dict(sorted(risks.items())),
                "earliest_security_eol": support_dates[0] if support_dates else None,
                "latest_security_eol": support_dates[-1] if support_dates else None,
                "netwatch_note": note,
            }
        )

    database["model_summaries"] = summaries


def rebuild_summary(database: dict[str, Any]) -> None:
    records = database.get("records", [])
    model_summaries = database.get("model_summaries", [])
    vendors = Counter(record["vendor_slug"] for record in records)
    statuses = Counter(record["lifecycle"]["status"] for record in records)
    risks = Counter(record["lifecycle"]["risk"] for record in records)
    device_classes = Counter(record["device_class"] for record in records)
    no_updates = sum(
        1 for record in records
        if record["lifecycle"]["receives_security_updates"] is False
    )
    supported = sum(
        1 for record in records
        if record["lifecycle"]["receives_security_updates"] is True
    )
    model_statuses = Counter(
        summary["overall_status"] for summary in model_summaries
    )
    database["summary"] = {
        "total_records": len(records),
        "total_model_summaries": len(model_summaries),
        "records_not_receiving_security_updates": no_updates,
        "records_receiving_security_updates": supported,
        "records_unknown_security_update_status": len(records) - no_updates - supported,
        "vendors": dict(sorted(vendors.items())),
        "lifecycle_statuses": dict(sorted(statuses.items())),
        "risks": dict(sorted(risks.items())),
        "device_classes": dict(sorted(device_classes.items())),
        "model_summary_statuses": dict(sorted(model_statuses.items())),
    }


def update_metadata(database: dict[str, Any], changed_count: int) -> None:
    metadata = database.setdefault("metadata", {})
    metadata["generated_at"] = datetime.now().isoformat(timespec="seconds")
    metadata.setdefault("status_definitions", {})["lifecycle_review"] = (
        "Official source indicates EOL/discontinued/lifecycle concern, but "
        "security-update status is not confirmed or may conflict with firmware "
        "evidence."
    )
    metadata["interpretation_policy"] = {
        "name": "cautious_policy_v2",
        "purpose": (
            "Prevent EOL/discontinued/end-of-sale sources from being treated "
            "as confirmed loss of security updates unless the source explicitly "
            "proves that."
        ),
        "changed_records": changed_count,
        "rule": (
            "Ambiguous status-only/discontinued/vendor EOL-list records become "
            "lifecycle_review with unknown receives_security_updates."
        ),
    }


def build_policy_report(
    database: dict[str, Any],
    changed: list[dict[str, Any]],
    source_path: Path,
) -> dict[str, Any]:
    return {
        "generated_at": database.get("metadata", {}).get("generated_at"),
        "source_database": str(source_path),
        "changed_records": len(changed),
        "changed_by_vendor": dict(
            Counter(record.get("vendor_slug") for record in changed).most_common()
        ),
        "changed_by_source_hint": dict(
            Counter(
                (record.get("source") or {}).get("source_hint") or ""
                for record in changed
            ).most_common()
        ),
        "summary": database.get("summary", {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--output-gz", required=True, type=Path)
    parser.add_argument("--output-summary", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    database = load_database(args.input)
    changed = apply_policy(database)
    rebuild_indexes(database)
    rebuild_model_summaries(database)
    rebuild_summary(database)
    update_metadata(database, len(changed))

    write_json(args.output_json, database)
    write_gzip_json(args.output_gz, database)
    write_json(
        args.output_summary,
        {
            "metadata": database["metadata"],
            "summary": database["summary"],
        },
    )
    if args.report:
        write_json(args.report, build_policy_report(database, changed, args.input))

    print(f"changed_records={len(changed)}")
    print(
        "records_not_receiving_security_updates="
        f"{database['summary']['records_not_receiving_security_updates']}"
    )
    print(
        "lifecycle_review="
        f"{database['summary']['lifecycle_statuses'].get('lifecycle_review', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
