#!/usr/bin/env python3
"""Split the NetWatch hardware EOL database into category shards.

The split artifact keeps global lookup indexes and model summaries in a small
index file, while full record detail lives in a few compressed category files.
"""

from __future__ import annotations

import argparse
import gzip
import json
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


CATEGORY_DEFINITIONS = {
    "network_infrastructure": {
        "label": "Network Infrastructure",
        "device_classes": {
            "router",
            "network_switch",
            "wireless_access_point",
            "controller",
            "modem",
        },
    },
    "general_network_devices": {
        "label": "General Network Devices",
        "device_classes": {
            "network_device",
        },
    },
    "security_surveillance": {
        "label": "Security and Surveillance",
        "device_classes": {
            "security_appliance",
            "ip_camera",
        },
    },
    "endpoints_peripherals": {
        "label": "Endpoints and Peripherals",
        "device_classes": {
            "printer",
            "nas",
            "network_adapter",
            "powerline",
            "smart_home",
        },
    },
    "software_services_modules": {
        "label": "Software, Services, and Modules",
        "device_classes": {
            "software",
            "service",
            "module",
            "accessory",
        },
    },
}

CLASS_TO_CATEGORY = {
    device_class: category
    for category, definition in CATEGORY_DEFINITIONS.items()
    for device_class in definition["device_classes"]
}
DEFAULT_CATEGORY = "general_network_devices"


def load_json(path: Path) -> dict[str, Any]:
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


def backup_existing(path: Path) -> None:
    if not path.exists():
        return
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(f"{path.name}.bak.{stamp}")
    shutil.copy2(path, backup)


def category_for(record: dict[str, Any]) -> str:
    device_class = str(record.get("device_class") or "").strip()
    return CLASS_TO_CATEGORY.get(device_class, DEFAULT_CATEGORY)


def split_database(database: dict[str, Any]) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    records = database.get("records") or []
    if not records:
        raise ValueError("input database has no records")

    shards = {category: [] for category in CATEGORY_DEFINITIONS}
    record_locations: dict[str, str] = {}

    for record in records:
        record_id = str(record.get("id") or "")
        if not record_id:
            continue
        category = category_for(record)
        shards.setdefault(category, []).append(record)
        record_locations[record_id] = category

    missing_locations = len(records) - len(record_locations)
    if missing_locations:
        raise ValueError(f"{missing_locations} records have no usable id")

    index = {
        key: value
        for key, value in database.items()
        if key != "records"
    }
    metadata = index.setdefault("metadata", {})
    metadata["artifact_layout"] = {
        "format": "split",
        "version": 1,
        "index_file": "netwatch_hardware_eol_index.json.gz",
        "category_count": len(CATEGORY_DEFINITIONS),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }

    record_shards = {}
    for category, items in shards.items():
        definition = CATEGORY_DEFINITIONS[category]
        classes = Counter(str(record.get("device_class") or "unknown") for record in items)
        record_shards[category] = {
            "label": definition["label"],
            "path": f"records/{category}.json.gz",
            "record_count": len(items),
            "device_classes": dict(sorted(classes.items())),
        }

    index["record_shards"] = record_shards
    index["record_locations"] = record_locations
    return index, shards


def build_shard(category: str, records: list[dict[str, Any]], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "metadata": {
            "schema": source.get("metadata", {}).get("schema"),
            "source_generated_at": source.get("metadata", {}).get("generated_at"),
            "split_generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "category": category,
        "label": CATEGORY_DEFINITIONS[category]["label"],
        "record_count": len(records),
        "records": records,
        "indexes": {
            "by_id": {
                str(record["id"]): pos
                for pos, record in enumerate(records)
                if record.get("id")
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--no-backup", action="store_true")
    args = parser.parse_args()

    database = load_json(args.input)
    index, shards = split_database(database)

    index_path = args.output_dir / "netwatch_hardware_eol_index.json.gz"
    summary_path = args.summary or args.output_dir / "netwatch_hardware_eol_summary.json"
    if not args.no_backup:
        backup_existing(index_path)
        backup_existing(summary_path)
        for category in CATEGORY_DEFINITIONS:
            backup_existing(args.output_dir / "records" / f"{category}.json.gz")

    write_gzip_json(index_path, index)
    for category, records in shards.items():
        shard = build_shard(category, records, database)
        write_gzip_json(args.output_dir / "records" / f"{category}.json.gz", shard)

    write_json(
        summary_path,
        {
            "metadata": index["metadata"],
            "summary": index.get("summary", {}),
            "record_shards": index["record_shards"],
        },
    )

    total = sum(len(items) for items in shards.values())
    print(f"records={total}")
    for category, items in shards.items():
        print(f"{category}={len(items)}")
    print(f"index={index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
