#!/usr/bin/env python3
"""Build smart downloadable hardware EOL packs from a full SunsetScan DB.

This is a staging generator. It keeps the full promoted database as the source
of truth, then emits smaller non-overlapping packs with compact pack indexes and
functional record shards.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.hardware_eol import normalize_key
from tools.apply_hardware_eol_policy import rebuild_model_summaries, rebuild_summary
from tools.split_hardware_eol_database import CATEGORY_DEFINITIONS, category_for


PACKS = ("home", "office", "enterprise", "industrial_ot", "service_provider")

PROFILE_DEFINITIONS = {
    "hardware-eol-home": {
        "packs": ["home"],
        "description": "Default home/SOHO hardware lifecycle coverage.",
    },
    "hardware-eol-office": {
        "packs": ["home", "office"],
        "description": "Home plus small-office and managed SMB hardware coverage.",
    },
    "hardware-eol-enterprise": {
        "packs": ["home", "office", "enterprise"],
        "description": "Home, office, enterprise, campus, and datacenter coverage.",
    },
    "hardware-eol-industrial": {
        "packs": ["home", "office", "industrial_ot"],
        "description": "Home, office, and industrial/OT hardware coverage.",
    },
    "hardware-eol-service-provider": {
        "packs": ["home", "office", "enterprise", "service_provider"],
        "description": "Home, office, enterprise, ISP, carrier, and telco coverage.",
    },
    "hardware-eol-full": {
        "packs": list(PACKS),
        "description": "Full hardware lifecycle coverage.",
    },
}

PROFILE_FOR_PACK = {
    "home": "hardware-eol-home",
    "office": "hardware-eol-office",
    "enterprise": "hardware-eol-enterprise",
    "industrial_ot": "hardware-eol-industrial",
    "service_provider": "hardware-eol-service-provider",
}


HOME_VENDORS = {
    "amcrest",
    "arris_commscope_cpe",
    "asus",
    "asustor",
    "asustor_nas",
    "brother",
    "buffalo_nas",
    "canon",
    "cudy",
    "dlink",
    "edimax",
    "eltako",
    "epson",
    "genexis",
    "gigaset",
    "hp",
    "hp_printers_official",
    "linksys",
    "lorex",
    "mercusys",
    "netgear",
    "qnap",
    "reolink",
    "screenbeam_actiontec",
    "seagate_lacie_nas",
    "siedle",
    "synology",
    "tenda",
    "terramaster",
    "totolink",
    "tplink",
    "wd_my_cloud",
}

OFFICE_VENDORS = {
    "alcatel_lucent_enterprise",
    "allied_telesis",
    "auerswald",
    "avaya_nortel_networking",
    "avigilon",
    "axis",
    "barracuda",
    "bosch_security",
    "cisco_meraki",
    "dahua",
    "digital_watchdog",
    "draytek",
    "engenius",
    "forcepoint",
    "forescout",
    "geovision",
    "grandstream",
    "hanwha",
    "hikvision",
    "honeywell_productivity",
    "imperva",
    "ipro_panasonic",
    "kyocera_printers",
    "lancom",
    "lexmark_printers",
    "mikrotik",
    "mobotix",
    "oki_printers",
    "paloalto",
    "progress_kemp",
    "ruckus",
    "snom",
    "sonicwall",
    "sophos",
    "trendnet",
    "ubiquiti",
    "versa",
    "vivotek",
    "watchguard",
    "zyxel",
}

ENTERPRISE_VENDORS = {
    "a10",
    "arista",
    "aruba_hpe",
    "broadcom_bluecoat",
    "broadcom_brocade",
    "checkpoint",
    "cisco",
    "citrix_netscaler",
    "dell_networking",
    "edgecore",
    "extreme",
    "fortinet",
    "h3c",
    "huawei",
    "juniper",
    "nvidia_mellanox_cumulus",
    "opengear",
    "perle",
    "riverbed",
    "silver_peak_aruba_edgeconnect",
    "supermicro_networking",
}

INDUSTRIAL_VENDORS = {
    "advantech_industrial_networking",
    "balluff",
    "beckhoff",
    "digi",
    "helmholz",
    "hirschmann_belden",
    "hms_ewon",
    "insys_icom",
    "lantronix_transition",
    "moxa",
    "oring",
    "phoenix_contact",
    "pilz",
    "red_lion_ntron",
    "softing_industrial",
    "teltonika",
    "weidmueller",
    "westermo",
    "zebra_printers_scanners",
}

SERVICE_PROVIDER_VENDORS = {
    "adtran",
    "atx_networks",
    "baicells",
    "calix",
    "cambium",
    "celona",
    "fiberhome",
    "zte_networking",
}

HOME_DEVICE_CLASSES = {
    "ip_camera",
    "modem",
    "nas",
    "network_adapter",
    "powerline",
    "printer",
    "router",
    "smart_home",
    "wireless_access_point",
}

OFFICE_DEVICE_CLASSES = {
    "controller",
    "network_switch",
    "security_appliance",
}

SERVICE_PROVIDER_KEYWORDS = (
    "backbone",
    "bng",
    "broadband access",
    "carrier",
    "ccap",
    "cmts",
    "dslam",
    "epon",
    "gpon",
    "headend",
    "metro ethernet",
    "msan",
    "olt",
    "optical transport",
    "pon",
    "service provider",
    "xgs pon",
    "xg pon",
)

HOME_CPE_KEYWORDS = (
    "cable modem",
    "cpe",
    "docsis",
    "dsl",
    "extender",
    "home",
    "mesh",
    "modem router",
    "nighthawk",
    "orbi",
    "powerline",
    "residential",
    "smart home",
    "soho",
    "velop",
)

INDUSTRIAL_KEYWORDS = (
    "automation",
    "bus terminal",
    "din rail",
    "din-rail",
    "ethercat",
    "factory",
    "fieldbus",
    "industrial",
    "modbus",
    "plc",
    "profinet",
    "rugged",
    "scada",
)


def load_json(path: Path) -> Any:
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_related_path(index_path: Path, rel_path: str) -> Path:
    path = Path(rel_path)
    candidates = [path] if path.is_absolute() else [index_path.parent / path]
    for candidate in list(candidates):
        if candidate.suffix == ".gz":
            candidates.append(candidate.with_suffix(""))
        else:
            candidates.append(Path(f"{candidate}.gz"))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def load_source_database(path: Path) -> dict[str, Any]:
    database = load_json(path)
    if not isinstance(database, dict):
        raise ValueError("input database must be a JSON object")
    if database.get("records"):
        return database

    record_shards = database.get("record_shards") or {}
    if not record_shards:
        raise ValueError("input database has neither records nor record_shards")

    records: list[dict[str, Any]] = []
    for category, info in sorted(record_shards.items()):
        rel_path = str((info or {}).get("path") or "")
        if not rel_path:
            raise ValueError(f"record shard {category!r} has no path")
        shard_path = resolve_related_path(path, rel_path)
        shard = load_json(shard_path)
        shard_records = shard.get("records") or []
        if not isinstance(shard_records, list):
            raise ValueError(f"record shard {shard_path} has no records list")
        records.extend(shard_records)

    result = {
        key: value
        for key, value in database.items()
        if key not in {"record_shards", "record_locations"}
    }
    result["records"] = records
    return result


def record_text(record: dict[str, Any]) -> str:
    match = record.get("match") or {}
    source = record.get("source") or {}
    parts = [
        record.get("vendor_slug"),
        record.get("vendor"),
        record.get("model"),
        record.get("product_name"),
        record.get("part_number"),
        record.get("device_type"),
        record.get("device_class"),
        record.get("description"),
        source.get("status_text"),
        source.get("source_hint"),
        " ".join(str(alias) for alias in match.get("aliases") or []),
    ]
    return normalize_key(" ".join(str(part) for part in parts if part))


def has_keyword(text: str, keywords: tuple[str, ...]) -> bool:
    padded = f" {text} "
    for keyword in keywords:
        needle = normalize_key(keyword)
        if needle and f" {needle} " in padded:
            return True
    return False


def classify_record(record: dict[str, Any]) -> tuple[str, str]:
    vendor = str(record.get("vendor_slug") or "")
    device_class = str(record.get("device_class") or "")
    text = record_text(record)

    if vendor in HOME_VENDORS:
        return "home", "home/SOHO vendor"

    if vendor in SERVICE_PROVIDER_VENDORS:
        return "service_provider", "service-provider vendor"

    if has_keyword(text, SERVICE_PROVIDER_KEYWORDS):
        return "service_provider", "service-provider keyword"

    if vendor in INDUSTRIAL_VENDORS:
        return "industrial_ot", "industrial vendor"

    if has_keyword(text, INDUSTRIAL_KEYWORDS):
        return "industrial_ot", "industrial keyword"

    if vendor in OFFICE_VENDORS:
        return "office", "office/SMB vendor"

    if vendor in ENTERPRISE_VENDORS:
        return "enterprise", "enterprise vendor"

    if has_keyword(text, HOME_CPE_KEYWORDS) and device_class in HOME_DEVICE_CLASSES:
        return "home", "home/SOHO product keyword"

    if device_class in {"software", "service", "module", "accessory"}:
        return "enterprise", "software/service/module default"

    if device_class in OFFICE_DEVICE_CLASSES:
        return "office", "office device class default"

    if device_class in HOME_DEVICE_CLASSES:
        return "office", "home-capable device class fallback"

    return "enterprise", "unclassified network-device default"


def append_index(index: dict[str, list[str]], key: str, record_id: str) -> None:
    if not key:
        return
    bucket = index.setdefault(key, [])
    if record_id not in bucket:
        bucket.append(record_id)


def rebuild_lookup_indexes(database: dict[str, Any], source_vendor_aliases: dict[str, str]) -> None:
    records = database.get("records") or []
    indexes: dict[str, Any] = {
        "by_id": {},
        "by_vendor": {},
        "by_model_key": {},
        "by_vendor_model_key": {},
        "by_part_key": {},
        "by_alias_key": {},
        "vendor_aliases": {},
    }

    pack_vendors = {str(record.get("vendor_slug") or "") for record in records if record.get("vendor_slug")}
    indexes["vendor_aliases"] = {
        alias: canonical
        for alias, canonical in source_vendor_aliases.items()
        if canonical in pack_vendors
    }
    for vendor in pack_vendors:
        indexes["vendor_aliases"].setdefault(vendor, vendor)

    for pos, record in enumerate(records):
        record_id = str(record.get("id") or "")
        if not record_id:
            continue
        vendor = str(record.get("vendor_slug") or "")
        model_key = str(record.get("model_key") or "")
        indexes["by_id"][record_id] = pos
        append_index(indexes["by_vendor"], vendor, record_id)
        append_index(indexes["by_model_key"], model_key, record_id)
        if vendor and model_key:
            append_index(indexes["by_vendor_model_key"], f"{vendor}|{model_key}", record_id)

        match = record.get("match") or {}
        vendor_model_key = str(match.get("vendor_model_key") or "")
        append_index(indexes["by_vendor_model_key"], vendor_model_key, record_id)

        for value in (record.get("part_number"), record.get("product_name"), record.get("model")):
            key = normalize_key(value)
            append_index(indexes["by_part_key"], key, record_id)
            if vendor and key:
                append_index(indexes["by_part_key"], f"{vendor}|{key}", record_id)

        for alias_key in match.get("alias_keys") or []:
            key = str(alias_key or "")
            append_index(indexes["by_alias_key"], key, record_id)
            if vendor and key and "|" not in key:
                append_index(indexes["by_alias_key"], f"{vendor}|{key}", record_id)

    for name, value in indexes.items():
        if name == "by_id":
            continue
        if isinstance(value, dict) and name != "vendor_aliases":
            indexes[name] = {key: sorted(ids) for key, ids in sorted(value.items())}
    indexes["vendor_aliases"] = dict(sorted(indexes["vendor_aliases"].items()))
    database["indexes"] = indexes


def build_pack_database(
    source: dict[str, Any],
    pack: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    database = {
        key: value
        for key, value in source.items()
        if key not in {"records", "indexes", "model_summaries", "summary", "record_shards", "record_locations"}
    }
    metadata = dict(database.get("metadata") or {})
    metadata["generated_at"] = datetime.now().isoformat(timespec="seconds")
    metadata["smart_pack"] = {
        "pack": pack,
        "source_records": (source.get("summary") or {}).get("total_records") or len(source.get("records") or []),
    }
    database["metadata"] = metadata
    database["records"] = records
    source_vendor_aliases = ((source.get("indexes") or {}).get("vendor_aliases") or {})
    rebuild_lookup_indexes(database, source_vendor_aliases)
    rebuild_model_summaries(database)
    rebuild_summary(database)
    return database


def split_pack_database(
    database: dict[str, Any],
    pack: str,
    output_dir: Path,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    shards: dict[str, list[dict[str, Any]]] = {category: [] for category in CATEGORY_DEFINITIONS}
    record_locations: dict[str, str] = {}

    for record in database.get("records") or []:
        record_id = str(record.get("id") or "")
        if not record_id:
            continue
        category = category_for(record)
        shards.setdefault(category, []).append(record)
        record_locations[record_id] = category

    index = {key: value for key, value in database.items() if key != "records"}
    metadata = index.setdefault("metadata", {})
    metadata["artifact_layout"] = {
        "format": "split",
        "version": 2,
        "index_file": f"indexes/{pack}.json.gz",
        "pack": pack,
        "category_count": sum(1 for items in shards.values() if items),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }

    record_shards = {}
    for category, items in shards.items():
        if not items:
            continue
        classes = Counter(str(record.get("device_class") or "unknown") for record in items)
        record_shards[category] = {
            "label": CATEGORY_DEFINITIONS[category]["label"],
            "path": f"../records/{pack}/{category}.json.gz",
            "record_count": len(items),
            "device_classes": dict(sorted(classes.items())),
        }

    index["record_shards"] = record_shards
    index["record_locations"] = record_locations
    return index, shards


def build_shard(pack: str, category: str, records: list[dict[str, Any]], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "metadata": {
            "schema": source.get("metadata", {}).get("schema"),
            "source_generated_at": source.get("metadata", {}).get("generated_at"),
            "split_generated_at": datetime.now().isoformat(timespec="seconds"),
            "pack": pack,
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


def file_entry(path: Path, output_dir: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(output_dir).as_posix(),
        "compressed_size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def build_smart_packs(source: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    records = source.get("records") or []
    if not records:
        raise ValueError("source database has no records")

    pack_records: dict[str, list[dict[str, Any]]] = {pack: [] for pack in PACKS}
    classification: dict[str, dict[str, str]] = {}
    reasons = Counter()
    vendors_by_pack: dict[str, Counter] = {pack: Counter() for pack in PACKS}
    vendor_pack_counts: dict[str, Counter] = {}

    seen_ids = set()
    for record in records:
        record_id = str(record.get("id") or "")
        if not record_id:
            raise ValueError("record without id")
        if record_id in seen_ids:
            raise ValueError(f"duplicate source record id: {record_id}")
        seen_ids.add(record_id)

        pack, reason = classify_record(record)
        category = category_for(record)
        pack_records[pack].append(record)
        classification[record_id] = {
            "pack": pack,
            "functional_category": category,
            "reason": reason,
        }
        reasons[(pack, reason)] += 1
        vendor = str(record.get("vendor_slug") or "unknown")
        vendors_by_pack[pack][vendor] += 1
        vendor_pack_counts.setdefault(vendor, Counter())[pack] += 1

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "classification_sidecar.json", classification)

    manifest: dict[str, Any] = {
        "metadata": {
            "schema": "sunsetscan.hardware_eol.smart_packs.v1",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "source_schema": (source.get("metadata") or {}).get("schema"),
            "source_generated_at": (source.get("metadata") or {}).get("generated_at"),
            "source_total_records": len(records),
        },
        "profiles": PROFILE_DEFINITIONS,
        "packs": {},
        "vendor_pack_hints": {
            vendor: {
                "packs": dict(sorted(counter.items())),
                "primary_pack": counter.most_common(1)[0][0],
                "recommended_profile": PROFILE_FOR_PACK[counter.most_common(1)[0][0]],
            }
            for vendor, counter in sorted(vendor_pack_counts.items())
        },
    }

    report: dict[str, Any] = {
        "source_total_records": len(records),
        "pack_counts": {},
        "reason_counts": {
            f"{pack}:{reason}": count
            for (pack, reason), count in sorted(reasons.items())
        },
        "top_vendors_by_pack": {},
        "vendor_pack_hints": manifest["vendor_pack_hints"],
        "files": [],
    }

    written_files: list[Path] = []
    all_pack_ids: list[str] = []
    for pack in PACKS:
        pack_db = build_pack_database(source, pack, pack_records[pack])
        index, shards = split_pack_database(pack_db, pack, output_dir)
        index_path = output_dir / "indexes" / f"{pack}.json.gz"
        write_gzip_json(index_path, index)
        written_files.append(index_path)

        shard_entries = {}
        for category, items in shards.items():
            if not items:
                continue
            shard = build_shard(pack, category, items, source)
            shard_path = output_dir / "records" / pack / f"{category}.json.gz"
            write_gzip_json(shard_path, shard)
            written_files.append(shard_path)
            shard_entries[category] = file_entry(shard_path, output_dir)

        pack_ids = [str(record["id"]) for record in pack_records[pack]]
        all_pack_ids.extend(pack_ids)
        manifest["packs"][pack] = {
            "record_count": len(pack_records[pack]),
            "vendor_count": len(vendors_by_pack[pack]),
            "index": file_entry(index_path, output_dir),
            "shards": shard_entries,
        }
        report["pack_counts"][pack] = len(pack_records[pack])
        report["top_vendors_by_pack"][pack] = vendors_by_pack[pack].most_common(25)

    if len(all_pack_ids) != len(set(all_pack_ids)):
        raise ValueError("duplicate record ids across packs")
    missing = sorted(seen_ids - set(all_pack_ids))
    if missing:
        raise ValueError(f"{len(missing)} source records missing from packs")
    if len(all_pack_ids) != len(records):
        raise ValueError(f"pack total {len(all_pack_ids)} does not equal source total {len(records)}")

    manifest_path = output_dir / "manifest.json.gz"
    write_gzip_json(manifest_path, manifest)
    written_files.append(manifest_path)
    report["files"] = [file_entry(path, output_dir) for path in written_files]
    write_json(output_dir / "smart_pack_report.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    source = load_source_database(args.input)
    report = build_smart_packs(source, args.output_dir)
    print(f"source_records={report['source_total_records']}")
    for pack, count in report["pack_counts"].items():
        print(f"{pack}={count}")
    print(f"output={args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
