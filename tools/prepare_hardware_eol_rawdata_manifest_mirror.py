#!/usr/bin/env python3
"""Create source manifests for a vendor rawdata tree without copying raw files.

The importer expects an ``output/RawData/<vendor>/source_manifest.json`` style
tree. The newer vendor rawdata scraper stores files as
``<vendor>/rawdata/<file>``. This helper builds a small manifest-only mirror
that points back to those raw files by absolute path, keeping the raw source
tree untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Any


SUPPORTED_SUFFIXES = {".csv", ".html", ".htm", ".json", ".xlsx", ".pdf", ".txt"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_name_from_slug(slug: str) -> str:
    overrides = {
        "a10": "A10 Networks",
        "arris_commscope_cpe": "ARRIS / CommScope CPE",
        "aruba_hpe": "HPE Aruba / HPE Networking",
        "asustor_nas": "ASUSTOR NAS",
        "avm_fritzbox": "AVM FRITZ!Box",
        "broadcom_bluecoat": "Broadcom / Blue Coat",
        "broadcom_brocade": "Broadcom / Brocade",
        "checkpoint": "Check Point",
        "cisco_meraki": "Cisco Meraki",
        "citrix_netscaler": "Citrix NetScaler",
        "dell_networking": "Dell Networking",
        "hp_printers_official": "HP Printers",
        "ipro_panasonic": "i-PRO / Panasonic",
        "qnap": "QNAP",
        "tplink": "TP-Link",
        "wd_my_cloud": "Western Digital My Cloud",
    }
    if slug in overrides:
        return overrides[slug]
    return " ".join(part.upper() if len(part) <= 3 else part.capitalize() for part in slug.split("_"))


def copied_manifest_by_dest(rawdata_root: Path) -> dict[Path, dict[str, Any]]:
    manifest_path = rawdata_root / "nhedb_rawdata_import_manifest.json"
    if not manifest_path.exists():
        return {}
    manifest = load_json(manifest_path)
    copied = manifest.get("copied") if isinstance(manifest, dict) else None
    if not isinstance(copied, list):
        return {}

    result = {}
    for entry in copied:
        if not isinstance(entry, dict) or not entry.get("dest_path"):
            continue
        result[Path(entry["dest_path"]).resolve()] = entry
    return result


def build_file_entry(path: Path, copied_entry: dict[str, Any] | None) -> dict[str, Any]:
    source_type = path.suffix.lower().lstrip(".")
    if source_type == "htm":
        source_type = "html"
    content_type = mimetypes.guess_type(path.name)[0]
    stat = path.stat()
    return {
        "url": (copied_entry or {}).get("source_url"),
        "source_type": source_type,
        "notes": (copied_entry or {}).get("notes")
        or (copied_entry or {}).get("reason")
        or "Raw lifecycle source captured by vendor rawdata scraper.",
        "fetched_at": None,
        "status": 200,
        "content_type": content_type,
        "bytes": stat.st_size,
        "sha256": sha256_file(path),
        "local_path": str(path.resolve()),
        "error": None,
        "blocked_hint": None,
        "write_mode": "manifest_mirror_absolute_path",
        "discovered_from": None,
    }


def iter_raw_files(raw_dir: Path) -> list[Path]:
    return [
        path
        for path in sorted(raw_dir.iterdir())
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
    ]


def build_manifest(
    *,
    vendor_dir: Path,
    copied_by_dest: dict[Path, dict[str, Any]],
    generated_at: str,
) -> dict[str, Any] | None:
    raw_dir = vendor_dir / "rawdata"
    if not raw_dir.is_dir():
        return None
    files = iter_raw_files(raw_dir)
    if not files:
        return None

    entries = [
        build_file_entry(path, copied_by_dest.get(path.resolve()))
        for path in files
    ]
    coverage_values = {
        copied_by_dest[path.resolve()].get("coverage_status")
        for path in files
        if path.resolve() in copied_by_dest
    }
    coverage_values.discard(None)
    coverage_status = (
        sorted(coverage_values)[0]
        if len(coverage_values) == 1
        else "rawdata_manifest_mirror"
    )
    return {
        "vendor": vendor_dir.name,
        "display_name": display_name_from_slug(vendor_dir.name),
        "coverage_status": coverage_status,
        "notes": (
            "Manifest-only mirror for SunsetScan hardware EOL staging. "
            "Raw source files remain in the vendor rawdata scraper tree."
        ),
        "collected_at": generated_at,
        "source_count": len(entries),
        "discovered_source_count": 0,
        "file_count": len(entries),
        "total_bytes": sum(entry["bytes"] for entry in entries),
        "known_gaps": [],
        "next_actions": [
            "Verify vendor lifecycle terminology against official documentation before promotion.",
            "Add a narrow parser when generic table extraction misses row-level product evidence.",
        ],
        "files": entries,
    }


def build_mirror(rawdata_root: Path, output_root: Path) -> dict[str, Any]:
    generated_at = datetime.now().isoformat(timespec="seconds")
    copied_by_dest = copied_manifest_by_dest(rawdata_root)
    vendors_written = 0
    files_indexed = 0
    skipped_dirs = []

    for vendor_dir in sorted(path for path in rawdata_root.iterdir() if path.is_dir()):
        if vendor_dir.name.startswith("."):
            continue
        manifest = build_manifest(
            vendor_dir=vendor_dir,
            copied_by_dest=copied_by_dest,
            generated_at=generated_at,
        )
        if not manifest:
            skipped_dirs.append(vendor_dir.name)
            continue
        write_json(output_root / vendor_dir.name / "source_manifest.json", manifest)
        vendors_written += 1
        files_indexed += manifest["file_count"]

    summary = {
        "generated_at": generated_at,
        "rawdata_root": str(rawdata_root),
        "output_root": str(output_root),
        "vendors_written": vendors_written,
        "files_indexed": files_indexed,
        "skipped_dirs": skipped_dirs,
        "policy": (
            "Manifest mirror only; does not copy, modify, or delete raw vendor files."
        ),
    }
    write_json(output_root / "_manifest_mirror_summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rawdata-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()

    summary = build_mirror(
        rawdata_root=args.rawdata_root.resolve(),
        output_root=args.output_root.resolve(),
    )
    print(f"vendors_written={summary['vendors_written']}")
    print(f"files_indexed={summary['files_indexed']}")
    print(f"output_root={summary['output_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
