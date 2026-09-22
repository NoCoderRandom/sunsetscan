#!/usr/bin/env python3
"""Add table-like raw vendor lifecycle sources to a hardware EOL database.

This is a conservative bridge for the scraper's raw evidence folders. It only
normalizes rows that have a recognizable product/model column and lifecycle
date columns, leaving policy prose and blocked portal shells untouched.
"""

from __future__ import annotations

import argparse
import calendar
import csv
import gzip
import html as html_lib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup

_LOCAL_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_LOCAL_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_LOCAL_PROJECT_ROOT))

from core.hardware_eol import normalize_key as scanner_normalize_key
from tools.apply_hardware_eol_policy import rebuild_model_summaries, rebuild_summary


SKIP_VENDOR_SLUGS = {
    # These are handled by the scraper's vendor-specific builder today.
    "asus",
    "asustor",
    "brother",
    "canon",
    "cisco",
    "cudy",
    "dahua",
    "dlink",
    "edimax",
    "epson",
    "hp",
    "huawei",
    "juniper",
    "linksys",
    "mercusys",
    "mikrotik",
    "netgear",
    "tenda",
    "totolink",
    "tplink",
    "ubiquiti",
    "zyxel",
}

VENDOR_DISPLAY_NAME_OVERRIDES = {
    "adlink": "ADLINK",
    "audiocodes": "AudioCodes",
    "dfi": "DFI",
    "eaton": "Eaton",
    "ezurio": "Ezurio",
    "fanvil": "Fanvil",
    "hp_poly": "HP Poly",
    "icp_das": "ICP DAS",
    "iogear": "IOGEAR",
    "ivanti_pulse_secure": "Ivanti Pulse Secure",
    "kontron": "Kontron",
    "ligowave": "LigoWave",
    "mitel": "Mitel",
    "netberg": "Netberg",
    "pepperl_fuchs": "Pepperl+Fuchs",
    "ribbon_communications": "Ribbon Communications",
    "silicom": "Silicom",
    "vertiv": "Vertiv",
}

SUPPORTED_SUFFIXES = {".csv", ".html", ".htm", ".json", ".xlsx", ".pdf", ".txt"}
HTML_GENERIC_TABLE_BLOCKLIST = {
    # These pages contain support/advisory/login tables that are not product
    # lifecycle tables. Use vendor-specific parsers for them instead.
    "3onedata",
    "adlink",
    "adtran",
    "aiphone",
    "akuvox",
    "arbor_technology",
    "arista",
    "arris_commscope_cpe",
    "antaira",
    "aten",
    "avm_fritzbox",
    "axiomtek",
    "bcm_advanced_research",
    "beijer_korenix",
    "beckhoff",
    "birddog",
    "bosch_security",
    "broadcom_bluecoat",
    "clavister",
    "crestron",
    "ctc_union",
    "ctsystem",
    "cyberdata",
    "digital_loggers",
    "dfi",
    "epiphan_video",
    "etherwan",
    "ezurio",
    "fanvil",
    "fluke_networks",
    "garland_technology",
    "geovision",
    "glinet",
    "grandstream",
    "hanwha",
    "h3c",
    "hillstone",
    "hp_printers_official",
    "icp_das",
    "iei",
    "idis",
    "inhand_networks",
    "insys_icom",
    "iogear",
    "ip_com",
    "ivanti_pulse_secure",
    "kontron",
    "kramer_av",
    "kyocera_printers",
    "lantronix_transition",
    "lenovo_networking",
    "lexmark_printers",
    "ligowave",
    "lupus_electronics",
    "matrox_video",
    "mimosa",
    "multitech",
    "mobotix",
    "moxa",
    "netally",
    "netberg",
    "netgate",
    "netmodule",
    "netskope_sdwan",
    "neousys",
    "milesight",
    "nokia_networks",
    "nvt_phybridge",
    "nvidia_mellanox_cumulus",
    "netcontrol",
    "patton",
    "pepperl_fuchs",
    "peplink",
    "pica8",
    "robustel",
    "rockwell_automation",
    "ricoh_printers",
    "ruijie_networks",
    "sangoma",
    "sierra_wireless_airlink",
    "stormshield",
    "synology",
    "telrad_networks",
    "teradek",
    "tippingpoint",
    "uniview",
    "uplogix_lantronix",
    "vertiv",
    "volktek",
    "wago",
    "winmate",
    "yealink",
    "zebra_printers_scanners",
    "zte_networking",
    "2n",
    "aaeon_network_appliances",
    "acrosser",
    "atlona",
    "cincoze",
    "comnet",
    "congatec",
    "exfo",
    "nexcom_aiot_mart",
    "portwell",
    "poynting",
}
LIFECYCLE_HEADER_NEEDLES = (
    "end of sale",
    "end-of-sale",
    "end of support",
    "end-of-support",
    "end of life",
    "end-of-life",
    "end of service",
    "end-of-service",
    "end of software",
    "support until",
    "eol",
    "eos",
    "eosl",
    "retirement",
    "discontinued",
)
PRODUCT_HEADER_NEEDLES = (
    "product",
    "model",
    "part",
    "sku",
    "pid",
    "platform",
    "appliance",
    "device",
)

CANONICAL_FIELD_ALIASES = {
    "model": [
        "model",
        "produkt",
        "product name",
        "end of sale product",
        "eol product",
        "product",
        "platform",
        "appliance",
        "device",
        "service",
    ],
    "part_number": [
        "affected product",
        "affected products",
        "affected sku",
        "arista sku",
        "discontinued part number",
        "end of life part number",
        "end of life part no",
        "end of life p n",
        "marketing part number",
        "eos pid",
        "pid",
        "product number",
        "part number",
        "part no",
        "part",
        "sku",
        "model number",
        "model no",
        "order code",
    ],
    "product_name": [
        "product name",
        "tradename",
        "product",
        "description",
        "service",
    ],
    "description": [
        "description",
        "product family",
        "family",
        "group",
        "category",
        "type",
    ],
    "hardware_version": [
        "version",
        "revision",
        "hardware version",
    ],
    "region": [
        "region",
        "locale",
        "country",
    ],
    "raw_status": [
        "status",
        "lifecycle phase",
        "product status",
    ],
    "replacement": [
        "current equivalent model",
        "replaced by",
        "replacement product #",
        "replacement products",
        "replacement model",
        "replacement",
        "successor",
        "alternative",
        "alternativ product",
        "migration",
    ],
    "aliases": [
        "alias",
        "aliases",
        "also known as",
        "aka",
        "alternate name",
        "alternate names",
        "alternative name",
        "alternative names",
        "former name",
        "former names",
        "localized name",
        "localized names",
        "marketing name",
        "marketing names",
        "original name",
        "original names",
        "product alias",
        "product aliases",
        "model alias",
        "model aliases",
    ],
}

CANONICAL_DATE_ALIASES = {
    "announcement": [
        "announcement",
        "announce",
        "eola",
        "notification",
        "announced",
    ],
    "last_sale": [
        "last sale",
    ],
    "end_of_sale": [
        "end of sale",
        "end of sales",
        "end of order",
        "end of order date",
        "end of availability",
        "eoa",
        "eoa date",
        "last order day",
        "last order date",
        "eos",
        "eos date",
    ],
    "end_of_life": [
        "end of life",
        "end of live",
        "eol",
        "eol date",
        "retirement",
    ],
    "end_of_support": [
        "end of support",
        "end of support date",
        "support until",
        "end of sw support",
        "end of software support",
        "end of software maintenance",
        "end of technical support",
        "eosm",
        "eosm date",
        "eots",
        "eots date",
    ],
    "end_of_service": [
        "end of service",
        "eosl",
        "eosl date",
        "service life",
    ],
    "end_of_vulnerability": [
        "vulnerability",
        "security",
    ],
}


def load_json(path: Path) -> Any:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def resolve_related_path(base_path: Path, rel_path: str) -> Path:
    path = Path(rel_path)
    candidates = [path] if path.is_absolute() else [base_path.parent / path]
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


def expand_split_database(index: dict[str, Any], index_path: Path) -> dict[str, Any]:
    record_shards = index.get("record_shards") or {}
    if not record_shards:
        return index

    records: list[dict[str, Any]] = []
    for category, info in sorted(record_shards.items()):
        if not isinstance(info, dict) or not info.get("path"):
            raise ValueError(f"split shard {category!r} has no usable path")
        shard_path = resolve_related_path(index_path, str(info["path"]))
        shard = load_json(shard_path)
        shard_records = shard.get("records") if isinstance(shard, dict) else None
        if not isinstance(shard_records, list):
            raise ValueError(f"split shard {shard_path} has no records list")
        records.extend(shard_records)

    database = {
        key: value
        for key, value in index.items()
        if key not in {"record_shards", "record_locations"}
    }
    metadata = dict(database.get("metadata") or {})
    metadata.pop("artifact_layout", None)
    database["metadata"] = metadata
    database["records"] = records
    return database


def load_database_for_ingest(path: Path) -> dict[str, Any]:
    database = load_json(path)
    if not isinstance(database, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    if database.get("record_shards") and not database.get("records"):
        return expand_split_database(database, path)
    return database


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def import_builder(scraper_root: Path):
    scripts_dir = scraper_root / "scripts"
    builder_path = scripts_dir / "build_sunsetscan_hardware_eol_db.py"
    if not builder_path.exists():
        builder_path = scripts_dir / "build_netwatch_hardware_eol_db.py"
    spec = importlib.util.spec_from_file_location("nhedb_builder", builder_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not import builder from {builder_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_header(value: Any) -> str:
    raw = normalize_text(value).replace("\ufeff", "")
    raw = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", raw)
    text = raw.lower()
    text = re.sub(r"[\u2010-\u2015]", "-", text)
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def normalize_alias_dedupe_key(value: Any) -> str:
    return scanner_normalize_key(value) or normalize_header(value)


def parse_date_any(value: Any, *, dayfirst: bool = False) -> str | None:
    text = re.sub(r"[\u200b-\u200f\ufeff]", "", normalize_text(value))
    if not text:
        return None
    low = text.lower()
    if low in {"-", "n/a", "na", "none", "null", "tbd", "unknown", "not announced"}:
        return None

    compact_text = re.sub(r"\s+", "", text)
    localized_date = re.match(r"^(\d{2,4})\u5e74(\d{1,2})\u6708(\d{1,2})\u65e5$", compact_text)
    if localized_date:
        y, m, d = (int(part) for part in localized_date.groups())
        if y < 100:
            y += 2000
        try:
            return date(y, m, d).isoformat()
        except ValueError:
            return None

    text = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", text, flags=re.I)
    year_dot_date = re.match(r"^(\d{4})\.(\d{1,2})\.(\d{1,2})$", text)
    if year_dot_date:
        y, m, d = (int(part) for part in year_dot_date.groups())
        try:
            return date(y, m, d).isoformat()
        except ValueError:
            return None

    dot_date = re.match(r"^(\d{1,2})\.(\d{1,2})\.(\d{2,4})$", text)
    if dot_date:
        d, m, y = (int(part) for part in dot_date.groups())
        if y < 100:
            y += 2000
        try:
            return date(y, m, d).isoformat()
        except ValueError:
            return None

    text = text.replace(".", "")
    text = re.sub(r",(?=\d{4}$)", ", ", text)

    if re.match(r"^\d{5}(?:\.0+)?$", text):
        serial = int(float(text))
        if 20000 <= serial <= 80000:
            return (date(1899, 12, 30) + timedelta(days=serial)).isoformat()

    iso = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})$", text)
    if iso:
        y, m, d = (int(part) for part in iso.groups())
        try:
            return date(y, m, d).isoformat()
        except ValueError:
            return None

    year_month_numeric = re.match(r"^(\d{4})-(\d{1,2})$", text)
    if year_month_numeric:
        y, m = (int(part) for part in year_month_numeric.groups())
        try:
            last_day = calendar.monthrange(y, m)[1]
            return date(y, m, last_day).isoformat()
        except ValueError:
            return None

    year_slash = re.match(r"^(\d{4})/(\d{1,2})/(\d{1,2})$", text)
    if year_slash:
        y, m, d = (int(part) for part in year_slash.groups())
        try:
            return date(y, m, d).isoformat()
        except ValueError:
            return None

    for fmt in (
        "%d %b %Y",
        "%d %B %Y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%b-%d-%Y",
        "%B-%d-%Y",
        "%d-%b-%y",
        "%d-%B-%y",
        "%b-%d-%y",
        "%B-%d-%y",
    ):
        try:
            normalized_text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
            return datetime.strptime(normalized_text, fmt).date().isoformat()
        except ValueError:
            pass

    month_year = re.match(r"^([A-Za-z]{3,9})[-/\s]+(\d{2,4})$", text)
    if month_year:
        month_name, year_text = month_year.groups()
        try:
            parsed = datetime.strptime(month_name[:3].title(), "%b")
        except ValueError:
            return None
        year = int(year_text)
        if year < 100:
            year += 2000
        last_day = calendar.monthrange(year, parsed.month)[1]
        return date(year, parsed.month, last_day).isoformat()

    year_month = re.match(r"^(\d{4})[-/\s]+([A-Za-z]{3,9})$", text)
    if year_month:
        year_text, month_name = year_month.groups()
        try:
            parsed = datetime.strptime(month_name[:3].title(), "%b")
        except ValueError:
            return None
        year = int(year_text)
        last_day = calendar.monthrange(year, parsed.month)[1]
        return date(year, parsed.month, last_day).isoformat()

    slash = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{2,4})$", text)
    if slash:
        first, second, year = (int(part) for part in slash.groups())
        if year < 100:
            year += 2000
        # Most collected vendor CSV/HTML sources use US order unless ISO or
        # textual month names are present. Impossible dates flip to day-first.
        day, month = (first, second) if dayfirst else (second, first)
        if not dayfirst and month > 12 and day <= 12:
            month, day = day, month
        elif dayfirst and month > 12 and day <= 12:
            day, month = month, day
        try:
            return date(year, month, day).isoformat()
        except ValueError:
            return None

    return None


def import_dedupe_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        normalize_header(record.get("vendor_slug")),
        normalize_alias_dedupe_key(record.get("part_number") or record.get("model")),
        normalize_alias_dedupe_key(record.get("hardware_version")),
        normalize_alias_dedupe_key(record.get("region")),
    )


def record_date_score(record: dict[str, Any]) -> int:
    dates = record.get("dates") or {}
    score = sum(1 for value in dates.values() if value)
    if dates.get("end_of_support") or dates.get("end_of_service"):
        score += 3
    elif dates.get("end_of_life"):
        score += 1
    return score


def record_latest_date_score(record: dict[str, Any]) -> int:
    latest = 0
    for value in (record.get("dates") or {}).values():
        if not value:
            continue
        try:
            parsed = datetime.strptime(str(value), "%Y-%m-%d").date()
        except ValueError:
            continue
        latest = max(latest, parsed.toordinal())
    return latest


def record_dedupe_score(record: dict[str, Any]) -> tuple[int, int]:
    return record_date_score(record), record_latest_date_score(record)


def table_header_score(cells: list[str]) -> int:
    normalized = [normalize_header(cell) for cell in cells]
    joined = " | ".join(normalized)
    score = 0
    if any(any(needle in cell for needle in PRODUCT_HEADER_NEEDLES) for cell in normalized):
        score += 2
    score += sum(1 for needle in LIFECYCLE_HEADER_NEEDLES if needle in joined)
    for cell in normalized:
        if any(header_matches(cell, aliases) for aliases in CANONICAL_DATE_ALIASES.values()):
            score += 1
    return score


def rows_to_dicts(rows: list[list[str]], source_name: str) -> list[dict[str, Any]]:
    if not rows:
        return []

    header_pos = None
    best_score = 0
    for pos, row in enumerate(rows[:12]):
        score = table_header_score(row)
        if score > best_score:
            header_pos = pos
            best_score = score
    if header_pos is None or best_score < 3:
        return []

    headers = [normalize_text(cell) for cell in rows[header_pos]]
    result = []
    for row in rows[header_pos + 1:]:
        if not any(normalize_text(cell) for cell in row):
            continue
        if table_header_score(row) >= best_score:
            continue
        padded = row + [""] * max(0, len(headers) - len(row))
        item: dict[str, str] = {}
        for i in range(min(len(headers), len(padded))):
            key = headers[i] or f"column_{i + 1}"
            value = normalize_text(padded[i])
            if key not in item:
                item[key] = value
            elif value and not item[key]:
                item[key] = value
            elif value and value != item[key]:
                item[f"{key} {i + 1}"] = value
        item["_source_table"] = source_name
        result.append(item)
    return result


def normalize_multiline_text(value: Any) -> str:
    text = str(value or "").replace("\ufeff", "").replace("\xa0", " ")
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def html_table_matrix(table: Any, *, separator: str = " ") -> list[list[str]]:
    rows = []
    for tr in table.find_all("tr"):
        cells = []
        for cell in tr.find_all(["th", "td"]):
            raw_text = cell.get_text(separator, strip=True)
            text = (
                normalize_multiline_text(raw_text)
                if separator == "\n"
                else normalize_text(raw_text)
            )
            colspan = int(cell.get("colspan") or 1)
            cells.extend([text] * max(colspan, 1))
        if cells:
            rows.append(cells)
    return rows


def html_table_matrix_with_rowspans(table: Any, *, separator: str = " ") -> list[list[str]]:
    rows = []
    active_rowspans: dict[int, tuple[str, int]] = {}
    for tr in table.find_all("tr"):
        row: list[str] = []
        next_rowspans: dict[int, tuple[str, int]] = {}
        col_index = 0
        for cell in tr.find_all(["th", "td"]):
            while col_index in active_rowspans:
                text, remaining = active_rowspans[col_index]
                row.append(text)
                if remaining > 1:
                    next_rowspans[col_index] = (text, remaining - 1)
                col_index += 1

            raw_text = cell.get_text(separator, strip=True)
            text = (
                normalize_multiline_text(raw_text)
                if separator == "\n"
                else normalize_text(raw_text)
            )
            colspan = int(cell.get("colspan") or 1)
            rowspan = int(cell.get("rowspan") or 1)
            for offset in range(max(colspan, 1)):
                target_col = col_index + offset
                row.append(text)
                if rowspan > 1:
                    next_rowspans[target_col] = (text, rowspan - 1)
            col_index += max(colspan, 1)

        while col_index in active_rowspans:
            text, remaining = active_rowspans[col_index]
            row.append(text)
            if remaining > 1:
                next_rowspans[col_index] = (text, remaining - 1)
            col_index += 1

        if row:
            rows.append(row)
        active_rowspans = next_rowspans
    return rows


def extract_html_tables(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table")):
        rows = html_table_matrix(table)
        extracted.extend(rows_to_dicts(rows, f"{path.name} table {table_index + 1}"))
    return extracted


def first_parsed_date(text: str, *, dayfirst: bool = False) -> str | None:
    patterns = (
        r"\d{4}[-/]\d{1,2}[-/]\d{1,2}",
        r"\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9}\s+\d{4}",
        r"[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}",
        r"[A-Za-z]{3,9}[-/\s]+\d{4}",
        r"\d{1,2}/\d{1,2}/\d{2,4}",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            parsed = parse_date_any(match.group(0), dayfirst=dayfirst)
            if parsed:
                return parsed
    return None


def split_multiline_values(value: Any) -> list[str]:
    parts = []
    for part in re.split(r"\n+", normalize_multiline_text(value)):
        text = normalize_text(part)
        if text and normalize_header(text) not in {"na", "n a", "none", "unknown"}:
            parts.append(text)
    return parts


def split_comma_values(value: Any) -> list[str]:
    parts = []
    for part in re.split(r",\s*", normalize_text(value)):
        text = part.strip()
        if text and len(text) <= 140:
            parts.append(text)
    return parts


def split_model_group(value: str) -> list[str]:
    value = normalize_text(value)
    if "/" not in value:
        return [value] if value else []
    parts = [part.strip() for part in value.split("/") if part.strip()]
    if not parts:
        return []
    first = parts[0]
    result = [first]
    prefix = first.rsplit("-", 1)[0] if "-" in first else ""
    vendor_prefix = first.split("-", 1)[0] + "-" if "-" in first else ""
    for part in parts[1:]:
        if part.startswith(vendor_prefix) or not prefix:
            result.append(part)
        else:
            result.append(f"{prefix}-{part}")
    return result


def row_dates_from_milestones(rows: list[list[str]]) -> dict[str, str | None]:
    header_pos = None
    for pos, row in enumerate(rows[:4]):
        normalized = [normalize_header(cell) for cell in row]
        if "milestone" in normalized and "date" in normalized:
            header_pos = pos
            break
    if header_pos is None:
        return {}

    dates: dict[str, str | None] = {}
    for row in rows[header_pos + 1:]:
        if len(row) < 2:
            continue
        milestone = normalize_header(row[0])
        parsed = parse_date_any(row[1], dayfirst=True)
        if not parsed:
            continue
        if "announcement" in milestone:
            dates.setdefault("announcement", parsed)
        elif "last day to order" in milestone or "end of sale" in milestone:
            dates.setdefault("end_of_sale", parsed)
            dates.setdefault("last_sale", parsed)
        elif "bug fixes" in milestone or (
            "software" in milestone and "support" in milestone
        ):
            dates.setdefault("end_of_support", parsed)
        elif "end of life" in milestone:
            dates.setdefault("end_of_life", parsed)
        elif "tac support" in milestone or "24x7" in milestone:
            dates.setdefault("end_of_service", parsed)
    return dates


def add_date_fields(row: dict[str, Any], dates: dict[str, str | None]) -> None:
    date_headers = {
        "announcement": "Announcement Date",
        "last_sale": "Last Sale",
        "end_of_sale": "End of Sale",
        "end_of_life": "End of Life",
        "end_of_support": "End of Support",
        "end_of_service": "End of Service",
        "end_of_vulnerability": "End of Vulnerability Support",
    }
    for key, header in date_headers.items():
        if dates.get(key):
            row[header] = dates[key]


def product_header_indexes(row: list[str]) -> dict[str, int] | None:
    normalized = [normalize_header(cell) for cell in row]
    product_idx = None
    description_idx = None
    replacement_idx = None
    for idx, header in enumerate(normalized):
        if product_idx is None and (
            "affected product" in header
            or "affected sku" in header
            or header in {"product number", "part number", "sku"}
        ):
            product_idx = idx
        elif replacement_idx is None and "replacement" in header:
            replacement_idx = idx
        elif description_idx is None and "description" in header:
            description_idx = idx
    if product_idx is None:
        return None
    result = {"product": product_idx}
    if description_idx is not None:
        result["description"] = description_idx
    if replacement_idx is not None:
        result["replacement"] = replacement_idx
    return result


def extract_split_milestone_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug not in {"arista", "h3c"}:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    tables = [
        (table_index, html_table_matrix_with_rowspans(table, separator="\n"))
        for table_index, table in enumerate(soup.find_all("table"), start=1)
    ]
    dates: dict[str, str | None] = {}
    for _, rows in tables:
        for key, value in row_dates_from_milestones(rows).items():
            dates.setdefault(key, value)
    if not any(dates.values()):
        return []

    source_hints = {
        "arista": "Arista end-of-sale notice milestone import",
        "h3c": "H3C end-of-sale notice milestone import",
    }
    extracted = []
    for table_index, rows in tables:
        header_pos = None
        indexes = None
        for pos, row in enumerate(rows[:4]):
            indexes = product_header_indexes(row)
            if indexes:
                header_pos = pos
                break
        if header_pos is None or indexes is None:
            continue
        table_items: dict[str, dict[str, Any]] = {}
        for row in rows[header_pos + 1:]:
            if len(row) <= indexes["product"]:
                continue
            products = split_multiline_values(row[indexes["product"]])
            if not products:
                continue
            description = ""
            if "description" in indexes and len(row) > indexes["description"]:
                description = normalize_text(row[indexes["description"]])
            replacements = []
            if "replacement" in indexes and len(row) > indexes["replacement"]:
                replacements = split_multiline_values(row[indexes["replacement"]])
            replacement_all = "; ".join(replacements)
            for product_index, product in enumerate(products):
                replacement = (
                    replacements[product_index]
                    if len(replacements) == len(products)
                    else replacement_all
                )
                item_key = normalize_header(product)
                item = table_items.get(item_key)
                if item is None:
                    item = {
                        "Affected Product": product,
                        "Product Name": description or product,
                        "Description": description,
                        "Replacement Products": replacement,
                        "_source_table": f"{path.name} split milestone table {table_index}",
                        "_source_hint": source_hints[vendor_slug],
                    }
                    add_date_fields(item, dates)
                    table_items[item_key] = item
                    continue
                if description and not item.get("Description"):
                    item["Description"] = description
                    item["Product Name"] = description
                if replacement:
                    existing = split_multiline_values(str(item.get("Replacement Products", "")).replace("; ", "\n"))
                    for value in split_multiline_values(replacement.replace("; ", "\n")):
                        if value not in existing:
                            existing.append(value)
                    item["Replacement Products"] = "; ".join(existing)
        extracted.extend(table_items.values())
    return extracted


def extract_perle_discontinuation_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "discontinuations.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        heading = table.find_previous(["h1", "h2", "h3", "h4"])
        heading_text = normalize_text(heading.get_text(" ", strip=True)) if heading else ""
        if "discontinuation notice" not in normalize_header(heading_text):
            continue
        notice_date = first_parsed_date(heading_text, dayfirst=True)
        if not notice_date:
            continue
        rows = html_table_matrix(table)
        if not rows:
            continue
        header_pos = None
        for pos, row in enumerate(rows[:4]):
            joined = " ".join(normalize_header(cell) for cell in row)
            if "discontinued" in joined and (
                "part number" in joined or "model" in joined
            ):
                header_pos = pos
                break
        if header_pos is None:
            continue
        headers = [normalize_header(cell) for cell in rows[header_pos]]
        part_indexes = [
            idx
            for idx, header in enumerate(headers)
            if "discontinued" in header and "part number" in header
        ]
        model_idx = next(
            (
                idx
                for idx, header in enumerate(headers)
                if "discontinued" in header and "model" in header
            ),
            None,
        )
        replacement_indexes = [
            idx for idx, header in enumerate(headers) if "replacement" in header
        ]
        for row in rows[header_pos + 1:]:
            part_number = next(
                (
                    normalize_text(row[idx])
                    for idx in part_indexes
                    if idx < len(row) and normalize_text(row[idx])
                ),
                "",
            )
            model = (
                normalize_text(row[model_idx])
                if model_idx is not None and model_idx < len(row)
                else ""
            )
            if not part_number and not model:
                continue
            replacement = "; ".join(
                normalize_text(row[idx])
                for idx in replacement_indexes
                if idx < len(row) and normalize_text(row[idx])
            )
            extracted.append(
                {
                    "Part Number": part_number or model,
                    "Product Name": model or part_number,
                    "Description": model or "Network Device",
                    "End of Sale": notice_date,
                    "Replacement Products": replacement,
                    "_source_table": f"{path.name} discontinuation notice table {table_index}",
                    "_source_hint": "Perle product discontinuation notice import",
                }
            )
    return extracted


def extract_reolink_discontinuation_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product-eol.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = soup.get_text("\n", strip=True)
    pattern = re.compile(
        r"(?P<model>[A-Za-z0-9][A-Za-z0-9 ._+/\-]*?)\s*"
        r"\(\s*EOL:\s*(?P<date>[^)]+)\)\s*,\s*"
        r"suggested replacement:\s*(?P<replacement>[^;\n]+)",
        flags=re.I,
    )
    extracted = []
    for match in pattern.finditer(text):
        eol_date = parse_date_any(match.group("date"), dayfirst=False)
        if not eol_date:
            continue
        model = normalize_text(match.group("model"))
        extracted.append(
            {
                "Model": model,
                "Product Name": model,
                "Description": "IP Camera",
                "EoL Date": eol_date,
                "Replacement Products": normalize_text(match.group("replacement")),
                "Product Status": "end-of-life",
                "_source_table": f"{path.name} discontinuation list",
                "_source_hint": "Reolink discontinuation notice review import",
                "_force_lifecycle_review": True,
                "_review_policy": "discontinued_not_security_eol",
            }
        )
    return extracted


def extract_vivotek_status_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end-of-life-product-list.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted = []
    skipped_categories = {
        "accessories",
        "cover",
        "cable",
        "enclosure",
        "illuminators",
        "lens",
        "mounting kit",
        "power box",
        "power supply",
        "storage",
        "water tank",
    }
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        for row in html_table_matrix(table):
            if len(row) < 2:
                continue
            category = normalize_text(row[0])
            model_list = normalize_text(row[1])
            category_key = normalize_header(category)
            model_list_key = normalize_header(model_list)
            if category_key in {"end of life product list", "network camera"}:
                continue
            if category_key == model_list_key:
                continue
            if category_key in skipped_categories:
                continue
            device_type = vivotek_device_type(category)
            for model in split_comma_values(model_list):
                extracted.append(
                    {
                        "Model": model,
                        "Product Name": model,
                        "Description": device_type,
                        "Product Status": "end-of-life",
                        "_source_table": f"{path.name} product list table {table_index}",
                        "_source_hint": "VIVOTEK end-of-life product list review import",
                        "_status_only_review": True,
                        "_review_policy": "status_only_not_security_eol",
                    }
                )
    return extracted


def vivotek_device_type(category: str) -> str:
    key = normalize_header(category)
    if "software" in key or key in {"standard vca", "vast"}:
        return "Video Management Software"
    if "nvr" in key or "recorder" in key or "video server" in key:
        return "Video Recorder"
    if "network switch" in key:
        return "Network Switch"
    if "poe extender" in key:
        return "PoE Extender"
    if "poe injector" in key:
        return "PoE Injector"
    if "sfp" in key or "transceiver" in key:
        return "Network Transceiver"
    if "long range" in key:
        return "Network Extension Device"
    if "facial recognition" in key or key == "cms":
        return "Surveillance Appliance"
    return f"{category} IP Camera".strip()


ATEN_JAPAN_DISCONTINUED_URL = (
    "https://www.aten.com/jp/ja/supportcenter/discontinued-products/"
)


def aten_device_type(description: str, model: str) -> str:
    text = f"{description} {model}"
    if any(token in text for token in ("IP-KVM", "IP KVM", "KVM")):
        return "KVM Device"
    if any(token in text for token in ("シリアルコンソール", "コンソールサーバー")):
        return "Serial Console Server"
    if any(token in text for token in ("PDU", "UPS", "電源")):
        return "Power Management Device"
    if "エクステンダー" in text:
        return "KVM/AV Extender"
    if any(token in text for token in ("スイッチャー", "スイッチ")):
        return "KVM/AV Switch"
    if any(token in text for token in ("分配器", "マトリックス")):
        return "AV Distribution Device"
    if any(token in text for token in ("ケーブル", "モジュール", "アダプター")):
        return "KVM/AV Accessory"
    if any(token in text for token in ("HDMI", "VGA", "DVI", "DisplayPort", "ビデオ")):
        return "AV Connectivity Device"
    return "KVM/AV Connectivity Product"


def aten_repair_availability(value: str) -> str:
    text = normalize_text(value)
    return {
        "〇": "repair available",
        "○": "repair available",
        "×": "repair unavailable",
        "x": "repair unavailable",
        "X": "repair unavailable",
        "-": "initial-defect support only",
        "▲": "repair consultation required",
    }.get(text, text)


def extract_aten_japan_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "japan_discontinued_products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    if "生産終了製品" not in title:
        return []

    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if not rows:
            continue
        headers = [normalize_text(cell) for cell in rows[0]]
        if headers[:5] != ["型番", "製品概要", "終了案内", "修理可否", "後継／代替"]:
            continue
        for row in rows[1:]:
            if len(row) < 5:
                continue
            model = normalize_text(row[0])
            product_overview = normalize_text(row[1])
            announcement = parse_date_any(row[2])
            repair = aten_repair_availability(row[3])
            replacement = normalize_text(row[4])
            if not model or not announcement:
                continue
            if replacement in {"-", "－"}:
                replacement = ""
            status = "Production ended/discontinued product"
            if repair:
                status = f"{status}; repair availability: {repair}"
            item: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": model,
                "Description": aten_device_type(product_overview, model),
                "Original Product Overview": product_overview,
                "Region": "Japan",
                "Product Status": status,
                "Announcement Date": announcement,
                "_source_table": f"{path.name} discontinued products table {table_index}",
                "_source_hint": "ATEN Japan discontinued products table review import",
                "_source_url": ATEN_JAPAN_DISCONTINUED_URL,
                "_status_only_review": True,
                "_review_policy": "aten_japan_discontinued_products_status_only",
                "_review_reason": (
                    "Source lists this model on ATEN Japan's discontinued/"
                    "production-ended products page with an announcement date, "
                    "but does not provide an exact support or security-update end date."
                ),
                "_prefer_model": True,
            }
            if replacement:
                item["Replacement Products"] = replacement
            extracted.append(item)
    return extracted


AVM_FRITZ_SUPPORT_STATUS_URL = "https://fritz.com/en/pages/status-produktunterstuetzung"

AVM_FRITZ_NETWORK_CATEGORIES = {
    "fritzbox": "FRITZ!Box Router",
    "fritzwlan": "FRITZ! Wi-Fi Repeater/Adapter",
    "fritzpowerline": "FRITZ! Powerline Network Adapter",
}


def avm_field(fields: dict[str, Any], key: str) -> str:
    value = fields.get(key)
    if isinstance(value, dict):
        return normalize_text(value.get("data"))
    return ""


def avm_fritz_status_text(*, eod: str, eos: str) -> str:
    parts = []
    if eod == "ja":
        parts.append("listed in Other models / EOD section")
    if eos == "ja":
        parts.append("personal support unavailable (EOS)")
    elif eos == "nein":
        parts.append("personal support available")
    return "; ".join(parts) or "product support status listed"


def extract_avm_fritzbox_status_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "status_products_api.json":
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    products = payload.get("data", {}).get("products", {})
    if not isinstance(products, dict):
        return []

    rows: list[dict[str, Any]] = []
    for category, device_type in AVM_FRITZ_NETWORK_CATEGORIES.items():
        category_products = products.get(category, {})
        if not isinstance(category_products, dict):
            continue
        for product in category_products.values():
            if not isinstance(product, dict):
                continue
            name = normalize_text(product.get("name"))
            slug = normalize_text(product.get("slug"))
            fields = product.get("data", {}).get("fields", {})
            if not name or not isinstance(fields, dict):
                continue
            if avm_field(fields, "im-web-anzeigen") != "true":
                continue

            eod = avm_field(fields, "eod")
            eos = avm_field(fields, "eos")
            if eod != "ja" and eos != "ja":
                continue

            current_version = avm_field(fields, "f-os-version") or avm_field(
                fields, "ios-version"
            )
            update_type = avm_field(fields, "update-typ")
            if current_version and update_type == "fos":
                current_version = f"FRITZ!OS {current_version}"
            update_link = avm_field(fields, "update-link")
            knowledge_base = avm_field(fields, "skb-link")
            warranty_years = avm_field(fields, "garantiezeit")

            row: dict[str, Any] = {
                "Model": name,
                "Part Number": name,
                "Product Name": name,
                "Description": device_type,
                "Product Category": category,
                "Product Status": avm_fritz_status_text(eod=eod, eos=eos),
                "EOD": eod,
                "EOS": eos,
                "_source_table": f"{path.name} {category} product support API",
                "_source_hint": "AVM FRITZ product support status API review import",
                "_source_url": AVM_FRITZ_SUPPORT_STATUS_URL,
                "_status_only_review": True,
                "_review_policy": "avm_fritz_support_status_without_exact_dates",
                "_review_reason": (
                    "Source lists current FRITZ product support status, but "
                    "does not provide exact support, vulnerability-support, "
                    "or security-update end dates for this row."
                ),
                "_aliases": [alias for alias in (slug, name) if alias],
                "_prefer_model": True,
            }
            if current_version:
                row["Current Version"] = current_version
            if update_link:
                row["Update Link"] = update_link
            if knowledge_base:
                row["Knowledge Base Link"] = knowledge_base
            if warranty_years:
                row["Manufacturer Warranty"] = f"{warranty_years} years"
            rows.append(row)
    return rows


GRANDSTREAM_FIRMWARE_URL = "https://www.grandstream.com/support/firmware"


def grandstream_device_type(model: str) -> str:
    key = normalize_header(model)
    if key.startswith(("bt", "gxp")):
        return "IP Phone"
    if key.startswith(("ht", "gxw")):
        return "VoIP Gateway/ATA"
    if key.startswith("ucm"):
        return "IP PBX Appliance"
    if key.startswith("gxe"):
        return "IP PBX Appliance"
    if key.startswith("gwn7000"):
        return "Network Router"
    if key.startswith("gwn"):
        return "Wireless Access Point"
    if key.startswith("gvr"):
        return "Video Recorder"
    if key.startswith(("gsc", "gds")):
        return "IP Intercom or Surveillance Device"
    if key.startswith("gxv"):
        return "IP Video Device"
    if "wave" in key:
        return "Softphone Software"
    return "Grandstream Network Device"


def grandstream_skip_eol_model(model: str) -> bool:
    key = normalize_header(model)
    return any(
        phrase in key
        for phrase in (
            "language pack",
            "ring tone",
            "voice prompts",
            "conversion tool",
            "release notes",
            "special notes",
            "system prompt",
        )
    )


def extract_grandstream_status_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in {"firmware.html", "firmware_end_of_life_products.html"}:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        heading = table.find_previous(["h1", "h2", "h3", "h4"])
        heading_text = normalize_text(heading.get_text(" ", strip=True)) if heading else ""
        rows = html_table_matrix(table, separator="\n")
        table_has_eol_title = any(
            "end of life products" in normalize_header(cell)
            for row in rows[:3]
            for cell in row
        )
        if (
            "end of life products" not in normalize_header(heading_text)
            and not table_has_eol_title
        ):
            continue
        header_pos = None
        for pos, row in enumerate(rows[:4]):
            if any(normalize_header(cell) == "model" for cell in row):
                header_pos = pos
                break
        if header_pos is None:
            continue
        headers = [normalize_header(cell) for cell in rows[header_pos]]
        model_idx = next(
            (idx for idx, header in enumerate(headers) if header == "model"),
            0,
        )
        firmware_idx = next(
            (idx for idx, header in enumerate(headers) if "firmware" in header),
            None,
        )
        for row in rows[header_pos + 1:]:
            if len(row) <= model_idx:
                continue
            firmware = (
                normalize_text(row[firmware_idx])
                if firmware_idx is not None and firmware_idx < len(row)
                else ""
            )
            for model in split_multiline_values(row[model_idx]):
                if grandstream_skip_eol_model(model):
                    continue
                extracted.append(
                    {
                        "Model": model,
                        "Product Name": model,
                        "Description": grandstream_device_type(model),
                        "Firmware": firmware,
                        "Product Status": "end-of-life",
                        "_source_table": f"{path.name} end-of-life table {table_index}",
                        "_source_hint": "Grandstream End-Of-Life Products firmware table review import",
                        "_source_url": GRANDSTREAM_FIRMWARE_URL,
                        "_status_only_review": True,
                        "_review_policy": "grandstream_eol_firmware_table_status_only",
                        "_review_reason": (
                            "Grandstream lists this model in the End-Of-Life "
                            "Products firmware table, but the table does not "
                            "publish an exact support, vulnerability, or "
                            "security-update end date."
                        ),
                    }
                )
    return extracted


YEALINK_EOL_POLICY_URL = "https://www.yealink.com/en/onepage/end-of-life-policy"
YEALINK_DATE_PATTERN = (
    r"(?:\d{4}[-./]\d{1,2}[-./]\d{1,2}|[A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})"
)


def yealink_jsonld_values(soup: BeautifulSoup) -> list[Any]:
    values: list[Any] = []
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            values.append(json.loads(script.get_text("", strip=True)))
        except json.JSONDecodeError:
            continue
    return values


def yealink_find_jsonld_type(value: Any, type_name: str) -> dict[str, Any]:
    if isinstance(value, dict):
        item_type = value.get("@type") or value.get("type")
        type_values = item_type if isinstance(item_type, list) else [item_type]
        if any(str(item).lower() == type_name.lower() for item in type_values):
            return value
        for child in value.values():
            found = yealink_find_jsonld_type(child, type_name)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = yealink_find_jsonld_type(item, type_name)
            if found:
                return found
    return {}


def yealink_jsonld_product(soup: BeautifulSoup) -> dict[str, Any]:
    for value in yealink_jsonld_values(soup):
        product = yealink_find_jsonld_type(value, "Product")
        if product:
            return product
    return {}


def yealink_source_url(soup: BeautifulSoup) -> str:
    for attrs in (
        {"property": "og:url"},
        {"name": "twitter:url"},
    ):
        node = soup.find("meta", attrs=attrs)
        if node and node.get("content"):
            return normalize_text(node.get("content"))
    for attrs in (
        {"rel": "canonical"},
        {"rel": "alternate", "hreflang": "en"},
    ):
        node = soup.find("link", attrs=attrs)
        if node and node.get("href"):
            return normalize_text(node.get("href"))
    for value in yealink_jsonld_values(soup):
        webpage = yealink_find_jsonld_type(value, "WebPage")
        if webpage.get("url"):
            return normalize_text(webpage.get("url"))
    return ""


def yealink_page_title(soup: BeautifulSoup) -> str:
    node = soup.find("input", attrs={"name": "pageTitle"})
    if node and node.get("value"):
        return normalize_text(node.get("value"))
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    return normalize_text(title)


def yealink_clean_model_name(value: str) -> str:
    model = html_lib.unescape(normalize_text(value))
    model = re.sub(r"\s*\|\s*Yealink.*$", "", model, flags=re.I)
    model = re.sub(
        r"\s+-\s+(?:Voice Communication|Video Conferencing).*$",
        "",
        model,
        flags=re.I,
    )
    model = re.sub(r"^Yealink\s+", "", model, flags=re.I)
    model = re.sub(r"\s+End[- ]of[- ]Sale.*$", "", model, flags=re.I)
    model = re.sub(r"\s+End of Life Announcement.*$", "", model, flags=re.I)
    model = re.sub(
        r"\s+in (?:the )?(?:United States|US).*Market$",
        "",
        model,
        flags=re.I,
    )
    model = re.sub(r"\s+", " ", model).strip(" .:-")
    return model


def yealink_announcement_model(soup: BeautifulSoup) -> str:
    patterns = (
        r"\bEnd[- ]of[- ]Sale Announcement for\s+(.+)$",
        r"\bEnd[- ]of[- ]Sale Announcement of\s+(.+?)\s+in (?:the )?(?:United States|US)",
        r"\bEnd of Life Announcement\s*(?:[-:\u2013\u2014]\s*)?(.+)$",
        r"\bEnd of Life Announcement for\s+(.+)$",
    )
    for heading in soup.find_all(["h1", "h2", "h3"]):
        heading_text = normalize_text(heading.get_text(" ", strip=True))
        for pattern in patterns:
            match = re.search(pattern, heading_text, flags=re.I)
            if match:
                return yealink_clean_model_name(match.group(1))
    return ""


def yealink_parse_date(value: str) -> str | None:
    text = normalize_text(value).strip(" .")
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    month_day_year = re.match(
        r"^([A-Za-z]{3,9})\s+(\d{1,2})\s+(\d{4})$",
        text,
        flags=re.I,
    )
    if month_day_year:
        return parse_date_any(
            f"{month_day_year.group(1)} {month_day_year.group(2)}, "
            f"{month_day_year.group(3)}"
        )
    return None


def yealink_regex_date(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, flags=re.I)
    if not match:
        return None
    return yealink_parse_date(match.group("date"))


def yealink_lifecycle_date(text: str, milestone: str, acronym: str) -> str | None:
    return yealink_regex_date(
        text,
        rf"{milestone}\s*\({acronym}\)\s*Date\s*:\s*(?P<date>{YEALINK_DATE_PATTERN})",
    )


def yealink_label_date(text: str, label: str) -> str | None:
    return yealink_regex_date(
        text,
        rf"{label}\s*:\s*(?P<date>{YEALINK_DATE_PATTERN})",
    )


def yealink_discontinued_since_date(text: str) -> str | None:
    return yealink_regex_date(
        text,
        rf"has been discontinued since\s*(?P<date>{YEALINK_DATE_PATTERN})",
    )


def yealink_replacement(text: str) -> str:
    match = re.search(
        r"recommended replacement solution to the .+? is\s+"
        r"(?P<replacement>[A-Z0-9][A-Z0-9 ._()+/-]+?)"
        r"(?:,|\s+which\b|\.)",
        text,
        flags=re.I,
    )
    return normalize_text(match.group("replacement")) if match else ""


def yealink_device_type(path: Path, model: str, description: str) -> str:
    key = normalize_header(f"{path.name} {model} {description}")
    if any(
        token in key
        for token in (
            "vc cloud management",
            "video conferencing vcd",
            "video conferencing vcm",
            "video conferencing yms",
            "meeting server",
        )
    ):
        return "Video Conferencing Software/Service"
    if any(
        token in key
        for token in ("wireless presentation", "wpp20", "wpp30", "roomcast")
    ):
        return "Wireless Presentation Device"
    if "roompanel" in key or "room panel" in key:
        return "Room Scheduling Panel"
    if any(token in key for token in ("headset", " yhs", "uh33")):
        return "Headset"
    if any(
        token in key
        for token in (
            "accessories",
            "mb camera",
            "mb floorstand",
            "mb wallstand",
            "vcm34",
            "vcm38",
            "cpw90",
            "exp20",
            "exp38",
            "exp39",
            "exp40",
            "bt40",
            "rt10",
            "rt20",
            "cpe80",
            "ehs36",
        )
    ):
        return "Collaboration Accessory"
    if "conference phone" in key or "conference phone" in path.name or re.search(
        r"\bcp\d",
        key,
    ):
        return "Conference Phone"
    if "dect" in key or re.search(r"\bw(?:41|52|53|56|60)[ph]?\b", key):
        return "DECT IP Phone"
    if any(
        token in key
        for token in (
            "ip phone",
            "teams phone",
            "zoom phone",
            "skype",
            "sip ",
            "sip-",
            " mp",
            " vp59",
            "t19",
            "t21",
            "t23",
            "t27",
            "t29",
            "t40",
            "t41",
            "t42",
            "t46",
            "t48",
            "t55",
            "t56",
            "t58",
        )
    ):
        return "IP Phone"
    if any(
        token in key
        for token in ("compatible camera", "usb videobar", "uvc40", "uvc84")
    ):
        return "USB Camera/BYOD Video Bar"
    if any(
        token in key
        for token in (
            "microsoft teams rooms",
            "zoom rooms",
            "video conferencing",
            "meetingbar",
            "meetingeye",
            "mvc",
            "zvc",
            "vc800",
            "vc500",
            "vc400",
            "vc200",
            "vc120",
            "vc110",
            "vc880",
            "ctp20",
            "etv",
        )
    ):
        return "Video Conferencing Endpoint/Room System"
    return "Yealink Collaboration Device"


def yealink_aliases(
    *,
    model: str,
    grouped_model: str,
    product_name: str,
    page_title: str,
    description: str,
    source_url: str,
) -> list[str]:
    aliases = [model, grouped_model, product_name, page_title, description]
    if model.startswith("SIP-"):
        aliases.append(model.removeprefix("SIP-"))
    if "(P)" in model:
        aliases.extend(
            [
                model.replace("(P)", "P"),
                model.replace("(P)", ""),
            ]
        )
    if source_url:
        slug = source_url.rstrip("/").rsplit("/", 1)[-1]
        aliases.append(slug)
    return [alias for alias in aliases if normalize_text(alias)]


def extract_yealink_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith(("product_detail_eol_", "product_detail_eos_")):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    normalized = normalize_header(text)
    source_url = yealink_source_url(soup)
    product = yealink_jsonld_product(soup)
    page_title = yealink_page_title(soup)
    product_name = normalize_text(product.get("name")) or page_title
    description = normalize_text(product.get("description"))
    grouped_model = (
        yealink_announcement_model(soup)
        or yealink_clean_model_name(product_name)
        or yealink_clean_model_name(page_title)
    )
    if not grouped_model:
        return []

    eol_page = path.name.startswith("product_detail_eol_")
    eol_date = yealink_lifecycle_date(text, r"End[-\s]*of[-\s]*Life", "EOL")
    end_sale = yealink_lifecycle_date(text, r"End[-\s]*of[-\s]*Sale", "EOS")
    if not end_sale:
        end_sale = yealink_discontinued_since_date(text)
    announcement = yealink_label_date(text, "Notification Date")
    if not end_sale and "no longer sell" in normalized:
        end_sale = yealink_label_date(text, "Effective Date")

    if eol_page and not eol_date:
        return []
    if not eol_page and not end_sale:
        return []

    region = ""
    if re.search(r"\b(?:United States|US)\s+market\b", text, flags=re.I):
        region = "United States"

    replacement = yealink_replacement(text)
    models = split_model_group(grouped_model) or [grouped_model]
    rows: list[dict[str, Any]] = []
    for model in models:
        device_type = yealink_device_type(path, model, description or product_name)
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": product_name or model,
            "Description": device_type,
            "Lifecycle Status Source": YEALINK_EOL_POLICY_URL,
            "_source_table": f"{path.name} product lifecycle announcement",
            "_source_hint": "Yealink product lifecycle detail page import",
            "_source_url": source_url or YEALINK_EOL_POLICY_URL,
            "_aliases": yealink_aliases(
                model=model,
                grouped_model=grouped_model,
                product_name=product_name,
                page_title=page_title,
                description=description,
                source_url=source_url,
            ),
            "_prefer_model": True,
        }
        if region:
            row["Region"] = region
        if announcement:
            row["Announcement Date"] = announcement
        if end_sale:
            row["End of Sale"] = end_sale
            row["Last Sale"] = end_sale
        if replacement:
            row["Replacement Products"] = replacement

        if eol_page:
            row.update(
                {
                    "Product Status": (
                        "End-of-Life announcement; support/services terminate "
                        "at EOL date"
                    ),
                    "End of Life": eol_date,
                    "End of Support": eol_date,
                    "End of Security Updates": eol_date,
                    "_review_policy": (
                        "yealink_eol_date_support_and_security_updates_end"
                    ),
                    "_review_reason": (
                        "Yealink defines EOST as ending technical assistance, "
                        "updates, and security patches. The product detail page "
                        "states support and services terminate at the EOL date."
                    ),
                }
            )
        else:
            row.update(
                {
                    "Product Status": (
                        "End-of-Sale announcement; support continues under "
                        "Yealink lifecycle policy"
                    ),
                    "_force_lifecycle_review": True,
                    "_review_policy": "yealink_eos_is_sales_end_not_support_end",
                    "_review_reason": (
                        "Yealink defines EOS as end of commercial availability. "
                        "The detail page does not publish an exact EOL/EOST or "
                        "security-update end date for this row."
                    ),
                }
            )
        rows.append(row)
    return rows


def extract_supermicro_status_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True)) if soup.title else ""
    spec = normalize_text(
        soup.find(id="specModel").get_text(" ", strip=True)
        if soup.find(id="specModel")
        else ""
    )
    status_text = normalize_header(soup.get_text(" ", strip=True))
    if "(eol)" not in title.lower() and "discontinued sku eol" not in status_text:
        return []
    candidates = []
    for text in (title, spec):
        candidates.extend(re.findall(r"\bSSE-[A-Z0-9][A-Z0-9./_-]+\b", text))
        candidates.extend(re.findall(r"\(([A-Z0-9][A-Z0-9./_-]*S[A-Z0-9./_-]*)\)", text))
    models: list[str] = []
    for candidate in candidates:
        for model in split_model_group(candidate):
            if model not in models:
                models.append(model)
    extracted = []
    for model in models:
        extracted.append(
            {
                "Model": model,
                "Product Name": model,
                "Description": "Network Switch",
                "Product Status": "discontinued end-of-life",
                "_source_table": f"{path.name} discontinued product page",
                "_source_hint": "Supermicro networking discontinued product page review import",
                "_status_only_review": True,
                "_review_policy": "discontinued_not_security_eol",
            }
        )
    return extracted


def extract_adtran_discontinued_page(path: Path) -> list[dict[str, Any]]:
    if "adtran-product-page-discontinued-example" not in path.name:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "product has been discontinued" not in text.lower():
        return []
    model = ""
    product_meta = soup.find("meta", attrs={"name": re.compile(r"^PRODUCT_NAME$", re.I)})
    if product_meta:
        model = normalize_text(product_meta.get("content"))
    for selector in ("h1", "title"):
        if model:
            break
        node = soup.find(selector)
        if node:
            model = normalize_text(node.get_text(" ", strip=True))
            model = re.sub(r"\s*\|\s*ADTRAN.*$", "", model, flags=re.I)
            if model:
                break
    part_number = ""
    part_meta = soup.find("meta", attrs={"name": re.compile(r"^PART_NUMBER$", re.I)})
    if part_meta:
        part_number = normalize_text(part_meta.get("content"))
    for raw in (str(soup), text):
        if part_number:
            break
        match = re.search(r"\b(?:PART_NUMBER|Part Number)\s*[=:]\s*([A-Z0-9-]+)", raw, re.I)
        if match:
            part_number = normalize_text(match.group(1))
            break
    replacement = ""
    replacement_match = re.search(r"Check out the\s+(.+?)(?:\.|$)", text, flags=re.I)
    if replacement_match:
        segment = normalize_text(replacement_match.group(1))
        codes = re.findall(r"\b[A-Z0-9-]*\d[A-Z0-9-]{5,}\b", segment, flags=re.I)
        if codes:
            code = codes[-1]
            name = normalize_text(segment.split(code, 1)[0])
            replacement = normalize_text(f"{name} / {code}")
        else:
            replacement = segment
    if not model and not part_number:
        return []
    return [
        {
            "Model": model or part_number,
            "Part Number": part_number or model,
            "Product Name": model or part_number,
            "Description": "Network Switch",
            "Replacement Products": replacement,
            "Product Status": "discontinued",
            "_source_table": f"{path.name} discontinued product page",
            "_source_hint": "Adtran discontinued product page review import",
            "_status_only_review": True,
            "_review_policy": "discontinued_not_security_eol",
        }
    ]


ADTRAN_AOS_SUPPORT_DATES_URL = (
    "https://supportcommunity.adtran.com/t5/General/"
    "AOS-End-of-Software-Support-Dates/ta-p/30392"
)
ADTRAN_AOS_SOFTWARE_SUPPORT_POLICY_URL = (
    "https://supportcommunity.adtran.com/jmaxz83287/attachments/jmaxz83287/"
    "nv-aos/364/1/AOS%20Software%20Support%20Policy.pdf"
)


def adtran_aos_version_model(version: str) -> tuple[str, str]:
    raw_version = normalize_text(version)
    clean_version = normalize_text(re.sub(r"\s*\([^)]*\)", "", raw_version))
    if not clean_version:
        return "", ""
    if clean_version.upper().startswith("AOS "):
        model = clean_version
    else:
        model = f"AOS {clean_version}"
    return model, clean_version


def extract_adtran_aos_support_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "article_aos_end_of_software_support_dates.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    if "AOS End of Software Support Dates" not in title:
        return []

    rows: list[dict[str, Any]] = []
    for table in soup.find_all("table"):
        heading_node = table.find_previous(["p", "h1", "h2", "h3"])
        heading = normalize_text(heading_node.get_text(" ", strip=True) if heading_node else "")
        if heading not in {"Currently Supported AOS Versions", "Unsupported AOS Versions"}:
            continue

        table_rows = table.find_all("tr")
        if not table_rows:
            continue
        headers = [
            normalize_text(cell.get_text(" ", strip=True))
            for cell in table_rows[0].find_all(["th", "td"])
        ]
        if headers[:2] != ["AOS Version", "End of Software Support Date"]:
            continue

        for row in table_rows[1:]:
            cells = [
                normalize_text(cell.get_text(" ", strip=True))
                for cell in row.find_all(["th", "td"])
            ]
            if len(cells) < 2:
                continue
            raw_version, support_date_text = cells[:2]
            support_date = parse_date_any(support_date_text)
            if not support_date:
                continue
            model, clean_version = adtran_aos_version_model(raw_version)
            if not model:
                continue
            rows.append(
                {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": f"ADTRAN {model}",
                    "Version": clean_version,
                    "Description": "ADTRAN Operating System software release",
                    "Product Status": f"{heading}; End of Software Support Date {support_date}",
                    "End of Software Support": support_date,
                    "_source_table": f"{path.name} {heading}",
                    "_source_hint": "ADTRAN AOS end-of-software-support dates article import",
                    "_source_url": ADTRAN_AOS_SUPPORT_DATES_URL,
                    "_review_policy": "adtran_aos_end_of_software_support",
                    "_aliases": [
                        raw_version,
                        clean_version,
                        model,
                        f"ADTRAN {model}",
                    ],
                    "_prefer_model": True,
                }
            )
    return rows


LENOVO_END_OF_SERVICE_LOOKUP_URL = (
    "https://support.lenovo.com/us/en/solutions/endofservice"
)


def lenovo_networking_source_url(soup: BeautifulSoup) -> str:
    for attrs in (
        {"property": "og:url"},
        {"name": "twitter:url"},
        {"rel": "canonical"},
    ):
        node = soup.find("meta", attrs=attrs)
        if node and node.get("content"):
            return normalize_text(node.get("content"))
        node = soup.find("link", attrs=attrs)
        if node and node.get("href"):
            return normalize_text(node.get("href"))

    match = re.search(
        r'internalsearchcanonical"\s*:\s*"([^"]+)"',
        str(soup),
        flags=re.I,
    )
    return normalize_text(match.group(1)) if match else ""


def lenovo_networking_product_title(soup: BeautifulSoup) -> str:
    title = ""
    h1 = soup.find("h1")
    if h1:
        title = normalize_text(h1.get_text(" ", strip=True))
    if not title and soup.title:
        title = normalize_text(soup.title.get_text(" ", strip=True))
    title = re.sub(r"\s*>\s*Lenovo Press\s*$", "", title, flags=re.I)
    title = re.sub(r"\s+Product Guide\s*\(withdrawn product\)\s*$", "", title, flags=re.I)
    title = re.sub(r"\s+\(withdrawn product\)\s*$", "", title, flags=re.I)
    title = re.sub(r"\s+\(withdrawn\)\s*$", "", title, flags=re.I)
    return normalize_text(title)


def lenovo_networking_status_text(soup: BeautifulSoup) -> str:
    for callout in soup.select("div.callout"):
        text = normalize_text(callout.get_text(" ", strip=True))
        key = normalize_header(text)
        if "withdrawn" in key or "no longer available for ordering" in key:
            return text

    text = normalize_text(soup.get_text(" ", strip=True))
    for pattern in (
        r"Withdrawn from marketing\s*:\s*[^.]+[.]",
        r"Withdrawn\s*:\s*[^.]+[.]",
        r"[^.]*\bwithdrawn and no longer available for ordering[.]",
        r"[^.]*\bwithdrawn from marketing[.]",
    ):
        match = re.search(pattern, text, flags=re.I)
        if match:
            return normalize_text(match.group(0))
    return "Lenovo Press product guide marked as withdrawn product"


def lenovo_networking_device_type(product_title: str) -> str:
    key = normalize_header(product_title)
    if "adapter" in key or "expansion card" in key:
        return "Network Adapter"
    if "pass thru" in key or "pass through" in key:
        return "Ethernet Pass-through Module"
    if "san switch" in key or "fibre channel" in key or "fc san" in key:
        return "SAN Switch"
    if "infiniband" in key or "infini band" in key:
        return "InfiniBand Switch"
    if "switch module" in key:
        return "Blade Networking Switch Module"
    if "switch" in key:
        return "Network Switch"
    return "Network Device"


def lenovo_networking_aliases(product_title: str, status_text: str) -> list[str]:
    aliases = [product_title]
    for value in re.findall(
        r"\b(?:[A-Z]{1,4}\d{3,5}[A-Z0-9-]*|\d{5}-[A-Z0-9]+|\d{5}-\d{3})\b",
        f"{product_title} {status_text}",
    ):
        if value not in aliases:
            aliases.append(value)
    return aliases


def extract_lenovo_networking_withdrawn_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name.startswith("nhedb__raw__") or path.suffix.lower() not in {".html", ".htm"}:
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    title_key = normalize_header(title)
    text_key = normalize_header(soup.get_text(" ", strip=True))
    if "lenovo press" not in title_key:
        return []
    if "withdrawn product" not in title_key and "withdrawn" not in text_key:
        return []

    product_title = lenovo_networking_product_title(soup)
    if not product_title:
        return []

    status_text = lenovo_networking_status_text(soup)
    device_type = lenovo_networking_device_type(product_title)
    return [
        {
            "Model": product_title,
            "Part Number": product_title,
            "Product Name": product_title,
            "Description": device_type,
            "Product Status": status_text,
            "Lifecycle Status Source": LENOVO_END_OF_SERVICE_LOOKUP_URL,
            "_source_table": f"{path.name} Lenovo Press withdrawn-product page",
            "_source_hint": "Lenovo Press withdrawn networking product guide review import",
            "_source_url": lenovo_networking_source_url(soup),
            "_status_only_review": True,
            "_review_policy": "lenovo_withdrawn_from_marketing_not_support_eol",
            "_review_reason": (
                "Lenovo Press identifies this product guide or main product as "
                "withdrawn from marketing or no longer orderable. Lenovo publishes "
                "End of Service dates separately; this captured product guide does "
                "not provide an exact service or security-update end date."
            ),
            "_aliases": lenovo_networking_aliases(product_title, status_text),
            "_prefer_model": True,
        }
    ]


ADTRAN_BSAP_1800_EOSN_URL = (
    "https://supportcommunity.adtran.com/jmaxz83287/attachments/jmaxz83287/"
    "access-points-doc/50/1/EOL%20-%20BSAP1800_052915.pdf"
)


def adtran_bluesocket_source_url(source_name: str) -> str:
    if "bsap1800" in source_name.lower():
        return ADTRAN_BSAP_1800_EOSN_URL
    return ""


def adtran_notice_date(text: str, label: str) -> str | None:
    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    label_header = normalize_header(label)
    for index, line in enumerate(lines):
        if label_header not in normalize_header(line):
            continue
        window = " ".join(lines[index:index + 8])
        for match in re.finditer(
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*"
            r"\s+\d{1,2},\s+\d{4}\b",
            window,
            flags=re.I,
        ):
            parsed = parse_date_any(match.group(0))
            if parsed:
                return parsed
    return None


def adtran_bluesocket_replacement(text: str) -> str:
    match = re.search(
        r"recommended replacements? for the affected .*? are\s+(.+?)\.",
        normalize_text(text),
        flags=re.I,
    )
    if not match:
        return ""
    return normalize_text(match.group(1))


def adtran_bluesocket_product_section(text: str) -> str:
    match = re.search(
        r"Table\s+1\.\s*Part Numbers Affected by this Announcement(.+?)Table\s+2",
        text,
        flags=re.I | re.S,
    )
    return match.group(1) if match else ""


def adtran_clean_bluesocket_description(lines: list[str]) -> str:
    text = normalize_text(" ".join(lines))
    text = re.split(
        r"\b(?:Vendor end of Life|Market demand has shifted)\b",
        text,
        maxsplit=1,
        flags=re.I,
    )[0]
    text = re.sub(r"\bEnd of Sale Product Part Number\b", "", text, flags=re.I)
    text = re.sub(r"\bProduct Description\b", "", text, flags=re.I)
    return normalize_text(text)


def adtran_bluesocket_model(description: str, part_number: str) -> str:
    for pattern in (
        r"\b(BSC-\d+)\b",
        r"\b(BSAP\s+\d{4}(?:\s+802\.11[A-Z0-9]+)?)\b",
    ):
        match = re.search(pattern, description, flags=re.I)
        if match:
            return normalize_text(match.group(1).upper().replace("BSAP ", "BSAP "))
    return part_number


def adtran_bluesocket_device_type(description: str) -> str:
    normalized = normalize_header(description)
    if "bsc" in normalized:
        return "Wireless LAN controller"
    if "bsap" in normalized:
        return "Wireless access point"
    return "Network Device"


def adtran_bluesocket_clean_product_section(text: str) -> str:
    cleaned = normalize_text(text)
    cleaned = re.sub(
        r"End of Sale Product\s+Product\s+Reason for Withdrawal\s+Part Number\s+Description",
        " ",
        cleaned,
        flags=re.I,
    )
    cleaned = re.sub(r"\b17\d{5}[A-Z0-9]{2}\b", " ", cleaned)
    cleaned = re.sub(
        r"\b(?:Vendor end of Life \(EOL\) components no|"
        r"longer available to assemble product|"
        r"Market demand has shifted to next|"
        r"generation cloud-based and virtualized|"
        r"solutions|"
        r"FORM SL13-2 RevC \(WORK TOOL\)|"
        r"Q[1-4]\s+\d{4})\b",
        " ",
        cleaned,
        flags=re.I,
    )
    return normalize_text(cleaned)


def adtran_bluesocket_descriptions(section: str) -> list[str]:
    cleaned = adtran_bluesocket_clean_product_section(section)
    patterns = [
        r"\bBSAP\s+\d{4}(?:\s+802\.11[A-Z0-9]+)?(?:\s+\d+x\d:\d)?\s+w/"
        r"(?:Internal|External)\s+Antenna(?:s| Connectors)\b",
        r"\bBSC-\d+,\s+\d+\s+Users,\s+\d+\s+APs,?"
        r"(?:\s+(?:Copper Ethernet|Fiber|Copper))?\b",
    ]
    descriptions: list[str] = []
    for pattern in patterns:
        descriptions.extend(
            normalize_text(match.group(0))
            for match in re.finditer(pattern, cleaned, flags=re.I)
        )
    return descriptions


def parse_adtran_bluesocket_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if (
        "ADTRAN" not in normalized
        or "End of Sale Notice" not in normalized
        or "Bluesocket" not in normalized
        or "Part Numbers Affected by this Announcement" not in normalized
    ):
        return []

    announcement = adtran_notice_date(text, "End of Life Announcement Date")
    end_sale = adtran_notice_date(text, "End of Sale Date")
    support_end = adtran_notice_date(text, "Last Date of Support")
    if not end_sale or not support_end:
        return []

    replacement = adtran_bluesocket_replacement(text)
    source_url = adtran_bluesocket_source_url(source_name)
    section = adtran_bluesocket_product_section(text)
    part_numbers = re.findall(r"\b17\d{5}[A-Z0-9]{2}\b", section)
    descriptions = adtran_bluesocket_descriptions(section)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    if len(part_numbers) != len(descriptions):
        return []

    for part_number, description in zip(part_numbers, descriptions):
        if part_number in seen:
            continue
        seen.add(part_number)
        model = adtran_bluesocket_model(description, part_number)
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": part_number,
            "Product Name": f"ADTRAN {description}",
            "Description": adtran_bluesocket_device_type(description),
            "Product Status": "End of Sale Notice; Last Date of Support published",
            "End of Sale": end_sale,
            "End of Support": support_end,
            "_source_table": f"{source_name} affected part numbers",
            "_source_hint": "ADTRAN Bluesocket end-of-sale/support PDF import",
            "_aliases": [model, part_number, description],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if replacement:
            row["Replacement Products"] = replacement
        if source_url:
            row["_source_url"] = source_url
        rows.append(row)
    return rows


def extract_moxa_eol_product_page(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "end of life product" not in text.lower() and "has been phased out" not in text.lower():
        return []
    title = ""
    for selector in ("h1", "title"):
        node = soup.find(selector)
        if node:
            title = normalize_text(node.get_text(" ", strip=True))
            title = re.sub(r"\s*(?:-\s*)?(?:\|\s*)?Moxa.*$", "", title, flags=re.I)
            title = re.sub(
                r"\s+-\s+(?:Unmanaged Switches|Phased-out Products).*$",
                "",
                title,
                flags=re.I,
            )
            if title:
                break
    replacement = ""
    for pattern in (
        r"has been phased out,\s*and has been replaced by the\s+(.+?)(?:\.|$)",
        r"recommend customers use\s+(.+?)(?:\s+Resources|\s+Contact Sales|$)",
    ):
        match = re.search(pattern, text, flags=re.I)
        if match:
            replacement = normalize_text(match.group(1))
            model_tokens = re.findall(
                r"\b[A-Z]{2,}-[A-Za-z0-9-]*\d[A-Za-z0-9-]*\b",
                replacement,
                flags=re.I,
            )
            if model_tokens:
                replacement = "; ".join(dict.fromkeys(model_tokens))
            break
    description = ""
    meta = soup.find("meta", attrs={"name": "description"})
    if meta:
        description = normalize_text(meta.get("content"))
    return [
        {
            "Model": title or path.stem.replace("-", " ").title(),
            "Product Name": title or path.stem.replace("-", " ").title(),
            "Description": description or "Network Device",
            "Replacement Products": replacement,
            "Product Status": "end-of-life",
            "_source_table": f"{path.name} end-of-life product page",
            "_source_hint": "Moxa end-of-life product page review import",
            "_status_only_review": True,
            "_review_policy": "discontinued_not_security_eol",
        }
    ]


def extract_imperva_hardware_schedule_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "imperva-eol-policy.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    section = soup.find(id="hardware-schedule")
    if not section:
        return []
    columns: dict[str, list[str]] = {}
    for table_cell in section.find_all("div", class_="table-cell"):
        heading = table_cell.find("h3")
        if not heading:
            continue
        header = normalize_text(heading.get_text(" ", strip=True))
        values = []
        for cell in table_cell.find_all("div", class_="cell", recursive=False):
            if "without-hover" in (cell.get("class") or []):
                continue
            values.append(normalize_text(cell.get_text(" ", strip=True)))
        columns[header] = values
    appliances = columns.get("Appliance") or []
    extracted = []
    for index, appliance_text in enumerate(appliances):
        lod = (columns.get("LoD / EoS") or [""] * len(appliances))[index]
        eosu = (columns.get("EOSU") or [""] * len(appliances))[index]
        eosm = (columns.get("EOSM") or [""] * len(appliances))[index]
        eosl = (columns.get("EOSL") or [""] * len(appliances))[index]
        matrix = (columns.get("Supported Software Matrix") or [""] * len(appliances))[index]
        models = re.findall(r"\b(?:M\d{3}|X\d{4}|10K\d)\b", appliance_text)
        dates = {
            "Announcement Date": parse_date_any(lod.replace("*", "")),
            "End of Sale": parse_date_any(lod.replace("*", "")),
            "End of Support": parse_date_any(eosm.replace("*", "")),
            "End of Service": parse_date_any(eosl.replace("*", "")),
        }
        if not dates["End of Support"]:
            dates["End of Support"] = parse_date_any(eosu.replace("*", ""))
        if not any(dates.values()):
            continue
        for model in models:
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Imperva {model}",
                "Description": f"Imperva appliance; supported software matrix {matrix}",
                "Product Status": "hardware lifecycle schedule",
                "_source_table": f"{path.name} hardware schedule",
                "_source_hint": "Imperva hardware end-of-life schedule import",
            }
            for header, value in dates.items():
                if value:
                    row[header] = value
            extracted.append(row)
    return extracted


def parse_softing_product_support_dates(value: Any) -> tuple[str | None, str | None]:
    text = normalize_text(value)
    date_matches = re.findall(r"\d{1,2}\.\d{1,2}\.\d{4}", text)
    if len(date_matches) < 2:
        return None, None
    return parse_date_any(date_matches[0]), parse_date_any(date_matches[1])


def extract_softing_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in {"discontinued-products.html", "discontinued-products-us.html"}:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table, separator="\n")
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if len(header) < 5:
            continue
        if (
            header[0] != "product name"
            or header[1] not in {"order nr", "order no"}
            or "successor product" not in header[2]
            or "discontinuation" not in header[4]
            or "support" not in header[4]
        ):
            continue

        last_product = ""
        for row in rows[1:]:
            padded = row + [""] * max(0, 5 - len(row))
            product = normalize_text(padded[0]) or last_product
            order_numbers = split_multiline_values(padded[1])
            replacement_product = normalize_text(padded[2])
            replacement_order_numbers = split_multiline_values(padded[3])
            end_sale, end_support = parse_softing_product_support_dates(padded[4])
            if normalize_text(padded[0]):
                last_product = normalize_text(padded[0])
            if not product or not order_numbers or not (end_sale or end_support):
                continue

            replacement = "; ".join(
                value
                for value in (
                    replacement_product,
                    ", ".join(replacement_order_numbers),
                )
                if value and normalize_header(value) not in {"na", "n a"}
            )
            for order_number in order_numbers:
                extracted.append(
                    {
                        "Product Name": product,
                        "Part Number": order_number,
                        "Description": product,
                        "Replacement Products": replacement,
                        "End of Sale": end_sale,
                        "End of Support": end_support,
                        "Product Status": "discontinued product/support schedule",
                        "_source_table": f"{path.name} discontinued table {table_index}",
                        "_source_hint": "Softing discontinued product/support schedule import",
                    }
                )
    return extracted


def extract_acti_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "discontinued-products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table in soup.find_all("table"):
        rows = html_table_matrix(table, separator="\n")
        for row in rows:
            if len(row) != 1:
                continue
            parts = split_multiline_values(row[0])
            if len(parts) < 2:
                continue
            category = parts[0]
            if normalize_header(category) in {
                "about acti",
                "products",
                "discontinued products",
            }:
                continue
            for model in parts[1:]:
                if len(model) > 80:
                    continue
                extracted.append(
                    {
                        "Model": model,
                        "Product Name": model,
                        "Description": category,
                        "Product Status": "discontinued",
                        "_source_table": f"{path.name} discontinued product list",
                        "_source_hint": "ACTi discontinued product list review import",
                        "_status_only_review": True,
                        "_review_policy": "discontinued_not_security_eol",
                    }
                )
    return extracted


def extract_acti_eol_json_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "eol_search_results.json":
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []

    extracted: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model = normalize_text(item.get("Model"))
        if not model or len(model) > 120:
            continue
        product_type = normalize_text(item.get("ProductType")) or "Discontinued product"
        clearance_start = parse_date_any(item.get("ClearanceStart"))
        clearance_end = parse_date_any(item.get("ClearanceEnd"))
        engineering_phase = parse_date_any(item.get("EngineeringPhase"))
        standard_warranty = parse_date_any(item.get("StandardWarranty"))
        technical_support = parse_date_any(item.get("TechnicalSupport"))
        if not any(
            (
                clearance_start,
                clearance_end,
                engineering_phase,
                standard_warranty,
                technical_support,
            )
        ):
            continue

        status_parts = ["discontinued product service schedule"]
        if engineering_phase:
            status_parts.append(f"engineering phase until {engineering_phase}")
        if standard_warranty:
            status_parts.append(f"standard warranty until {standard_warranty}")
        if technical_support:
            status_parts.append(f"technical support until {technical_support}")

        row: dict[str, Any] = {
            "Model": model,
            "Product Name": model,
            "Description": f"{product_type} discontinued product",
            "Product Status": "; ".join(status_parts),
            "_source_url": "https://www.acti.com/eol",
            "_source_table": f"{path.name} ACTi discontinued product service schedule",
            "_source_hint": "ACTi discontinued product service schedule import",
            "_force_lifecycle_review": True,
            "_review_policy": "acti_technical_support_not_security_update_eol",
            "_review_reason": (
                "ACTi publishes clearance, engineering, warranty, and technical "
                "support milestones, but the source does not define technical "
                "support as the security-update period; keep security-update "
                "status under lifecycle review."
            ),
        }
        if clearance_start:
            row["Announcement Date"] = clearance_start
        if clearance_end:
            row["End of Sale"] = clearance_end
        if technical_support:
            row["End of Support"] = technical_support

        replacement_values: list[str] = []
        replacement_list = item.get("ReplacementModelList")
        if isinstance(replacement_list, list):
            for replacement_item in replacement_list:
                if isinstance(replacement_item, dict):
                    replacement = normalize_text(replacement_item.get("Model"))
                    stage = normalize_text(replacement_item.get("Stage"))
                    if replacement and stage:
                        replacement_values.append(f"{replacement} ({stage})")
                    elif replacement:
                        replacement_values.append(replacement)
                else:
                    replacement = normalize_text(replacement_item)
                    if replacement:
                        replacement_values.append(replacement)
        if replacement_values:
            row["Replacement Product"] = "; ".join(replacement_values)

        stage = normalize_text(item.get("Stage"))
        if stage:
            row["_aliases"] = [f"{model} {stage}"]

        extracted.append(row)
    return extracted


def arris_discontinued_device_type(model: str) -> str:
    normalized = normalize_text(model).upper()
    first = re.split(r"\s+|/", normalized, maxsplit=1)[0]
    if first.startswith(("DCH", "DCT", "DCX", "DTA", "HD-DTA", "IP805")):
        return "Cable set-top box"
    if first.startswith(("DG", "TG", "SBG")):
        return "Cable gateway"
    if first.startswith(("SBR", "WR")):
        return "Router"
    if first.startswith(("SBX", "SBM", "WECB")):
        return "Network adapter"
    if first.startswith(("CM", "SB", "TM")):
        return "Cable modem"
    return "Consumer broadband CPE"


def arris_model_aliases(model: str) -> list[str]:
    aliases = [model]
    parenthetical_removed = normalize_text(re.sub(r"\([^)]*\)", "", model))
    if parenthetical_removed and parenthetical_removed != model:
        aliases.append(parenthetical_removed)
    for part in re.split(r"\s*(?:/|&|\band\b)\s*", model, flags=re.I):
        part = normalize_text(part)
        if part and len(part) <= 80 and re.search(r"\d", part):
            aliases.append(part)
    base_aliases = list(aliases)
    for prefix in ("ARRIS", "Motorola", "SURFboard", "CommScope"):
        aliases.extend(f"{prefix} {alias}" for alias in base_aliases)
    return aliases


def extract_arris_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("Discontinued-Products-"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    heading_text = " ".join(
        normalize_text(tag.get_text(" ", strip=True)) for tag in soup.find_all(["h1", "h2", "h3", "h4", "h5"])
    )
    if "Discontinued" not in f"{page_title} {heading_text}":
        return []

    extracted: list[dict[str, Any]] = []
    seen: set[str] = set()
    for title in soup.select(".prodContainer .boxTitle1 h6"):
        model = normalize_text(title.get_text(" ", strip=True))
        if not model or len(model) > 120:
            continue
        key = normalize_header(model)
        if key in seen:
            continue
        seen.add(key)
        device_type = arris_discontinued_device_type(model)
        extracted.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": model,
                "Description": f"{device_type} discontinued product {model}",
                "Product Status": "discontinued",
                "_source_table": f"{path.name} discontinued products list",
                "_source_hint": "ARRIS Consumer Care discontinued products list review import",
                "_source_url": "https://arris.my.salesforce-sites.com/consumers/ConsumerProductList?c=Discontinued",
                "_status_only_review": True,
                "_review_policy": "arris_discontinued_not_security_eol",
                "_review_reason": (
                    "ARRIS Consumer Care lists this product under Discontinued "
                    "Products, but the captured source does not prove that "
                    "support, firmware updates, or security updates have ended."
                ),
                "_aliases": arris_model_aliases(model),
                "_prefer_model": True,
            }
        )
    return extracted


def iter_document360_categories(node: Any):
    if isinstance(node, dict):
        yield node
        for child in node.get("children") or []:
            yield from iter_document360_categories(child)
    elif isinstance(node, list):
        for item in node:
            yield from iter_document360_categories(item)


def extract_insys_icom_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("discontinued-products"):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    if "Discontinued Products" not in page_title:
        return []

    script = soup.find("script", {"id": "serverApp-state"})
    if not script:
        return []
    try:
        state = json.loads(script.string or script.get_text())
    except json.JSONDecodeError:
        return []

    discontinued_node: dict[str, Any] | None = None
    canonical_url = "https://docs.insys-icom.com/docs/discontinued-products-en"
    for value in state.values():
        result = ((value or {}).get("b") or {}).get("result") if isinstance(value, dict) else None
        if not isinstance(result, dict):
            continue
        canonical_url = normalize_text(result.get("canonicalUrl")) or canonical_url
        for node in iter_document360_categories(result.get("categories")):
            if (
                normalize_text(node.get("slug")) == "discontinued-products-en"
                and normalize_text(node.get("title")) == "Discontinued Products"
            ):
                discontinued_node = node
                break
        if discontinued_node:
            break
    if not discontinued_node:
        return []

    skipped_titles = {"accessories", "modems"}
    extracted: list[dict[str, Any]] = []
    seen: set[str] = set()
    for child in discontinued_node.get("children") or []:
        title = normalize_text(child.get("title"))
        slug = normalize_text(child.get("slug"))
        if not title or normalize_header(title) in skipped_titles:
            continue
        key = normalize_header(title)
        if key in seen:
            continue
        seen.add(key)

        compact_title = normalize_header(title).replace(" ", "")
        short_standalone_title = len(compact_title) <= 4 and " " not in title
        record_model = title if not short_standalone_title else f"INSYS {title}"

        aliases = [record_model]
        if not short_standalone_title:
            aliases.append(title)
        if " and " in title:
            for part in re.split(r"\s+\band\b\s+", title, flags=re.I):
                part = normalize_text(part)
                if not part:
                    continue
                if len(normalize_header(part).replace(" ", "")) <= 4:
                    aliases.append(f"INSYS {part}")
                    aliases.append(f"INSYS icom {part}")
                else:
                    aliases.append(part)
        for alias in list(aliases):
            if not normalize_header(alias).startswith("insys"):
                aliases.append(f"INSYS {alias}")
                aliases.append(f"INSYS icom {alias}")

        extracted.append(
            {
                "Model": record_model,
                "Part Number": record_model,
                "Product Name": record_model,
                "Description": f"Industrial communication device discontinued product family {title}",
                "Product Status": "discontinued",
                "_source_table": f"{path.name} Document360 discontinued products category",
                "_source_hint": "INSYS icom discontinued products category review import",
                "_source_url": canonical_url,
                "_status_only_review": True,
                "_review_policy": "insys_discontinued_category_not_security_eol",
                "_review_reason": (
                    "INSYS icom lists this product family under Discontinued "
                    "Products, but the captured source does not provide exact "
                    "support or security-update end dates."
                ),
                "_aliases": aliases,
                "_prefer_model": True,
                "_document360_slug": slug,
            }
        )
    return extracted


HANWHA_MODEL_CODE_RE = re.compile(
    r"\b(?:SRN|SDH|SNK|SDE|SHR|SNH)-[A-Z0-9]{2,14}(?:-[A-Z0-9]{1,8})?\b"
)


def hanwha_device_type(model: str) -> str:
    if model.startswith("SNH-"):
        return "SmartCam network camera"
    if model.startswith(("SDH-", "SDE-", "SHR-", "SNK-", "SRN-")):
        return "Video surveillance recorder"
    return "Video surveillance device"


def extract_hanwha_nested_section_articles(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"const nestedSection = (\[.*?\])\[0\]", text, re.S)
    if not match:
        return []
    try:
        section = json.loads(match.group(1))[0]
    except (json.JSONDecodeError, IndexError, TypeError):
        return []
    articles = section.get("articles") if isinstance(section, dict) else None
    return articles if isinstance(articles, list) else []


def hanwha_article_source_url(article: dict[str, Any]) -> str:
    url = normalize_text(article.get("url"))
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if url.startswith("/"):
        return f"https://support.hanwhavision.com{url}"
    return "https://support.hanwhavision.com/hc/en-001/sections/14048239557775-Discontinued-Products"


def extract_hanwha_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("discontinued-products-section"):
        return []

    extracted: list[dict[str, Any]] = []
    seen: set[str] = set()
    for article in extract_hanwha_nested_section_articles(path):
        title = normalize_text(html_lib.unescape(article.get("title") or ""))
        if not title.lower().startswith("discontinued:") and "discontinued models" not in title.lower():
            continue
        snippet = normalize_text(html_lib.unescape(article.get("snippet") or ""))
        models = sorted(set(HANWHA_MODEL_CODE_RE.findall(f"{title} {snippet}")))
        for model in models:
            key = normalize_header(model)
            if key in seen:
                continue
            seen.add(key)
            device_type = hanwha_device_type(model)
            extracted.append(
                {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": model,
                    "Description": f"{device_type} discontinued product {model}",
                    "Product Status": "discontinued",
                    "_source_table": f"{path.name} Zendesk discontinued products article list",
                    "_source_hint": "Hanwha Vision discontinued products section review import",
                    "_source_url": hanwha_article_source_url(article),
                    "_status_only_review": True,
                    "_review_policy": "hanwha_discontinued_article_not_security_eol",
                    "_review_reason": (
                        "Hanwha Vision lists this exact model in its official "
                        "Discontinued Products support section, but the captured "
                        "source does not provide exact support or security-update "
                        "end dates."
                    ),
                    "_aliases": [
                        model,
                        f"Hanwha Vision {model}",
                        f"Samsung Techwin {model}",
                        f"Wisenet {model}",
                    ],
                    "_prefer_model": True,
                }
            )
    return extracted


AMCREST_MODEL_RE = re.compile(
    r"(?<![A-Z0-9])(?:"
    r"IP(?:M|[23458]M)-[A-Z0-9]+(?:-[A-Z0-9]+)?|"
    r"AMDV[0-9A-Z+-]+(?:-[A-Z0-9]+)?|"
    r"NV\d[0-9A-Z-]*|"
    r"ATC-\d+[A-Z]?|"
    r"ACD-\d+[A-Z]?|"
    r"960H\d{1,2}\+?"
    r")(?![A-Z0-9])",
    flags=re.I,
)


def amcrest_model_tokens(value: Any) -> list[str]:
    seen: set[str] = set()
    models: list[str] = []
    for match in AMCREST_MODEL_RE.finditer(normalize_text(value)):
        model = match.group(0).upper()
        key = normalize_header(model)
        if key and key not in seen:
            models.append(model)
            seen.add(key)
    return models


def amcrest_strong_model_tokens(value: Any) -> list[str]:
    return [
        model
        for model in amcrest_model_tokens(value)
        if not model.startswith("960H")
    ]


def extract_amcrest_discontinued_firmware_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith(("firmware.", "firmwaredownloads.")):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "The following products are discontinued" not in page_text:
        return []
    if "only receive security firmware updates" not in page_text:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table)
        header_pos = None
        product_index = None
        attention_index = None
        for index, cells in enumerate(matrix[:5]):
            headers = [normalize_header(cell) for cell in cells]
            product_candidates = [
                idx for idx, header in enumerate(headers)
                if header in {"products", "product"}
            ]
            attention_candidates = [
                idx for idx, header in enumerate(headers)
                if header == "attention"
            ]
            if product_candidates and attention_candidates:
                header_pos = index
                product_index = product_candidates[0]
                attention_index = attention_candidates[0]
                break
        if header_pos is None or product_index is None or attention_index is None:
            continue
        heading = ""
        previous_heading = table.find_previous("h2")
        if previous_heading is not None:
            heading = normalize_text(previous_heading.get_text(" ", strip=True))

        for cells in matrix[header_pos + 1:]:
            padded = cells + [""] * max(0, attention_index + 1 - len(cells))
            attention = normalize_text(padded[attention_index])
            if "discontinued" not in attention.lower():
                continue
            product = normalize_text(padded[product_index])
            models = amcrest_strong_model_tokens(attention)
            if not models:
                models = amcrest_strong_model_tokens(product)
            if not models:
                continue
            aliases = [product, *amcrest_model_tokens(attention)]
            for model in models:
                key = (normalize_header(model), normalize_header(heading))
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "Model": model,
                        "Part Number": model,
                        "Product Name": model,
                        "Description": heading or "Amcrest firmware product",
                        "Product Status": (
                            "discontinued; security firmware updates only"
                        ),
                        "Firmware Attention": attention,
                        "_source_table": f"{path.name} firmware table {table_index}",
                        "_source_hint": "Amcrest discontinued firmware table review import",
                        "_status_only_review": True,
                        "_review_policy": "amcrest_discontinued_security_firmware_only",
                        "_review_reason": (
                            "Amcrest lists this product in its official "
                            "Discontinued Products firmware section, but the "
                            "same source says discontinued products still "
                            "receive security firmware updates and does not "
                            "publish an exact security-update end date."
                        ),
                        "_aliases": aliases,
                        "_prefer_model": True,
                    }
                )
    return rows


def extract_red_lion_ntron_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "red-lion-ntron-eol-replacements.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table, separator="\n")
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if header[:3] != ["product number", "unmanaged", "managed"]:
            continue
        for row in rows[1:]:
            padded = row + [""] * max(0, 3 - len(row))
            product_number = normalize_text(padded[0])
            if not product_number:
                continue
            replacements = [
                normalize_text(value)
                for value in padded[1:3]
                if normalize_text(value)
            ]
            extracted.append(
                {
                    "Model": product_number,
                    "Part Number": product_number,
                    "Product Name": product_number,
                    "Description": "Industrial Ethernet Switch",
                    "Replacement Products": "; ".join(replacements),
                    "Product Status": "end-of-life replacement list",
                    "_source_table": f"{path.name} EOL replacement table {table_index}",
                    "_source_hint": "Red Lion N-Tron EOL replacement list review import",
                    "_status_only_review": True,
                    "_review_policy": "status_only_not_security_eol",
                }
            )
    return extracted


def qnap_support_date(value: Any) -> str | None:
    text = normalize_text(value)
    match = re.search(r"\d{4}-\d{1,2}(?:-\d{1,2})?", text)
    if not match:
        return first_parsed_date(text)
    return parse_date_any(match.group(0))


def qnap_clean_support_value(value: Any) -> str:
    return normalize_text(value).replace("\u00a0", " ")


def qnap_is_active_value(value: Any) -> bool:
    return qnap_clean_support_value(value).casefold() == "active"


def qnap_product_status(model: dict[str, Any], detail: dict[str, Any]) -> str:
    tech = qnap_clean_support_value(
        detail.get("technical_support_and_security_updates")
    )
    if model.get("is_eol"):
        return "End-of-life (EOL)"
    if model.get("is_eos"):
        if qnap_is_active_value(tech):
            return "Active; Legacy (End-of-sale)"
        return "Legacy (End-of-sale)"
    return "Active"


QNAP_PRODUCT_LINE_DESCRIPTIONS = {
    "1": "NAS / Expansion",
    "2": "QBoat IoT Device",
    "3": "QGenie Mobile NAS",
    "4": "Computing Accelerator Module",
    "5": "Network Switch",
    "6": "Video Conferencing System",
    "7": "QDA Drive Adapter",
    "8": "QNA Network Adapter",
    "9": "QXP Expansion Card",
    "10": "QWU Wake on WAN Device",
    "12": "QXG Network Expansion Card",
    "14": "QVR Surveillance Appliance",
    "16": "Router",
    "17": "QuCPE Network Appliance",
    "19": "Accessory",
}


def qnap_product_line_description(
    product_line_id: Any,
    product_line_list: dict[str, Any],
) -> str:
    key = str(product_line_id)
    return (
        QNAP_PRODUCT_LINE_DESCRIPTIONS.get(key)
        or normalize_text(product_line_list.get(key))
        or "QNAP Product"
    )


def qnap_replacement(value: Any) -> str:
    text = normalize_text(value)
    return "" if text in {"", "-"} else text


def qnap_os_update_date(value: Any) -> str | None:
    return qnap_support_date(value)


def qnap_api_model_row(
    model: dict[str, Any],
    product_line_list: dict[str, Any],
) -> dict[str, Any] | None:
    name = normalize_text(model.get("name") or model.get("display_name"))
    if not name:
        return None
    detail = model.get("eol_detail")
    if not isinstance(detail, dict):
        return None

    tech_value = detail.get("technical_support_and_security_updates")
    os_value = detail.get("os_and_application_updates_and_maintenance")
    status = qnap_product_status(model, detail)
    support_date = qnap_support_date(tech_value)
    if not support_date:
        return None
    os_update_date = qnap_os_update_date(os_value)

    return {
        "Model": name,
        "Product Name": normalize_text(model.get("display_name")) or name,
        "Description": qnap_product_line_description(
            model.get("product_line_id"), product_line_list
        ),
        "Product Status": status,
        "Replacement Products": qnap_replacement(detail.get("recommended_replacement")),
        "End of Support": support_date,
        "End of Security Updates": support_date,
        "End of OS Updates": os_update_date,
        "_source_table": "product_status_api.json modelList",
        "_source_hint": "QNAP product support status API import",
    }


def extract_qnap_product_status_api_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product_status_api.json":
        return []
    try:
        payload = load_json(path)
    except Exception:
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, dict):
        return []
    product_line_list = results.get("productLineList") or {}
    if not isinstance(product_line_list, dict):
        product_line_list = {}
    model_list = results.get("modelList") or []
    if not isinstance(model_list, list):
        return []

    rows = []
    for model in model_list:
        if not isinstance(model, dict):
            continue
        row = qnap_api_model_row(model, product_line_list)
        if row:
            rows.append(row)
    return rows


def extract_javascript_object_assignment(
    text: str,
    variable_name: str,
) -> dict[str, Any] | None:
    marker = f"var {variable_name}"
    start = text.find(marker)
    if start < 0:
        return None
    eq = text.find("=", start)
    if eq < 0:
        return None
    obj_start = text.find("{", eq)
    if obj_start < 0:
        return None

    depth = 0
    quote = ""
    escaped = False
    for idx, char in enumerate(text[obj_start:], start=obj_start):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[obj_start : idx + 1])
                except Exception:
                    return None
    return None


def qnap_os_cycle_date(value: Any) -> str | None:
    text = normalize_text(value)
    if text in {"", "-", "--"}:
        return None
    return parse_date_any(text)


def qnap_os_aliases(product: str, version_text: str) -> list[str]:
    clean_version = re.sub(r"\s*\(.*?\)", "", normalize_text(version_text)).strip()
    aliases = [f"{product} {clean_version}"]
    if re.fullmatch(r"h?\d+(?:\.\d+){1,2}", clean_version, flags=re.I):
        aliases.append(f"{product} {clean_version}.x")
    return aliases


def extract_qnap_os_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product_status.html":
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    payload = extract_javascript_object_assignment(text, "osLocaleData")
    if not payload:
        return []

    rows: list[dict[str, Any]] = []
    for chapter in payload.get("chapters") or []:
        if not isinstance(chapter, dict) or chapter.get("title") != "End-of-Life (EOL) Dates":
            continue
        for content in chapter.get("contents") or []:
            if not isinstance(content, dict) or "table" not in content:
                continue
            product = normalize_text(content.get("title"))
            if product not in {"QTS", "QuTS hero"}:
                continue
            table = content.get("table") or {}
            tbody = table.get("tbody") or []
            if not isinstance(tbody, list):
                continue
            for item in tbody:
                if not isinstance(item, dict):
                    continue
                version_text = normalize_text(item.get("version"))
                clean_version = re.sub(r"\s*\(.*?\)", "", version_text).strip()
                if not clean_version:
                    continue
                maintenance_end = qnap_os_cycle_date(item.get("maintenance"))
                lts_end = qnap_os_cycle_date(item.get("lts"))
                eol_date = lts_end or maintenance_end
                if not eol_date:
                    continue
                model = f"{product} {clean_version}"
                rows.append(
                    {
                        "Model": model,
                        "Part Number": model,
                        "Product Name": f"{product} {version_text}",
                        "Description": "Software",
                        "Product Status": "Operating system EOL date",
                        "Announcement": qnap_os_cycle_date(item.get("availability")),
                        "End of Support": eol_date,
                        "End of Security Updates": eol_date,
                        "Aliases": "; ".join(qnap_os_aliases(product, version_text)),
                        "_source_table": f"{path.name} {product} operating system lifecycle table",
                        "_source_hint": "QNAP operating system lifecycle import",
                    }
                )
    return rows


def extract_qnap_support_status_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product-support-status"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if "model" not in header or not any(
            "technical support and security updates" in cell for cell in header
        ):
            continue
        model_idx = header.index("model")
        status_idx = next(
            (idx for idx, cell in enumerate(header) if "product availability" in cell),
            None,
        )
        security_idx = next(
            (
                idx
                for idx, cell in enumerate(header)
                if "technical support and security updates" in cell
            ),
            None,
        )
        os_updates_idx = next(
            (
                idx
                for idx, cell in enumerate(header)
                if "os and application updates" in cell
            ),
            None,
        )
        replacement_idx = next(
            (idx for idx, cell in enumerate(header) if "successor" in cell),
            None,
        )
        for row in rows[1:]:
            if len(row) <= model_idx:
                continue
            model = normalize_text(row[model_idx])
            if not model:
                continue
            status = (
                normalize_text(row[status_idx])
                if status_idx is not None and status_idx < len(row)
                else ""
            )
            end_support = (
                qnap_support_date(row[security_idx])
                if security_idx is not None and security_idx < len(row)
                else None
            )
            end_os_updates = (
                qnap_support_date(row[os_updates_idx])
                if os_updates_idx is not None and os_updates_idx < len(row)
                else None
            )
            replacement = (
                normalize_text(row[replacement_idx])
                if replacement_idx is not None and replacement_idx < len(row)
                else ""
            )
            extracted.append(
                {
                    "Model": model,
                    "Product Name": model,
                    "Description": "NAS Storage",
                    "Product Status": status or "product support status",
                    "End of Support": end_support,
                    "End of Security Updates": end_support,
                    "End of OS Updates": end_os_updates,
                    "Replacement Products": replacement,
                    "_source_table": f"{path.name} support status table {table_index}",
                    "_source_hint": "QNAP product support status table import",
                }
            )
    return extracted


def extract_versa_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "eol-eos.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if "release" not in header or not any("end of support" in cell for cell in header):
            continue
        heading = table.find_previous(["h1", "h2", "h3", "h4"])
        product_family = normalize_text(heading.get_text(" ", strip=True)) if heading else ""
        release_idx = header.index("release")
        eol_idx = next((idx for idx, cell in enumerate(header) if "end of life" in cell), None)
        eos_idx = next((idx for idx, cell in enumerate(header) if "end of support" in cell), None)
        for row in rows[1:]:
            if len(row) <= release_idx:
                continue
            release = normalize_text(row[release_idx])
            if not release:
                continue
            model = normalize_text(f"{product_family} {release}") if product_family else release
            eol_date = (
                parse_date_any(row[eol_idx])
                if eol_idx is not None and eol_idx < len(row)
                else None
            )
            eos_date = (
                parse_date_any(row[eos_idx])
                if eos_idx is not None and eos_idx < len(row)
                else None
            )
            if not (eol_date or eos_date):
                continue
            extracted.append(
                {
                    "Model": model,
                    "Product Name": model,
                    "Description": f"Software - {product_family}".strip(" -"),
                    "Product Status": "software release EOL/EOS schedule",
                    "End of Life": eol_date,
                    "End of Support": eos_date,
                    "_source_table": f"{path.name} software lifecycle table {table_index}",
                    "_source_hint": "Versa Networks software EOL/EOS table import",
                }
            )
    return extracted


def wd_os3_support_end_date(text: str) -> str | None:
    for pattern in (
        r"\bOn\s+([^,]+,\s+\d{4}),\s+support\b.+?\bended\b",
        r"\bAfter\s+([^,]+,\s+\d{4}),.+?\bsecurity updates\b",
    ):
        match = re.search(pattern, text, flags=re.I | re.S)
        if match:
            parsed = parse_date_any(match.group(1))
            if parsed:
                return parsed
    return None


def split_wd_os3_models(value: Any) -> list[str]:
    text = normalize_text(value)
    if not text:
        return []
    match = re.match(r"^(?P<prefix>.+?\s)(?P<first>[A-Z]{2,}\d{3,})\s*&\s*(?P<second>[A-Z]{2,}\d{3,})$", text)
    if match:
        prefix = match.group("prefix")
        return [
            normalize_text(f"{prefix}{match.group('first')}"),
            normalize_text(f"{prefix}{match.group('second')}"),
        ]
    return [text]


def extract_wd_my_cloud_os3_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "my-cloud-os3-end-of-support-and-service.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    support_end = wd_os3_support_end_date(soup.get_text(" ", strip=True))
    if not support_end:
        return []
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if header[:3] != ["model", "firmware version", "release date"]:
            continue
        for row in rows[1:]:
            padded = row + [""] * max(0, 3 - len(row))
            firmware = normalize_text(padded[1])
            release_date = normalize_text(padded[2])
            for model in split_wd_os3_models(padded[0]):
                extracted.append(
                    {
                        "Model": model,
                        "Product Name": model,
                        "Description": (
                            f"My Cloud OS 3 NAS; last OS 3 firmware {firmware} "
                            f"released {release_date}"
                        ),
                        "Product Status": "support ended; security updates ended",
                        "End of Support": support_end,
                        "End of Vulnerability Support": support_end,
                        "End of Service": support_end,
                        "_source_table": f"{path.name} OS3 firmware table {table_index}",
                        "_source_hint": "WD My Cloud OS 3 end-of-support and security update notice import",
                    }
                )
    return extracted


def wd_lifecycle_device_type(category: str, product_group: str, name: str) -> str:
    text = normalize_header(f"{category} {product_group} {name}")
    if "software" in text or "mobile app" in text or "app" in text:
        return "Software"
    if "nas" in text or "my book live" in text or "sentinel" in text or "arkeia" in text:
        return "NAS Storage"
    if "networking" in text or "my net" in text:
        return "Network Device"
    if "wd tv" in text or "media player" in text:
        return "Media Player"
    if "readyview" in text or "surveillance" in text:
        return "Surveillance System"
    return "Network Device"


def extract_wd_product_lifecycle_policy_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "western-digital-product-lifecycle-support-policy.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if len(rows) < 3:
            continue
        category = normalize_text(rows[0][0]) if rows[0] else ""
        header_pos = None
        for pos, row in enumerate(rows[:3]):
            normalized = [normalize_header(cell) for cell in row]
            if "name" in normalized and "support status" in normalized:
                header_pos = pos
                break
        if header_pos is None:
            continue
        header = [normalize_header(cell) for cell in rows[header_pos]]
        name_idx = header.index("name")
        product_idx = header.index("product") if "product" in header else None
        status_idx = header.index("support status")
        last_manufactured_idx = (
            header.index("last manufactured date")
            if "last manufactured date" in header
            else None
        )
        for row in rows[header_pos + 1:]:
            if len(row) <= max(name_idx, status_idx):
                continue
            name = normalize_text(row[name_idx])
            status = normalize_text(row[status_idx])
            if not name or not status:
                continue
            product_group = (
                normalize_text(row[product_idx])
                if product_idx is not None and product_idx < len(row)
                else ""
            )
            last_manufactured = (
                normalize_text(row[last_manufactured_idx])
                if last_manufactured_idx is not None and last_manufactured_idx < len(row)
                else ""
            )
            description_parts = [part for part in (category, product_group) if part]
            if last_manufactured:
                description_parts.append(f"last manufactured {last_manufactured}")
            extracted.append(
                {
                    "Model": name,
                    "Product Name": name,
                    "Description": "; ".join(description_parts) or category or "Network Device",
                    "Product Status": status,
                    "_source_table": f"{path.name} lifecycle policy table {table_index}",
                    "_source_hint": "WD product lifecycle support policy table review import",
                    "_status_only_review": True,
                    "_review_policy": "status_only_support_updates_no_exact_date",
                    "_review_reason": (
                        "Source status says updates/support have ended, but no exact "
                        "support or security-update end date is present in this row."
                    ),
                    "Device Type": wd_lifecycle_device_type(category, product_group, name),
                }
            )
    return extracted


def extract_wd_my_cloud_rows(path: Path) -> list[dict[str, Any]]:
    return (
        extract_wd_my_cloud_os3_rows(path)
        + extract_wd_product_lifecycle_policy_rows(path)
    )


def screenbeam_device_description(name: str) -> str:
    if " - " in name:
        return normalize_text(name.split(" - ", 1)[1])
    text = normalize_header(name)
    if "moca" in text:
        return "MoCA Network Adapter"
    if "extender" in text:
        return "Wireless Network Extender"
    if "transmitter" in text:
        return "Wireless Display Transmitter"
    if "receiver" in text:
        return "Wireless Display Receiver"
    if "adapter" in text:
        return "Wireless Display Adapter"
    return "Network Device"


def extract_screenbeam_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end-of-life-products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for heading in soup.find_all(["h2", "h3"]):
        name = normalize_text(heading.get_text(" ", strip=True))
        if not name or normalize_header(name) == "end of life products":
            continue
        description = screenbeam_device_description(name)
        model = normalize_text(name.split(" - ", 1)[0]) if " - " in name else name
        extracted.append(
            {
                "Model": model,
                "Product Name": name,
                "Description": description,
                "Product Status": "end-of-life and end-of-support product",
                "_source_table": f"{path.name} product heading list",
                "_source_hint": "ScreenBeam/Actiontec end-of-life and end-of-support product list review import",
                "_status_only_review": True,
                "_review_policy": "status_only_support_updates_no_exact_date",
                "_review_reason": (
                    "Source lists the product as end-of-life/end-of-support, but "
                    "does not provide an exact support or security-update end date."
                ),
            }
        )
    return extracted


def extract_digi_eol_model_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product-models.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if header[:2] != ["part number", "description"]:
            continue
        for row in rows[1:]:
            if len(row) < 2:
                continue
            part_number = normalize_text(row[0])
            description = normalize_text(row[1])
            if not part_number or not normalize_header(description).startswith("end of life"):
                continue
            product_name = re.sub(
                r"^\s*End-of-life\s+",
                "",
                description,
                flags=re.I,
            ).strip()
            product_name = re.split(r"\s+[\u2014-]\s+", product_name, maxsplit=1)[0].strip() or part_number
            extracted.append(
                {
                    "Model": part_number,
                    "Part Number": part_number,
                    "Product Name": product_name,
                    "Description": description,
                    "Product Status": "End-of-life",
                    "_source_table": f"{path.name} part number table {table_index}",
                    "_source_hint": "Digi product model end-of-life status table review import",
                    "_status_only_review": True,
                    "_review_policy": "status_only_not_security_eol",
                    "_review_reason": (
                        "Source marks the part number End-of-life, but does not "
                        "provide an exact support or security-update end date."
                    ),
                }
            )
    return extracted


def edgecore_eol_effective_date(text: str) -> str | None:
    match = re.search(
        r"(?:completed the End of Life\s*\(EOL\)\s*process\s+)?"
        r"effective on\s+([A-Za-z]{3,9})\s*,?\s*(\d{1,2}),?\s+(\d{4})",
        text,
        flags=re.I,
    )
    if match:
        month, day, year = match.groups()
        return parse_date_any(f"{month} {day}, {year}")
    match = re.search(
        r"Effective\s+([A-Za-z]{3,9})\s*,?\s*(\d{1,2})\s+(\d{4})",
        text,
        flags=re.I,
    )
    if match:
        month, day, year = match.groups()
        return parse_date_any(f"{month} {day}, {year}")
    return None


def extract_edgecore_product_page_eol_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    eol_date = edgecore_eol_effective_date(text)
    if not eol_date:
        return []
    match = re.search(
        r"\b([A-Z][A-Z0-9-]+(?:\([A-Z0-9-]+\))?)\s+Warranty Support Period",
        text,
    )
    if not match:
        return []
    model_text = normalize_text(match.group(1))
    model = re.sub(r"\(.+\)$", "", model_text).strip()
    product_name = model_text.replace("(", " (")
    extracted = [
        {
            "Model": model,
            "Part Number": model,
            "Product Name": product_name,
            "Description": "Network Switch",
            "Product Status": "completed End of Life (EOL) process",
            "End of Life": eol_date,
            "_source_table": f"{path.name} product EOL notice",
            "_source_hint": "Edgecore product page EOL process notice review import",
            "_force_lifecycle_review": True,
            "_review_policy": "eol_process_not_security_eol",
            "_review_reason": (
                "Source gives an End of Life process date, but does not prove "
                "that security updates or support ended on that date."
            ),
        }
    ]
    return extracted


def extract_edgecore_notice_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "datacenter-switch-eol-notice-2021.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    eol_date = edgecore_eol_effective_date(text)
    if not eol_date:
        return []
    extracted: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows = html_table_matrix(table)
        if not rows:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if header[:2] != ["eol equipment", "replacement"]:
            continue
        for row in rows[1:]:
            if len(row) < 2:
                continue
            model = normalize_text(row[0])
            replacement = normalize_text(row[1])
            if not model:
                continue
            extracted.append(
                {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": model,
                    "Description": "Data Center Switch",
                    "Replacement Products": replacement,
                    "Product Status": "end of sales and end of life notice",
                    "End of Life": eol_date,
                    "_source_table": f"{path.name} EOL equipment table {table_index}",
                    "_source_hint": "Edgecore data center switch EOL notice review import",
                    "_force_lifecycle_review": True,
                    "_review_policy": "eol_process_not_security_eol",
                    "_review_reason": (
                        "Source gives an End of Life process date, but does not "
                        "prove that security updates or support ended on that date."
                    ),
                }
            )
    return extracted


def extract_edgecore_wifi_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "wifi-eol-product-list.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    extracted: list[dict[str, Any]] = []
    current_group = ""
    for heading in soup.find_all(["h2", "h3", "h4"]):
        text = normalize_text(heading.get_text(" ", strip=True))
        if not text:
            continue
        if heading.name in {"h2", "h3"}:
            current_group = text if heading.name == "h3" else current_group
            continue
        extracted.append(
            {
                "Model": text,
                "Part Number": text,
                "Product Name": text,
                "Description": current_group or "Wi-Fi Product",
                "Product Status": "EOL product list",
                "_source_table": f"{path.name} product heading list",
                "_source_hint": "Edgecore Wi-Fi EOL product list review import",
                "_status_only_review": True,
                "_review_policy": "status_only_not_security_eol",
            }
        )
    return extracted


def extract_edgecore_eol_rows(path: Path) -> list[dict[str, Any]]:
    return (
        extract_edgecore_wifi_eol_rows(path)
        + extract_edgecore_notice_rows(path)
        + extract_edgecore_product_page_eol_rows(path)
    )


def extract_sophos_product_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product-lifecycle.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    try:
        start = next(
            idx
            for idx, line in enumerate(lines)
            if normalize_header(line) == "sophos products now end of life"
        )
    except StopIteration:
        return []
    try:
        end = next(
            idx
            for idx in range(start + 1, len(lines))
            if normalize_header(lines[idx]).startswith("upgrade to the latest")
        )
    except StopIteration:
        return []

    section = "\n".join(lines[start:end])
    support_end = first_parsed_date(section)
    if not support_end:
        return []

    product_start = None
    for idx in range(start, end):
        if normalize_header(lines[idx]).startswith("if you still use one of the products below"):
            product_start = idx + 1
            break
    if product_start is None:
        return []

    products: list[str] = []
    for line in lines[product_start:end]:
        normalized = normalize_header(line)
        if not line or len(line) > 180:
            continue
        if normalized in {
            "migration assistance",
            "retirement calendars",
            "migration paths",
            "product alerts",
        }:
            continue
        if normalized.startswith("if you ") or normalized.startswith("customers "):
            continue
        products.append(line)

    extracted = []
    for product in dict.fromkeys(products):
        extracted.append(
            {
                "Model": product,
                "Product Name": product,
                "Description": "Software",
                "Product Status": "end of life; no longer supported; no longer receive updates",
                "End of Support": support_end,
                "End of Vulnerability Support": support_end,
                "_source_table": f"{path.name} products now end-of-life section",
                "_source_hint": "Sophos products now end-of-life update/support notice import",
            }
        )
    return extracted


def axis_support_product_name(lines: list[str]) -> str:
    for index, line in enumerate(lines):
        if normalize_header(line) == "product support for":
            for candidate in lines[index + 1:index + 5]:
                text = normalize_text(candidate)
                if text and normalize_header(text) != "technical support":
                    return text
    return ""


def axis_support_model(product_name: str) -> str:
    match = re.match(r"^(AXIS\s+[A-Z0-9][A-Z0-9-]+)", product_name, flags=re.I)
    if match:
        return normalize_text(match.group(1))
    return product_name


def axis_support_replacement(lines: list[str]) -> str:
    replacements: list[str] = []
    for line in lines:
        if line.startswith("Replacement:"):
            replacement = normalize_text(line.split(":", 1)[1])
            if replacement and replacement not in replacements:
                replacements.append(replacement)
    for index, line in enumerate(lines):
        if normalize_header(line) != "we have replaced this product with":
            continue
        for candidate in lines[index + 1:index + 8]:
            normalized = normalize_header(candidate)
            if normalized.startswith("see the") or "support" in normalized:
                break
            if re.match(r"^AXIS\s+[A-Z0-9][A-Z0-9-]+$", candidate, flags=re.I):
                replacements.append(normalize_text(candidate))
        break
    return "; ".join(dict.fromkeys(replacements))


def extract_axis_product_support_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.endswith(".html") or "support" not in path.name:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    if not any(normalize_header(line) == "product end of support" for line in lines):
        return []

    product_name = axis_support_product_name(lines)
    if not product_name:
        return []
    model = axis_support_model(product_name)
    description = normalize_text(product_name.replace(model, "", 1)) or product_name
    replacement = axis_support_replacement(lines)
    hardware_support = ""
    software_support = ""
    for line in lines:
        hardware_match = re.search(
            r"Hardware support and RMA service\s+(?:expired on|offered until)\s+"
            r"(\d{4}-\d{1,2}-\d{1,2})",
            line,
            flags=re.I,
        )
        if hardware_match:
            hardware_support = parse_date_any(hardware_match.group(1)) or hardware_support
        software_match = re.search(
            r"(?:AXIS OS|Software) support\s+(?:expired on|offered until|until)\s+"
            r"(\d{4}-\d{1,2}-\d{1,2})",
            line,
            flags=re.I,
        )
        if software_match:
            software_support = parse_date_any(software_match.group(1)) or software_support

    if not hardware_support and not software_support:
        return []

    row: dict[str, Any] = {
        "Model": model,
        "Product Name": product_name,
        "Description": description,
        "Product Status": "Product end of support",
        "Replacement Products": replacement,
        "_source_table": f"{path.name} product end-of-support section",
        "_source_hint": "Axis product support end-of-support page import",
    }
    if hardware_support:
        row["End of Service"] = hardware_support
    if software_support:
        row["End of Support"] = software_support
        row["End of Vulnerability Support"] = software_support
    return [row]


def fiberhome_term_key(value: Any) -> str:
    text = normalize_text(value).upper().replace("E0S", "EOS")
    return re.sub(r"[^A-Z0-9]+", "", text)


def fiberhome_replacement_text(value: Any) -> str:
    text = normalize_text(value).replace("\u3001", "; ")
    if normalize_header(text) in {"", "none"} or text in {"\u65e0", "\u6682\u65e0"}:
        return ""
    return text


def fiberhome_product_parts(value: Any) -> tuple[str, str, str]:
    product = normalize_text(value).replace("\uff08", "(").replace("\uff09", ")")
    product = product.replace("\u7cfb\u5217", " Series")
    product = normalize_text(product)
    paren = re.match(r"^(.+?)\s*\(([^)]+)\)$", product)
    if paren:
        return normalize_text(paren.group(1)), normalize_text(paren.group(2)), product
    parts = product.split()
    if (
        len(parts) == 2
        and re.match(r"^[A-Z0-9]{2,6}$", parts[0])
        and re.search(r"\d", parts[1])
    ):
        return parts[0], parts[1], product
    return product, product, product


def fiberhome_replacement_map(tables: list[tuple[int, list[list[str]]]]) -> dict[str, str]:
    replacements: dict[str, str] = {}
    for _, rows in tables:
        if not rows:
            continue
        header_pos = None
        product_idx = replacement_idx = None
        for pos, row in enumerate(rows[:4]):
            normalized = [normalize_text(cell) for cell in row]
            for idx, header in enumerate(normalized):
                if product_idx is None and "\u9000\u51fa\u4ea7\u54c1\u578b\u53f7" in header:
                    product_idx = idx
                if replacement_idx is None and "\u66ff\u4ee3\u4ea7\u54c1" in header:
                    replacement_idx = idx
            if product_idx is not None and replacement_idx is not None:
                header_pos = pos
                break
        if header_pos is None or product_idx is None or replacement_idx is None:
            continue
        for row in rows[header_pos + 1:]:
            if len(row) <= max(product_idx, replacement_idx):
                continue
            product = normalize_text(row[product_idx])
            replacement = fiberhome_replacement_text(row[replacement_idx])
            if not product or not replacement:
                continue
            model, part, full_name = fiberhome_product_parts(product)
            for key in {product, model, part, full_name}:
                normalized = normalize_header(key)
                if normalized:
                    replacements[normalized] = replacement
    return replacements


def extract_fiberhome_milestone_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    tables = [
        (table_index, html_table_matrix(table))
        for table_index, table in enumerate(soup.find_all("table"), start=1)
    ]
    replacements = fiberhome_replacement_map(tables)
    extracted: list[dict[str, Any]] = []

    for table_index, rows in tables:
        if len(rows) < 3:
            continue
        header_pos = None
        labels: list[str] = []
        for pos in range(min(4, len(rows) - 1)):
            first_row = " ".join(rows[pos])
            second_keys = [fiberhome_term_key(cell) for cell in rows[pos + 1]]
            if (
                "\u4ea7\u54c1" in first_row
                and "\u5173\u952e\u91cc\u7a0b\u7891" in first_row
                and any(key in {"EOM", "EOFS", "EOS", "EOP"} for key in second_keys)
            ):
                header_pos = pos
                labels = second_keys
                break
        if header_pos is None:
            continue

        last_dates: dict[str, str] = {}
        for row in rows[header_pos + 2:]:
            if not row:
                continue
            product = normalize_text(row[0])
            if not product or "\u4ea7\u54c1" in product:
                continue

            row_dates: dict[str, str] = {}
            for label_index, label in enumerate(labels, start=1):
                if label not in {"EOM", "EOFS", "EOS", "EOP"}:
                    continue
                value = row[label_index] if label_index < len(row) else ""
                parsed = parse_date_any(value)
                if parsed:
                    row_dates[label] = parsed
            if row_dates:
                last_dates = {**last_dates, **row_dates}
            elif last_dates and len(row) == 1:
                row_dates = dict(last_dates)
            else:
                row_dates = {**last_dates, **row_dates}

            if not row_dates:
                continue

            model, part_number, product_name = fiberhome_product_parts(product)
            replacement = ""
            for key in (product, product_name, model, part_number):
                replacement = replacements.get(normalize_header(key), "")
                if replacement:
                    break

            item: dict[str, Any] = {
                "Model": model,
                "Part Number": part_number,
                "Product Name": product_name,
                "Description": "FiberHome broadband access lifecycle schedule",
                "Product Status": "EOM/EOFS/EOS lifecycle schedule",
                "Replacement Products": replacement,
                "_source_table": f"{path.name} FiberHome milestone table {table_index}",
                "_source_hint": "FiberHome translated EOM/EOFS/EOS milestone schedule import",
                "_prefer_model": True,
            }
            if row_dates.get("EOM"):
                item["End of Sale"] = row_dates["EOM"]
            if row_dates.get("EOFS"):
                item["End of Support"] = row_dates["EOFS"]
                item["End of Vulnerability Support"] = row_dates["EOFS"]
            if row_dates.get("EOS"):
                item["End of Service"] = row_dates["EOS"]
            extracted.append(item)
    return extracted


def extract_hms_ewon_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in {
        "ewon-flexy-103-end-of-life.html",
        "ewon_flexy_103_end_of_life.html",
        "nhedb__raw__ewon-flexy-103-end-of-life.html",
    }:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    product_name = ""
    item_number = ""
    description = ""
    for index, line in enumerate(lines):
        if normalize_header(line) == "ewon flexy 103 end of life":
            product_name = "Ewon Flexy 103"
        if normalize_header(line).startswith("item number "):
            item_number = normalize_text(line.split(" ", 2)[-1])
        if "has been designed for" in line and "Ewon Flexy 103" in line:
            description_parts = [line]
            if index + 1 < len(lines) and re.match(r"^[a-z]", lines[index + 1]):
                description_parts.append(lines[index + 1])
            description = normalize_text(" ".join(description_parts))
    if not product_name:
        return []
    return [
        {
            "Model": product_name,
            "Part Number": item_number or product_name,
            "Product Name": f"{product_name} (End of Life)",
            "Description": description or "Industrial gateway",
            "Product Status": "End of Life",
            "_source_table": f"{path.name} product page",
            "_source_hint": "HMS Ewon product page end-of-life status review import",
            "_status_only_review": True,
            "_prefer_model": True,
            "_review_policy": "status_only_not_security_eol",
            "_review_reason": (
                "Source marks this product End of Life, but does not provide "
                "an exact support or security-update end date."
            ),
        }
    ]


def extract_hms_ewon_firmware_replacement_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "ewon_product_list_firmware_versions_replacement_guide.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    supported_on_talk2m = (
        "supported on the Talk2M platform for now" in text
        or "supported on our Talk2M platform for now" in text
    )
    if (
        "Ewon Product List: Firmware Versions and Replacement Guide" not in text
        or not supported_on_talk2m
    ):
        return []

    table = soup.find("table")
    if not table:
        return []

    rows: list[dict[str, Any]] = []
    family = ""
    upgrade_process = ""
    latest_firmware = ""
    for tr in table.find_all("tr"):
        cells = [
            normalize_text(cell.get_text(" ", strip=True))
            for cell in tr.find_all(["th", "td"])
        ]
        if not cells or cells[0] == "Product family":
            continue
        if len(cells) >= 5:
            family, models, serial_pattern, latest_firmware, upgrade_process = cells[:5]
        elif len(cells) >= 3:
            models, serial_pattern, latest_firmware = cells[:3]
        else:
            continue

        if upgrade_process not in {"Cosy141_replacement", "EwonCD_replacement"}:
            continue

        for model in [part.strip() for part in re.split(r",\s*", models) if part.strip()]:
            product_name = model if model.lower().startswith("ewon ") else f"Ewon {model}"
            row: dict[str, Any] = {
                "Model": product_name,
                "Part Number": serial_pattern,
                "Product Name": product_name,
                "Description": f"{family} remote access gateway",
                "Product Status": (
                    "HMS Ewon firmware/replacement guide lists this device "
                    f"under obsolete replacement process {upgrade_process}; "
                    "obsolete devices remain supported on the Talk2M platform "
                    "for now"
                ),
                "Lifecycle Status Source": path.name,
                "_source_table": (
                    f"{path.name} Ewon models and latest firmware versions table"
                ),
                "_source_hint": "HMS Ewon obsolete device replacement guide import",
                "_status_only_review": True,
                "_force_lifecycle_review": True,
                "_prefer_model": True,
                "_review_policy": "hms_ewon_obsolete_but_talk2m_supported",
                "_review_reason": (
                    "The HMS article identifies this exact Ewon device as an "
                    "obsolete replacement-guide entry, but also says obsolete "
                    "devices remain supported on the Talk2M platform for now "
                    "and does not publish an exact support, service, firmware, "
                    "vulnerability, or security-update end date."
                ),
                "_aliases": [product_name, model],
                "_suppress_description_aliases": True,
            }
            if latest_firmware:
                row["Latest Firmware"] = latest_firmware
            rows.append(row)
    return rows


def mitel_article_lines(path: Path) -> list[str]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    candidates = soup.select(".field--name-body, .node__content, article, main")
    node = candidates[0] if candidates else soup
    return [
        normalize_text(tag.get_text(" ", strip=True)).replace("A astra", "Aastra")
        for tag in node.find_all(["h1", "h2", "h3", "p", "li"])
        if normalize_text(tag.get_text(" ", strip=True))
    ]


def mitel_review_row(
    *,
    path: Path,
    model: str,
    status: str,
    description: str,
    aliases: list[str] | None = None,
    replacement: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": model,
        "Description": description,
        "Product Status": status,
        "Replacement Products": replacement,
        "_source_table": f"{path.name} Mitel lifecycle article",
        "_source_hint": "Mitel lifecycle article import",
        "_status_only_review": True,
        "_force_lifecycle_review": True,
        "_prefer_model": True,
        "_review_policy": "mitel_status_only_not_security_eol",
        "_review_reason": (
            "Mitel article identifies this product as discontinued, retired, "
            "or in an end-of-life process, but does not provide an exact "
            "support or security-update end date for this row."
        ),
        "_aliases": aliases or [],
    }
    return {key: value for key, value in row.items() if value}


def mitel_dated_row(
    *,
    path: Path,
    model: str,
    status: str,
    description: str,
    end_of_sale: str = "",
    end_of_life: str = "",
    end_of_support: str = "",
    aliases: list[str] | None = None,
    replacement: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": model,
        "Description": description,
        "Product Status": status,
        "Replacement Products": replacement,
        "_source_table": f"{path.name} Mitel lifecycle article",
        "_source_hint": "Mitel lifecycle article import",
        "_prefer_model": True,
        "_aliases": aliases or [],
    }
    if end_of_sale:
        row["End of Sale"] = end_of_sale
    if end_of_life:
        row["End of Life"] = end_of_life
        row["End of Support"] = end_of_life
        row["End of Vulnerability Support"] = end_of_life
        row["End of Security Updates"] = end_of_life
    if end_of_support:
        row["End of Support"] = end_of_support
        row["End of Vulnerability Support"] = end_of_support
    return {key: value for key, value in row.items() if value}


def extract_mitel_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() not in {".html", ".htm"}:
        return []
    accepted_pages = {
        "mivoice_office_250_alternatives.html",
        "unify_now_part_mitel.html",
        "what_happened_aastra_products.html",
        "what_happened_micloud_flex.html",
        "what_happened_mitel_products.html",
        "what_happened_shoretel_products.html",
    }
    if path.name not in accepted_pages:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(row: dict[str, Any]) -> None:
        key = (normalize_alias_dedupe_key(row.get("Model")), row.get("End of Support", ""))
        if key in seen:
            return
        seen.add(key)
        rows.append(row)

    lines = mitel_article_lines(path)
    text = "\n".join(lines)

    if path.name == "mivoice_office_250_alternatives.html":
        if "end-of-life process for MiVoice Office 250" in text:
            add(
                mitel_review_row(
                    path=path,
                    model="MiVoice Office 250",
                    status="End-of-life process announced",
                    description="Mitel business communications platform",
                    replacement="MiVoice Business",
                )
            )
        return rows

    if path.name == "unify_now_part_mitel.html":
        if "Unify Circuit has been retired" in text:
            add(
                mitel_review_row(
                    path=path,
                    model="Unify Circuit",
                    status="Retired",
                    description="Unify collaboration service",
                )
            )
        return rows

    if path.name == "what_happened_aastra_products.html":
        for line in lines:
            match = re.match(
                r"^(?:The )?(Aastra .+?) (?:has been discontinued ?\.?|became the (Mitel .+?)"
                r"(?:,? but it has now been discontinued ?\.?| but it has now been discontinued ?\.?))"
                r"(?: .*)?$",
                line,
            )
            if not match:
                continue
            model = normalize_text(match.group(1))
            renamed = normalize_text(match.group(2) or "")
            aliases = [model]
            if renamed:
                aliases.append(renamed)
            add(
                mitel_review_row(
                    path=path,
                    model=model,
                    status="Discontinued",
                    description="Legacy Aastra phone or communications product",
                    aliases=aliases,
                )
            )
        return rows

    if path.name in {"what_happened_mitel_products.html", "what_happened_micloud_flex.html"}:
        if "MiCloud Connect reached end of sale in June 2022" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="MiCloud Connect",
                    status="End of sale",
                    description="Mitel cloud communications service",
                    end_of_sale="2022-06-30",
                    aliases=["ShoreTel Connect Cloud"],
                )
            )
        if "Teamwork is part of MiCloud Connect" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="Teamwork",
                    status="End of sale as part of MiCloud Connect",
                    description="Mitel collaboration service",
                    end_of_sale="2022-06-30",
                )
            )
        if "MiCloud Connect Contact Center is part of MiCloud Connect" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="MiCloud Connect Contact Center",
                    status="End of sale as part of MiCloud Connect",
                    description="Mitel cloud contact-center service",
                    end_of_sale="2022-06-30",
                )
            )
        if "Retail and Partner Delivered versions of MiCloud Flex reached end of sale on June 30, 2022" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="MiCloud Flex Retail and Partner Delivered",
                    status="End of sale; existing customers continue to be supported",
                    description="Mitel cloud communications service",
                    end_of_sale="2022-06-30",
                    aliases=["MiCloud Flex Retail", "MiCloud Flex Partner Delivered"],
                    replacement="MiVoice Business Subscription",
                )
            )
        if "Wholesale versions of MiCloud Flex reached End of Sale on December 31, 2023" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="MiCloud Flex Wholesale",
                    status="End of sale; existing customers continue to be supported",
                    description="Mitel cloud communications service",
                    end_of_sale="2023-12-31",
                    replacement="MiVoice Business Subscription",
                )
            )
        if "MiCloud Business reached end of sale in December 2019 and will be End of Life June 2024" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="MiCloud Business",
                    status="End of Life",
                    description="Mitel cloud communications service",
                    end_of_sale="2019-12-31",
                    end_of_life="2024-06-30",
                    replacement="RingCentral; MiVoice Business Subscription",
                )
            )
        if "ShoreTel 14.2 / Mitel 14.2 reached end-of-life status in September 2020" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="ShoreTel 14.2 / Mitel 14.2",
                    status="End of Life",
                    description="Legacy ShoreTel/Mitel phone-system software",
                    end_of_life="2020-09-30",
                    aliases=["ShoreTel 14.2", "Mitel 14.2"],
                    replacement="MiVoice Business",
                )
            )

    if path.name == "what_happened_shoretel_products.html":
        if "MiVoice Connect" in text and "End of Technical Support will be December 31, 2029" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="MiVoice Connect",
                    status="End of Technical Support scheduled",
                    description="Mitel communications platform formerly ShoreTel Connect Onsite",
                    end_of_support="2029-12-31",
                    aliases=["ShoreTel Connect Onsite"],
                    replacement="MiVoice Business",
                )
            )
        if "ShoreTel 14.2 / Mitel 14.2 reached end-of-life status in September 2020" in text:
            add(
                mitel_dated_row(
                    path=path,
                    model="ShoreTel 14.2 / Mitel 14.2",
                    status="End of Life",
                    description="Legacy ShoreTel/Mitel phone-system software",
                    end_of_life="2020-09-30",
                    aliases=["ShoreTel 14.2", "Mitel 14.2"],
                    replacement="MiVoice Business",
                )
            )

    return rows


def extract_oring_phase_out_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() not in {".html", ".htm"}:
        return []
    if not (
        path.name.startswith("phase-out-")
        or path.name.startswith("nhedb__raw__phase-out-")
    ):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    title = next(
        (
            line
            for line in lines
            if normalize_header(line).startswith("phase out model")
        ),
        "",
    )
    if not title:
        return []
    models_text = re.split(r"[:\uff1a]", title, maxsplit=1)[-1]
    models = [
        normalize_text(part)
        for part in re.split(r"\s*,\s*", models_text)
        if normalize_text(part)
    ]
    notice_date = ""
    for line in lines:
        parsed = parse_date_any(line)
        if parsed:
            notice_date = parsed
            break
    extracted: list[dict[str, Any]] = []
    for model in dict.fromkeys(models):
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": model,
            "Description": "Industrial networking product",
            "Product Status": "Product End of Life / Change Notification",
            "_source_table": f"{path.name} phase-out notice",
            "_source_hint": "ORing product end-of-life phase-out notice review import",
            "_status_only_review": True,
            "_review_policy": "phase_out_notice_not_security_eol",
            "_review_reason": (
                "Source is an official phase-out/EOL notification, but this "
                "row does not provide an exact support or security-update end date."
            ),
        }
        if notice_date:
            row["Announcement Date"] = notice_date
        extracted.append(row)
    return extracted


def extract_phoenix_contact_sfn_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("fl-switch-sfn-discontinuation"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "FL SWITCH SFN" not in text or "discontinued" not in text.lower():
        return []
    return [
        {
            "Model": "FL SWITCH SFN",
            "Product Name": "FL SWITCH SFN family",
            "Description": "Industrial unmanaged switch family",
            "Product Status": "due to be discontinued",
            "Replacement Products": "FL SWITCH 1000",
            "_source_table": f"{path.name} discontinuation article",
            "_source_hint": "Phoenix Contact FL SWITCH SFN discontinuation article review import",
            "_status_only_review": True,
            "_review_policy": "discontinuation_article_not_security_eol",
            "_review_reason": (
                "Source says the product family is due to be discontinued, "
                "but does not provide an exact support or security-update end date."
            ),
        }
    ]


def extract_cradlepoint_ibr1700_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("ibr1700-600m-end-of-life-general-information"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    text = "\n".join(lines)
    if "IBR1700-600M" not in text or "Last Date of Support" not in text:
        return []

    def next_date(label: str) -> str:
        for index, line in enumerate(lines):
            if normalize_header(line).startswith(normalize_header(label)):
                window = " ".join(lines[index:index + 3])
                parsed = first_parsed_date(window)
                if parsed:
                    return parsed
        return ""

    announcement = next_date("End-of-Sale Announcement Date")
    end_sale = next_date("End-of-Sale Date")
    support_end = next_date("Last Date of Support")
    if not support_end:
        return []
    return [
        {
            "Model": "IBR1700-600M Series",
            "Product Name": "Cradlepoint IBR1700-600M Series Ruggedized Router",
            "Description": "Ruggedized Router",
            "Product Status": "End of Life; Last Date of Support listed",
            "Announcement Date": announcement,
            "End of Sale": end_sale,
            "End of Life": support_end,
            "End of Support": support_end,
            "End of Vulnerability Support": support_end,
            "_source_table": f"{path.name} lifecycle milestones",
            "_source_hint": "Ericsson Cradlepoint IBR1700-600M end-of-life support milestones import",
        }
    ]


def extract_baicells_nova233_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "nova233-end-of-life-announcement.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "Nova233" not in text or "Product End of Life" not in text:
        return []
    match = re.search(r"Product End of Life:\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})", text)
    eol_date = parse_date_any(match.group(1)) if match else None
    if not eol_date:
        return []

    rows = []
    for model in ("Nova233", "Nova R9"):
        rows.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Baicells {model} outdoor small cell",
                "Description": "Outdoor small cell",
                "Product Status": "End of Life; support and bug fixes ended",
                "End of Life": eol_date,
                "End of Support": eol_date,
                "End of Vulnerability Support": eol_date,
                "Replacement Products": "Nova436Q",
                "_source_table": f"{path.name} product end-of-life announcement",
                "_source_hint": "Baicells Nova233 end-of-life support and bug-fix notice import",
                "_prefer_model": True,
            }
        )
    return rows


def split_lorex_product_models(value: Any) -> list[str]:
    models = []
    for part in re.split(r",|\n", normalize_multiline_text(value)):
        model = normalize_text(part)
        if model:
            models.append(model)
    return models


def extract_lorex_psti_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product-use-policy.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "PSTI Product End-of-Life Policy" not in text:
        return []
    if "firmware updates (including security updates)" not in text:
        return []

    rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table")):
        table_rows = html_table_matrix(table, separator="\n")
        if not table_rows:
            continue
        headers = [normalize_header(cell) for cell in table_rows[0]]
        try:
            product_idx = headers.index("product name")
            model_idx = headers.index("product model")
            support_idx = headers.index("service and support end date")
        except ValueError:
            continue
        source_table = f"{path.name} PSTI milestone table {table_index + 1}"
        for table_row in table_rows[1:]:
            if len(table_row) <= max(product_idx, model_idx, support_idx):
                continue
            product_name = normalize_text(table_row[product_idx])
            support_end = parse_date_any(table_row[support_idx])
            if not product_name or not support_end:
                continue
            for model in split_lorex_product_models(table_row[model_idx]):
                rows.append(
                    {
                        "Model": model,
                        "Part Number": model,
                        "Product Name": f"Lorex {model}",
                        "Description": product_name,
                        "Product Status": "End of Service & Support (EOS) listed",
                        "End of Support": support_end,
                        "End of Vulnerability Support": support_end,
                        "_source_table": source_table,
                        "_source_hint": "Lorex PSTI product end-of-life support/security update schedule import",
                        "_prefer_model": True,
                    }
                )
    return rows


IPRO_MODEL_RE = re.compile(r"\b(?:WV|DG)-[A-Z0-9]+(?:-[A-Z0-9]+)?\b")


def extract_ipro_panasonic_discontinued_firmware_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in {
        "panasonic-ipro-eol-firmware-360.html",
        "panasonic-ipro-eol-firmware-ptz.html",
    }:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if not re.search(r"i-PRO|Panasonic", page_text):
        return []

    description = (
        "360-degree security camera"
        if "360" in path.stem
        else "PTZ security camera"
    )
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for h2 in soup.find_all("h2"):
        title = normalize_text(h2.get_text(" ", strip=True))
        for model in IPRO_MODEL_RE.findall(title):
            if model in seen:
                continue
            seen.add(model)
            rows.append(
                {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": model,
                    "Description": description,
                    "Product Status": "Production discontinued product firmware page",
                    "_source_table": f"{path.name} discontinued firmware sections",
                    "_source_hint": "i-PRO/Panasonic discontinued firmware page review import",
                    "_status_only_review": True,
                    "_review_policy": "production_discontinued_no_exact_support_date",
                    "_review_reason": (
                        "Source lists this model on an official discontinued "
                        "product firmware page, but no exact per-model support "
                        "or security-update end date is present in the row."
                    ),
                    "_prefer_model": True,
                }
            )
    return rows


def seagate_nas_os4_eol_date(path: Path, text: str = "") -> str | None:
    candidates = [text]
    sibling = path.parent / "seagate-nas-os-4.html"
    if sibling.exists() and sibling != path:
        soup = BeautifulSoup(
            sibling.read_text(encoding="utf-8", errors="ignore"),
            "lxml",
        )
        candidates.append(normalize_text(soup.get_text(" ", strip=True)))
    for candidate in candidates:
        match = re.search(
            r"End-of-Life effective\s+([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?,\s+\d{4})",
            candidate,
            flags=re.I,
        )
        if match:
            return parse_date_any(re.sub(r"(\d{1,2})(?:st|nd|rd|th)", r"\1", match.group(1)))
    return None


def extract_seagate_lacie_nas_os4_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "seagate-lacie-nas-os-4-end-of-life-de.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Seagate" not in page_text or "LaCie NAS OS 4" not in page_text:
        return []
    if "No more Security or Feature Updates" not in page_text:
        return []
    support_end = seagate_nas_os4_eol_date(path, page_text)

    device_list: list[str] = []
    marker = soup.find(string=re.compile(r"This article applies to the following devices", re.I))
    if marker:
        parent = marker.find_parent(["p", "div"])
        next_ul = parent.find_next("ul") if parent else None
        if next_ul:
            device_list = [
                normalize_text(li.get_text(" ", strip=True))
                for li in next_ul.find_all("li")
            ]
    if not device_list:
        return []

    rows: list[dict[str, Any]] = []
    for model in device_list:
        if not model:
            continue
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": model,
            "Description": "NAS storage",
            "Product Status": "NAS OS 4 End of Life; security updates discontinued",
            "_source_table": f"{path.name} affected NAS OS 4 device list",
            "_source_hint": "Seagate and LaCie NAS OS 4 end-of-life notice import",
            "_prefer_model": True,
        }
        if support_end:
            row["End of Support"] = support_end
            row["End of Vulnerability Support"] = support_end
            row["End of Service"] = support_end
        else:
            row["_status_only_review"] = True
            row["_review_policy"] = "seagate_lacie_nas_os4_no_exact_security_update_date"
            row["_review_reason"] = (
                "Source says NAS OS 4 security updates are discontinued, but "
                "no exact end date was found in the captured source set."
            )
        rows.append(row)
    return rows


LOCALIZED_MONTHS = {
    "jan": 1,
    "januar": 1,
    "feb": 2,
    "februar": 2,
    "maer": 3,
    "maerz": 3,
    "mar": 3,
    "mrz": 3,
    "apr": 4,
    "april": 4,
    "mai": 5,
    "jun": 6,
    "juni": 6,
    "jul": 7,
    "juli": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "okt": 10,
    "oktober": 10,
    "nov": 11,
    "november": 11,
    "dez": 12,
    "dezember": 12,
}


def parse_german_month_year(value: Any) -> str | None:
    text = normalize_text(value)
    parsed = parse_date_any(text, dayfirst=True)
    if parsed:
        return parsed
    match = re.search(
        r"\b([A-Za-z\u00c4\u00d6\u00dc\u00e4\u00f6\u00fc\u00df]+)\.?\s+(\d{4})\b",
        text,
    )
    if not match:
        return None
    month_text, year_text = match.groups()
    key = (
        month_text.lower()
        .replace("\u00e4", "ae")
        .replace("\u00f6", "oe")
        .replace("\u00fc", "ue")
        .replace("\u00df", "ss")
    )
    key = re.sub(r"[^a-z]", "", key)
    month = LOCALIZED_MONTHS.get(key)
    if not month:
        return None
    year = int(year_text)
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, last_day).isoformat()


def auerswald_product_title(soup: BeautifulSoup, path: Path) -> str:
    heading = soup.find("h1")
    if heading:
        title = normalize_text(heading.get_text(" ", strip=True)).replace("\u00ae", "")
        if title:
            return normalize_text(title)
    return normalize_text(path.stem.replace("-", " ").title())


def extract_auerswald_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = soup.get_text("\n", strip=True)
    if "End-of-Support" not in text:
        return []

    dates: dict[str, str] = {}
    for label, canonical in (
        ("End-of-Support", "End of Support"),
        ("End-of-Service", "End of Service"),
        ("End-of-Repair", "End of Repair"),
    ):
        match = re.search(
            rf"{re.escape(label)}:\s*([^\n]+)",
            text,
            flags=re.I,
        )
        if match:
            parsed = parse_german_month_year(match.group(1))
            if parsed:
                dates[canonical] = parsed
    support_end = dates.get("End of Support")
    if not support_end:
        return []

    model = auerswald_product_title(soup, path)
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": model,
        "Description": "IP communications product",
        "Product Status": (
            "End-of-Support listed; no further software updates guaranteed"
        ),
        "End of Support": support_end,
        "End of Vulnerability Support": support_end,
        "_source_table": f"{path.name} product lifecycle fields",
        "_source_hint": "Auerswald product page End-of-Support/End-of-Service lifecycle import",
        "_prefer_model": True,
    }
    if dates.get("End of Service"):
        row["End of Service"] = dates["End of Service"]
    if dates.get("End of Repair"):
        row["End of Repair"] = dates["End of Repair"]
    return [row]


def split_slash_model_aliases(value: Any) -> list[str]:
    text = normalize_text(value)
    if not text:
        return []
    parts = [normalize_text(part) for part in re.split(r"\s*/\s*", text) if normalize_text(part)]
    if len(parts) <= 1:
        return parts
    first = parts[0]
    prefix_match = re.match(r"^([A-Z]+[0-9]+)", first)
    prefix = prefix_match.group(1) if prefix_match else ""
    models = [first]
    for part in parts[1:]:
        if prefix and not re.search(r"\d", part):
            models.append(f"{prefix}{part}")
        else:
            models.append(part)
    return models


def extract_asustor_support_status_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product-support-status"):
        return []
    soup = BeautifulSoup(
        path.read_text(encoding="utf-8", errors="ignore"),
        "html.parser",
    )
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Product Support Status" not in page_text:
        return []
    if "Device will not receive updates" not in page_text:
        return []

    rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table")):
        for tr in table.find_all("tr"):
            cells = [
                normalize_text(cell.get_text(" ", strip=True))
                for cell in tr.find_all(["th", "td"])
            ]
            if len(cells) < 6:
                continue
            product_name = cells[0]
            availability = cells[2]
            software_support = cells[3]
            technical_support = cells[4]
            warranty = cells[5]
            if normalize_header(software_support) != "ended":
                continue
            for model in split_slash_model_aliases(product_name):
                rows.append(
                    {
                        "Model": model,
                        "Part Number": model,
                        "Product Name": model,
                        "Description": "NAS storage",
                        "Product Status": (
                            "Software support ended; device will not receive updates"
                        ),
                        "Product Availability": availability,
                        "Software Support": software_support,
                        "Technical Support": technical_support,
                        "Warranty Years": warranty,
                        "_source_table": f"{path.name} product support status table {table_index + 1}",
                        "_source_hint": "ASUSTOR product support status review import",
                        "_status_only_review": True,
                        "_review_policy": "asustor_software_support_ended_no_exact_date",
                        "_review_reason": (
                            "ASUSTOR defines ended software support as a device "
                            "not receiving updates, but this table row does not "
                            "provide an exact update or security-update end date."
                        ),
                        "_prefer_model": True,
                    }
                )
    return rows


def extract_terramaster_support_termination_rows(path: Path) -> list[dict[str, Any]]:
    if "technical-support-termination" not in path.name:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "technical support and maintenance services" not in text:
        return []
    if "applications and systems will no longer be updated" not in text:
        return []
    end_date = first_parsed_date(text)
    if not end_date:
        return []

    models_match = re.search(
        r"The product models involved are:\s*(.+?)\s*What does end",
        text,
        flags=re.I,
    )
    if not models_match:
        return []
    replacement_map: dict[str, str] = {}
    for old_model, new_model in re.findall(
        r"\b([A-Z0-9-]+(?:\s+\d+)?)\s+can be replaced with\s+([A-Z0-9-]+)",
        text,
        flags=re.I,
    ):
        replacement_map[normalize_text(old_model)] = normalize_text(new_model)

    rows: list[dict[str, Any]] = []
    for model in [normalize_text(part) for part in models_match.group(1).split(",")]:
        if not model:
            continue
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": model,
            "Description": "NAS storage",
            "Product Status": (
                "Technical support and maintenance services ended; "
                "applications and systems no longer updated"
            ),
            "End of Support": end_date,
            "End of Vulnerability Support": end_date,
            "End of Service": end_date,
            "_source_table": f"{path.name} support termination notice",
            "_source_hint": "TerraMaster technical support and maintenance termination notice import",
            "_prefer_model": True,
        }
        if replacement_map.get(model):
            row["Replacement Products"] = replacement_map[model]
        rows.append(row)
    return rows


def extract_siedle_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True)) if soup.title else ""
    if "discontinued" not in title.lower():
        return []

    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    try:
        start = next(
            idx for idx, line in enumerate(lines)
            if normalize_header(line) == "product information"
        )
    except StopIteration:
        return []

    rows: list[dict[str, Any]] = []
    for index in range(start + 1, len(lines) - 4):
        current = lines[index]
        normalized = normalize_header(current)
        if normalized in {"loading", "show more", "accessories", "spare parts"}:
            break
        article_number = lines[index + 4]
        if not re.match(r"^\d{9}-\d{2}$", article_number):
            continue
        description = lines[index + 1]
        if "discontinued" not in description.lower():
            continue
        color = lines[index + 2]
        product_description = normalize_text(
            re.sub(r"\s*\(discontinued\)\s*", "", description, flags=re.I)
        )
        row = {
            "Model": current,
            "Part Number": article_number,
            "Product Name": f"Siedle {current}",
            "Description": (
                f"{product_description}; color/material {color}"
                if color
                else product_description
            ),
            "Product Status": "Discontinued",
            "_source_table": f"{path.name} product information",
            "_source_hint": "Siedle discontinued product page review import",
            "_status_only_review": True,
            "_review_policy": "siedle_discontinued_product_page_not_security_eol",
            "_review_reason": (
                "Siedle product page marks this product variant discontinued, "
                "but it does not provide an exact support or security-update "
                "end date."
            ),
            "_aliases": [current, article_number, product_description],
            "_prefer_model": True,
        }
        rows.append(row)
    return rows


def balluff_title_parts(title: str) -> tuple[str, str, str]:
    match = re.match(
        r"^(?P<model>[A-Z0-9]+)\s+\((?P<part>[^)]+)\)\s+"
        r"(?P<description>.+?)\s+-\s+BALLUFF",
        title,
        flags=re.I,
    )
    if not match:
        return "", "", ""
    description = normalize_text(match.group("description")).replace(" und ", " and ")
    return (
        normalize_text(match.group("model")),
        normalize_text(match.group("part")),
        description,
    )


def balluff_main_feature(lines: list[str]) -> str:
    for index, line in enumerate(lines):
        if normalize_header(line) == "datasheet" and index + 1 < len(lines):
            candidate = normalize_text(lines[index + 1]).replace(" und ", " and ")
            if candidate and normalize_header(candidate) not in {"key features", "downloads"}:
                return candidate
    return ""


def balluff_replacement_products(lines: list[str], current_model: str) -> str:
    try:
        start = next(
            idx for idx, line in enumerate(lines)
            if normalize_header(line) == "alternative products"
        )
    except StopIteration:
        return ""

    window = lines[start + 1:start + 30]
    first_code_idx = None
    for idx, line in enumerate(window):
        if re.match(r"^[A-Z]{2,}\d[A-Z0-9]*$", line):
            first_code_idx = idx
            break
    if first_code_idx is None:
        return ""

    labels = [normalize_header(line) for line in window[:first_code_idx]]
    codes = []
    for line in window[first_code_idx:]:
        if re.match(r"^[A-Z]{2,}\d[A-Z0-9]*$", line):
            codes.append(line)
        else:
            break
    if len(codes) < 2:
        return ""

    part_start = first_code_idx + len(codes)
    part_numbers = []
    for line in window[part_start:part_start + len(codes)]:
        if re.match(r"^[A-Z0-9]+(?:\s+[A-Z0-9]+)+[-A-Z0-9 ]*$", line):
            part_numbers.append(line)

    replacement_indexes: list[int] = []
    if len(labels) == 1:
        replacement_indexes = [1]
    else:
        for idx, label in enumerate(labels):
            if idx == 0:
                continue
            if "alternative" in label:
                replacement_indexes.append(idx)
    replacements = []
    for idx in replacement_indexes:
        if idx >= len(codes):
            continue
        code = codes[idx]
        if normalize_header(code) == normalize_header(current_model):
            continue
        part = part_numbers[idx] if idx < len(part_numbers) else ""
        replacements.append(" / ".join(value for value in (code, part) if value))
    return "; ".join(dict.fromkeys(replacements))


def extract_balluff_product_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True)) if soup.title else ""
    model, part_number, title_description = balluff_title_parts(title)
    if not model:
        return []

    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    normalized_lines = [normalize_header(line) for line in lines]
    status = ""
    review_policy = "balluff_lifecycle_status_not_security_eol"
    review_reason = (
        "Balluff product page shows a lifecycle status, but it does not "
        "provide an exact support or security-update end date."
    )
    end_of_sale = ""
    if "canceled" in normalized_lines:
        status = "Canceled"
        review_policy = "balluff_canceled_not_security_eol"
    elif "soon no longer available" in normalized_lines:
        status = "Soon no longer available"
        review_policy = "balluff_available_until_not_security_eol"
        for index, line in enumerate(normalized_lines):
            if line == "available until" and index + 1 < len(lines):
                end_of_sale = parse_date_any(lines[index + 1]) or ""
                break
    elif "classic product" in normalized_lines:
        status = "Classic portfolio product"
        review_policy = "balluff_classic_portfolio_not_security_eol"
        review_reason = (
            "Balluff defines Classic products as approaching the end of their "
            "life cycle and no longer receiving product development, redesigns, "
            "or other updates, but this page does not provide an exact support "
            "or security-update end date."
        )
    else:
        return []

    feature_description = balluff_main_feature(lines)
    description = "; ".join(
        dict.fromkeys(
            value
            for value in (title_description, feature_description)
            if value
        )
    )
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": part_number or model,
        "Product Name": f"Balluff {model}",
        "Description": description or "IO-Link product",
        "Product Status": status,
        "Replacement Products": balluff_replacement_products(lines, model),
        "_source_table": f"{path.name} product lifecycle status",
        "_source_hint": "Balluff product lifecycle status page review import",
        "_status_only_review": True,
        "_force_lifecycle_review": True,
        "_review_policy": review_policy,
        "_review_reason": review_reason,
        "_aliases": [model, part_number, title_description, feature_description],
        "_prefer_model": True,
    }
    if end_of_sale:
        row["End of Sale"] = end_of_sale
    return [{key: value for key, value in row.items() if value}]


def beckhoff_service_table_section(table: Any, table_index: int) -> str:
    accordion_item = table.find_parent(
        lambda tag: tag.name == "div"
        and "accordion-item" in (tag.get("class") or [])
    )
    if accordion_item:
        button = accordion_item.find("button", class_="accordion-button")
        if button:
            return normalize_text(button.get_text(" ", strip=True))
    return f"service products table {table_index}"


def beckhoff_clean_text(value: Any) -> str:
    text = normalize_text(value)
    replacements = {
        "\u00ae": "",
        "\u2122": "",
        "\u00b0": " deg",
        "\u00b5": "u",
        "\u00d8": "diameter ",
        "\u03a9": "Ohm",
        "\u2026": " to ",
        "\u2211": "sum",
        "\u00b1": "+/-",
        "\u2013": "-",
        "\u2014": "-",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return normalize_text(text)


def beckhoff_normalize_status(value: Any) -> str:
    status = beckhoff_clean_text(value)
    status_key = normalize_header(status)
    if status_key in {"service phase", "servicephase", "servicep hase"}:
        return "Service phase"
    if status_key == "end of service":
        return "End of service"
    return status


def extract_beckhoff_service_product_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True)) if soup.title else ""
    if "service products" not in title.lower():
        return []

    rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix_with_rowspans(table)
        header_pos = None
        indexes: dict[str, int] = {}
        for pos, table_row in enumerate(matrix[:5]):
            normalized = [normalize_header(cell) for cell in table_row]
            current = {
                "product": next(
                    (idx for idx, header in enumerate(normalized) if header == "product"),
                    -1,
                ),
                "description": next(
                    (idx for idx, header in enumerate(normalized) if header == "short description"),
                    -1,
                ),
                "processor": next(
                    (idx for idx, header in enumerate(normalized) if header == "processor"),
                    -1,
                ),
                "status": next(
                    (idx for idx, header in enumerate(normalized) if header == "product status"),
                    -1,
                ),
                "discontinuation": next(
                    (idx for idx, header in enumerate(normalized) if header == "discontinuation"),
                    -1,
                ),
                "successor": next(
                    (
                        idx
                        for idx, header in enumerate(normalized)
                        if header == "successor product"
                    ),
                    -1,
                ),
            }
            if (
                current["product"] >= 0
                and current["status"] >= 0
                and current["discontinuation"] >= 0
            ):
                header_pos = pos
                indexes = current
                break
        if header_pos is None:
            continue

        section = beckhoff_service_table_section(table, table_index)
        for table_row in matrix[header_pos + 1:]:
            padded = table_row + [""] * max(0, len(matrix[header_pos]) - len(table_row))
            model = beckhoff_clean_text(padded[indexes["product"]])
            status = beckhoff_clean_text(padded[indexes["status"]])
            if not model or not status:
                continue
            if normalize_header(model) in {"product", "order number"}:
                continue
            status = beckhoff_normalize_status(status)

            discontinuation = beckhoff_clean_text(padded[indexes["discontinuation"]])
            end_of_sale = parse_date_any(discontinuation, dayfirst=True) or ""
            description_parts = [section]
            if indexes.get("description", -1) >= 0:
                description_parts.append(beckhoff_clean_text(padded[indexes["description"]]))
            if indexes.get("processor", -1) >= 0:
                processor = beckhoff_clean_text(padded[indexes["processor"]])
                if processor:
                    description_parts.append(f"processor {processor}")

            replacement = ""
            if indexes.get("successor", -1) >= 0:
                candidate = beckhoff_clean_text(padded[indexes["successor"]])
                candidate_key = normalize_header(candidate)
                if (
                    candidate_key
                    and "contact our service" not in candidate_key
                    and "contact service" not in candidate_key
                ):
                    replacement = candidate

            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Beckhoff {model}",
                "Description": "; ".join(dict.fromkeys(part for part in description_parts if part)),
                "Product Status": status,
                "_source_table": f"{path.name} {section} service products",
                "_source_hint": "Beckhoff service products lifecycle review import",
                "_status_only_review": True,
                "_force_lifecycle_review": True,
                "_review_policy": "beckhoff_service_phase_not_security_eol",
                "_review_reason": (
                    "Beckhoff marks this product as a service product in "
                    "service phase after discontinuation and offers service, "
                    "spare parts, or repair, but the captured source does not "
                    "state that firmware or security updates have ended."
                ),
                "_aliases": [value for value in (model, replacement) if value],
                "_prefer_model": True,
            }
            if end_of_sale:
                row["End of Sale"] = end_of_sale
            if replacement:
                row["Replacement Products"] = replacement
            rows.append({key: value for key, value in row.items() if value})
    return rows


def extract_kyocera_taskalfa_sales_end_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "taskalfa-4012w-sales-end-notice.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "TASKalfa 4012w" not in text or "\u8ca9\u58f2\u7d42\u4e86" not in text:
        return []

    date_match = re.search(r"(\d{4})\u5e74(\d{1,2})\u6708(\d{1,2})\u65e5", text)
    announcement = ""
    if date_match:
        announcement = parse_date_any(".".join(date_match.groups()))

    models = ["TASKalfa 4012w", "TASKalfa 4011w"]
    series_alias = "TASKalfa 4012w/4011w"
    rows: list[dict[str, Any]] = []
    for model in models:
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Kyocera {model}",
            "Description": (
                "Monochrome A2 multifunction printer series; sales ending "
                "when current inventory is exhausted; no successor products "
                "planned"
            ),
            "Product Status": "Sales ending when stock is exhausted",
            "_source_table": f"{path.name} sales-end notice",
            "_source_hint": "Kyocera TASKalfa 4012w series sales-end notice review import",
            "_status_only_review": True,
            "_force_lifecycle_review": True,
            "_review_policy": "kyocera_sales_end_notice_not_security_eol",
            "_review_reason": (
                "Kyocera says this printer series will end sales when current "
                "inventory is exhausted and no successor is planned, but the "
                "notice does not provide an exact support or security-update "
                "end date."
            ),
            "_aliases": [model, series_alias, "TASKalfa 4012w Series"],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        rows.append(row)
    return rows


def extract_lexmark_product_eosl_rows(path: Path) -> list[dict[str, Any]]:
    if not re.match(r"^lexmark-[a-z0-9-]+\.html$", path.name):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    text = " ".join(lines)
    if "This device has reached the end of its service life" not in text:
        return []
    if "Firmware Support" not in text or "Parts Support" not in text:
        return []

    model = ""
    for line in lines:
        match = re.fullmatch(r"Lexmark\s+([A-Z0-9][A-Za-z0-9 -]{1,40})", line)
        if match:
            model = normalize_text(match.group(1))
            break
    if not model:
        return []

    feature = ""
    for line in lines:
        if line.startswith("Printer features:"):
            feature = normalize_text(line.split(":", 1)[1])
            break

    return [
        {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Lexmark {model}",
            "Description": f"Printer; {feature}" if feature else "Printer",
            "Product Status": (
                "End of Service Life; Firmware Support discontinued; "
                "Maintenance Services discontinued; Parts Support discontinued"
            ),
            "_source_table": f"{path.name} end-of-service-life support page",
            "_source_hint": "Lexmark product support end-of-service-life page import",
            "_allow_status_only": True,
            "_review_policy": "lexmark_eosl_firmware_support_discontinued",
            "_review_reason": (
                "Lexmark states this device has reached end of service life "
                "and that firmware support, maintenance services, and parts "
                "support have been discontinued."
            ),
            "_aliases": [model, f"Lexmark {model}"],
            "_prefer_model": True,
        }
    ]


def synology_filter_option(payload: dict[str, Any], field: str, value: Any) -> str:
    filters = payload.get("filters")
    if not isinstance(filters, dict):
        return normalize_text(value)
    field_filter = filters.get(field)
    if not isinstance(field_filter, dict):
        return normalize_text(value)
    options = field_filter.get("options")
    if not isinstance(options, dict):
        return normalize_text(value)
    return normalize_text(options.get(str(value), value))


def synology_product_type_title(payload: dict[str, Any], product_type: str) -> str:
    product_types = payload.get("product_types")
    if not isinstance(product_types, dict):
        return ""
    product_type_data = product_types.get(product_type)
    if not isinstance(product_type_data, dict):
        return ""
    return normalize_text(product_type_data.get("title"))


def synology_device_description(category: str, product_type_title: str, product_type: str) -> str:
    descriptor_by_category = {
        "BeeDrive": "Storage drive",
        "Camera": "IP camera",
        "EmbeddedDataStation": "NAS storage device",
        "NAS": "NAS storage device",
        "NetworkVideoRecorder": "Network video recorder",
        "USBStation": "NAS storage device",
        "VisualStation": "Video surveillance station",
    }
    descriptor = descriptor_by_category.get(category, category)
    return "; ".join(
        dict.fromkeys(
            part
            for part in (
                descriptor,
                product_type_title or product_type,
            )
            if part
        )
    )


def extract_synology_product_status_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product-support-status-all"):
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "product_items" not in text or "firmware_support" not in text:
        return []
    match = re.search(r"\bvar\s+ret\s*=\s*(\{.*?\});", text, flags=re.S)
    if not match:
        return []
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return []
    product_items = payload.get("product_items")
    if not isinstance(product_items, dict):
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key, item in sorted(product_items.items()):
        if not isinstance(item, dict):
            continue
        if normalize_text(item.get("firmware_support")) != "suspended":
            continue
        model = normalize_text(item.get("name") or key)
        if not model or model in seen:
            continue
        seen.add(model)

        category = normalize_text(item.get("category"))
        product_type = normalize_text(item.get("type"))
        product_type_title = synology_product_type_title(payload, product_type)
        product_status = synology_filter_option(payload, "status", item.get("status"))
        firmware_status = synology_filter_option(
            payload,
            "firmware_support",
            item.get("firmware_support"),
        )
        support_status = synology_filter_option(payload, "support", item.get("support"))
        description = synology_device_description(
            category,
            product_type_title,
            product_type,
        )
        raw_status_parts = [
            f"Product Availability {product_status}" if product_status else "",
            f"OS/Firmware Update {firmware_status}" if firmware_status else "",
            "future firmware, software, and security/vulnerability updates discontinued",
        ]
        rows.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Synology {model}",
                "Description": description or "Synology hardware product",
                "Product Status": "; ".join(part for part in raw_status_parts if part),
                "Technical Support Status": support_status,
                "_source_table": f"{path.name} product support status data",
                "_source_hint": "Synology product support status page import",
                "_source_url": "https://www.synology.com/en-global/products/status?status=all",
                "_allow_status_only": True,
                "_review_policy": "synology_firmware_update_end_of_life",
                "_review_reason": (
                    "Synology defines OS/Firmware Update End of Life as future "
                    "firmware, software, and security/vulnerability updates "
                    "being discontinued."
                ),
                "_aliases": [model, f"Synology {model}"],
                "_prefer_model": True,
            }
        )
    return rows


def hp_effective_eosl_date(line: str) -> str:
    text = normalize_text(line)
    if "effective on" not in text.lower():
        return ""
    match = re.search(
        r"\b(\d{1,2})(?:st|nd|rd|th)?(?:\s+of)?\s+([A-Za-z]+)\s+(\d{4})\b",
        text,
        flags=re.I,
    )
    if not match:
        return ""
    day, month, year = match.groups()
    return parse_date_any(f"{day} {month} {year}") or ""


def hp_designjet_product_parts(line: str) -> tuple[str, str]:
    text = normalize_text(line)
    text = text.replace("\u2022", " ").replace("\u00b7", " ").replace("\t", " ")
    text = re.sub(r"^[*.-]+\s*", "", text)
    text = normalize_text(text)
    match = re.match(
        r"^([A-Z0-9]{4,12})\s*(?:-\s*)?(HP\s+Design\s*[Jj]et.+)$",
        text,
    )
    if not match:
        return "", ""
    return normalize_text(match.group(1)), normalize_text(match.group(2))


def hp_designjet_source_metadata(path: Path, soup: BeautifulSoup) -> tuple[str, str, str]:
    metadata_path = path.with_name(path.name.replace(".content.json", ".metadata.json"))
    document_id = ""
    title = ""
    language = ""
    if metadata_path.exists():
        try:
            metadata = load_json(metadata_path)
            data = metadata.get("data") if isinstance(metadata, dict) else {}
            if isinstance(data, dict):
                document_id = normalize_text(data.get("documentId"))
                title = normalize_text(data.get("title"))
                language = normalize_text(data.get("languageCode"))
        except Exception:
            pass
    if not title:
        h1 = soup.find("h1")
        title = normalize_text(h1.get_text(" ", strip=True)) if h1 else ""
    source_url = (
        f"https://support.hp.com/us-en/document/{document_id}"
        if document_id
        else ""
    )
    return title, source_url, language


def extract_hp_designjet_eosl_json_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.endswith(".content.json"):
        return []
    try:
        payload = load_json(path)
    except Exception:
        return []
    html = payload.get("data") if isinstance(payload, dict) else ""
    if not isinstance(html, str) or (
        "DesignJet" not in html and "Designjet" not in html
    ):
        return []

    soup = BeautifulSoup(html, "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "discontinue all services and support" not in text.lower():
        return []
    if "printer firmware" not in text.lower() or "eventual new vulnerabilities" not in text.lower():
        return []

    title, source_url, language = hp_designjet_source_metadata(path, soup)
    if language and language.lower() != "en":
        return []

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    current_date = ""
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    for index, line in enumerate(lines):
        if "effective on" in line.lower():
            effective_date = hp_effective_eosl_date(" ".join(lines[index:index + 4]))
            if effective_date:
                current_date = effective_date
                continue
        if not current_date:
            continue
        sku, product = hp_designjet_product_parts(line)
        if not sku or not product:
            continue
        key = (sku, product, current_date)
        if key in seen:
            continue
        seen.add(key)
        aliases = [sku, product]
        canonical_product = re.sub(r"\bDesignjet\b", "DesignJet", product, flags=re.I)
        if canonical_product != product:
            aliases.append(canonical_product)
        product_without_vendor = re.sub(r"^HP\s+", "", product, flags=re.I)
        if product_without_vendor != product:
            aliases.append(product_without_vendor)

        row = {
            "Model": product,
            "Part Number": sku,
            "Product Name": product,
            "Description": f"Printer; {product}",
            "Product Status": "End of Service Life; all services and support discontinued",
            "End of Support": current_date,
            "End of Vulnerability Support": current_date,
            "_source_table": f"{path.name} {title or 'HP DesignJet EOSL customer newsletter'}",
            "_source_hint": "HP DesignJet end-of-service-life customer newsletter import",
            "_aliases": aliases,
            "_prefer_model": True,
        }
        if source_url:
            row["_source_url"] = source_url
        rows.append(row)
    return rows


ZEBRA_REGION_LABELS = {
    "APAC": "APAC",
    "EMEA": "EMEA",
    "North America": "North America",
    "Latin America": "Latin America",
    "EMEA, LATAM & NA": "EMEA, LATAM and North America",
    "EMEA, North, and Latin America": "EMEA, North America and Latin America",
}


def zebra_clean_model(value: str) -> str:
    text = normalize_text(value).strip(",")
    return re.sub(r"\s+", " ", text).strip()


def zebra_models_from_lines(lines: list[str]) -> list[str]:
    models: list[str] = []
    for index, line in enumerate(lines):
        normalized = normalize_header(line)
        if normalized != "models" and not normalized.startswith("models "):
            continue
        inline = re.sub(r"^models\s*:?", "", line, flags=re.I).strip()
        candidates = ([inline] if inline else []) + lines[index + 1:index + 5]
        for candidate in candidates:
            candidate_text = normalize_text(candidate)
            if not candidate_text or candidate_text.startswith("The "):
                break
            if candidate_text.startswith("Zebra is no longer"):
                break
            for model in re.split(r",|/|\bor\b", candidate_text):
                model = zebra_clean_model(model)
                if model and model not in models:
                    models.append(model)
        break
    return models


def zebra_region_label(line: str) -> str:
    text = normalize_text(line)
    if text in ZEBRA_REGION_LABELS:
        return ZEBRA_REGION_LABELS[text]
    match = re.match(r"^(APAC|EMEA|North America|Latin America)\s+Discontinuation Dates:?", text)
    if match:
        return ZEBRA_REGION_LABELS[match.group(1)]
    return ""


def zebra_model_scope(line: str, fallback_models: list[str]) -> list[str]:
    text = normalize_text(line)
    match = re.match(r"^For\s+(.+?)\s+only$", text, flags=re.I)
    if not match:
        return fallback_models
    models = [
        zebra_clean_model(model)
        for model in re.split(r",|/|\bor\b", match.group(1))
        if zebra_clean_model(model)
    ]
    return models or fallback_models


def zebra_next_date(lines: list[str], index: int) -> str:
    date_pattern = (
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)"
        r"[a-z]*\s+\d{1,2},\s+\d{4}\b"
    )
    for candidate in lines[index:index + 4]:
        parsed = parse_date_any(candidate)
        if parsed:
            return parsed
        match = re.search(date_pattern, candidate, flags=re.I)
        if match:
            parsed = parse_date_any(match.group(0))
            if parsed:
                return parsed
    return ""


def zebra_product_title(soup: BeautifulSoup, fallback_model: str) -> str:
    h1 = soup.find("h1")
    title = normalize_text(h1.get_text(" ", strip=True)) if h1 else ""
    title = re.sub(r"\s+Support(?:\s*&.*)?$", "", title, flags=re.I)
    return title or fallback_model


def zebra_device_description(product_title: str, category: str) -> str:
    parts = [category, product_title]
    return "; ".join(dict.fromkeys(part for part in parts if part))


def extract_zebra_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    combined = " ".join(lines)
    if "Zebra is no longer offering this product for sale" not in combined:
        return []
    if "Service and Support Discontinuation Date" not in combined and (
        "Service & Support Discontinuation Date" not in combined
    ):
        return []

    models = zebra_models_from_lines(lines)
    if not models:
        return []
    product_title = zebra_product_title(soup, models[0])
    category_tag = soup.find(class_="eyebrow")
    category = normalize_text(category_tag.get_text(" ", strip=True)) if category_tag else ""
    description = zebra_device_description(product_title, category)

    rows: list[dict[str, Any]] = []
    replacements: list[str] = []
    for line in lines:
        if line.startswith("Replacement:"):
            replacement = normalize_text(line.split(":", 1)[1])
            if replacement and replacement not in replacements:
                replacements.append(replacement)

    current_region = ""
    current_models = models
    current_sale = ""
    current_last_sale = ""
    global_sale = ""
    seen: set[tuple[str, str, str, str, str]] = set()
    seen_lifecycle_notice = False

    for index, line in enumerate(lines):
        if line.startswith("Replacement:"):
            continue
        if line.startswith("Zebra is no longer offering this product for sale"):
            seen_lifecycle_notice = True
            current_region = ""
            current_models = models
            current_sale = ""
            current_last_sale = ""
            continue
        if not seen_lifecycle_notice:
            continue

        region = zebra_region_label(line)
        if region:
            current_region = region
            current_models = models
            current_sale = ""
            current_last_sale = ""
            continue

        scoped_models = zebra_model_scope(line, models)
        if scoped_models != models:
            current_region = ""
            current_models = scoped_models
            current_sale = ""
            current_last_sale = ""
            continue

        header = normalize_header(line)
        if (
            header.startswith("product discontinuation date")
            or header.startswith("printer discontinuation date")
        ):
            current_sale = zebra_next_date(lines, index)
            if not current_region:
                global_sale = current_sale or global_sale
            continue
        if header.startswith("last sale date"):
            current_last_sale = zebra_next_date(lines, index)
            continue
        if not (
            header.startswith("service and support discontinuation date")
            or header.startswith("service support discontinuation date")
        ):
            continue

        support_end = zebra_next_date(lines, index)
        if not support_end:
            continue
        for model in current_models:
            key = (
                model,
                current_region,
                current_sale or global_sale,
                current_last_sale,
                support_end,
            )
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": product_title,
                "Description": description,
                "Product Status": (
                    "Discontinued product; Service and Support Discontinuation Date published"
                ),
                "End of Support": support_end,
                "End of Vulnerability Support": support_end,
                "Replacement Products": " / ".join(replacements),
                "_source_table": f"{path.name} discontinued product support page",
                "_source_hint": "Zebra discontinued product support page import",
                "_aliases": [model, product_title, *models],
                "_prefer_model": True,
            }
            if current_region:
                row["Region"] = current_region
            if current_last_sale:
                row["Last Sale Date"] = current_last_sale
            elif current_sale or global_sale:
                row["End of Sale"] = current_sale or global_sale
            rows.append({key: value for key, value in row.items() if value})
    return rows


def extract_broadcom_bluecoat_packetshaper_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "packetshaper-stabilization-and-eol-announcement.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "Updated PacketShaper product Stabilization and End of Life announcement" not in text:
        return []
    if "PacketShaper into Stabilization status" not in text:
        return []

    eol_match = re.search(
        r"New date for end of life for\s+(.+?)\s+Models?\s+is\s*:?\s*"
        r"(\d{1,2}-[A-Za-z]{3,9}-\d{4})",
        text,
        flags=re.I,
    )
    if not eol_match:
        return []
    eol_date = parse_date_any(eol_match.group(2))
    if not eol_date:
        return []

    maintenance_match = re.search(
        r"New date for Last Date to Purchase the Maintenance Date\s+is\s*:?\s*"
        r"(\d{1,2}-[A-Za-z]{3,9}-\d{4})",
        text,
        flags=re.I,
    )
    maintenance_date = (
        parse_date_any(maintenance_match.group(1)) if maintenance_match else ""
    )
    models = [
        normalize_text(model)
        for model in re.split(r"\s*,\s*|\s+and\s+", eol_match.group(1))
        if normalize_text(model)
    ]

    rows: list[dict[str, Any]] = []
    for model in models:
        rows.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": f"PacketShaper {model}",
                "Description": f"PacketShaper network appliance; {model}",
                "Product Status": "Stabilization; End of Life date announced",
                "End of Support": eol_date,
                "End of Life": eol_date,
                "Last Maintenance Purchase": maintenance_date,
                "_source_table": f"{path.name} PacketShaper stabilization advisory",
                "_source_hint": (
                    "Broadcom PacketShaper stabilization and EOL announcement"
                ),
                "_aliases": [
                    model,
                    f"PacketShaper {model}",
                    f"Broadcom PacketShaper {model}",
                ],
                "_prefer_model": True,
            }
        )
    return rows


def extract_buffalo_nas_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "terastation-7000-eol.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    title_tag = soup.find("title")
    title = normalize_text(title_tag.get_text(" ", strip=True) if title_tag else "")
    combined = f"{title} {text}"
    if "TeraStation 7000" not in combined or "Entered EOL" not in combined:
        return []
    return [
        {
            "Model": "TeraStation 7000 Series",
            "Part Number": "TeraStation 7000 Series",
            "Product Name": "TeraStation 7000 Series",
            "Description": "NAS storage family",
            "Product Status": "Entered EOL",
            "_source_table": f"{path.name} end-of-life announcement",
            "_source_hint": "Buffalo Americas TeraStation 7000 EOL announcement review import",
            "_status_only_review": True,
            "_review_policy": "buffalo_family_eol_no_exact_support_date",
            "_review_reason": (
                "Buffalo announces that this NAS family entered EOL, but the "
                "captured source does not provide an exact support or "
                "security-update end date."
            ),
            "_prefer_model": True,
        }
    ]


def cleaned_vendor_cell(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none", "null", "not applicable"}:
        return ""
    if text in {"-", "–", "—"}:
        return ""
    return text


def split_2n_product_and_order(value: Any) -> tuple[str, str]:
    text = cleaned_vendor_cell(value)
    if not text:
        return "", ""
    bracket = re.search(r"\s*\[([A-Z0-9][A-Z0-9._-]+)\]\s*$", text, flags=re.I)
    if bracket:
        return normalize_text(text[: bracket.start()]), cleaned_vendor_cell(bracket.group(1))
    return text, ""


def extract_2n_page_discontinuation_date(path: Path) -> str:
    try:
        soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "html.parser")
    except OSError:
        return ""
    text = soup.get_text(" ", strip=True)
    patterns = (
        r"Discontinuation date in\b[^:]*:\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        r"discontinuation date\b[^:]*:\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        r"final order date\b[^.]*?\bis\s+(\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]+\s+\d{4})",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            parsed = parse_date_any(match.group(1))
            if parsed:
                return parsed
    return ""


def extract_2n_page_security_update_date(path: Path) -> str:
    try:
        soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "html.parser")
    except OSError:
        return ""
    text = soup.get_text(" ", strip=True)
    if "security updates" not in text.lower() and "bug fixes" not in text.lower():
        return ""
    match = re.search(
        r"security updates and bug fixes\b.*?\buntil\s+([A-Za-z]+\s+\d{4})",
        text,
        flags=re.I,
    )
    if not match:
        return ""
    return parse_date_any(match.group(1)) or ""


def extract_2n_voiceblue_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "news_voiceblue_next_gateway_discontinued_en_gb.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "html.parser")
    lines = [
        normalize_text(line)
        for line in soup.get_text("\n", strip=True).splitlines()
        if normalize_text(line)
    ]
    try:
        start = lines.index("Name")
    except ValueError:
        return []
    if start + 2 >= len(lines) or normalize_header(lines[start + 1]) != "order number":
        return []
    if "final order date" not in normalize_header(lines[start + 2]):
        return []

    rows: list[dict[str, Any]] = []
    index = start + 3
    while index + 2 < len(lines):
        product = cleaned_vendor_cell(lines[index])
        order = cleaned_vendor_cell(lines[index + 1])
        final_order = parse_date_any(lines[index + 2], dayfirst=True)
        if not product or product.startswith("*") or not order or not final_order:
            break
        rows.append(
            {
                "Product Name": product,
                "Part Number": order,
                "End of Sale": final_order,
                "Replacement Products": "",
                "Product Status": "end of sale",
                "_source_table": f"{path.name} product discontinuation text table",
                "_source_hint": "2N end-of-sale product notice",
                "_review_policy": "2n_final_order_is_sales_end",
                "_prefer_model": True,
            }
        )
        index += 3
    return rows


def extract_2n_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("news_"):
        return []

    rows: list[dict[str, Any]] = []
    page_sale = extract_2n_page_discontinuation_date(path)
    page_security = extract_2n_page_security_update_date(path)
    for row in extract_html_tables(path):
        product = cleaned_vendor_cell(
            row.get("Discontinued Product")
            or row.get("Discontinued product")
            or row.get("Product Name")
        )
        product, embedded_part = split_2n_product_and_order(product)
        if normalize_header(product) in {"name", "discontinued product", "product"}:
            continue
        part_number = cleaned_vendor_cell(
            row.get("Order Number")
            or row.get("Order number")
            or row.get("End of Life Order Number")
            or row.get("column_2")
            or embedded_part
        )
        replacement = cleaned_vendor_cell(
            row.get("Replacement Product") or row.get("Replacement product")
        )
        replacement_part = cleaned_vendor_cell(
            row.get("Replacement Order Number")
            or row.get("Replacement order number")
            or row.get("Order number 4")
        )
        if replacement_part and replacement:
            replacement = f"{replacement} ({replacement_part})"
        elif replacement_part:
            replacement = replacement_part

        sale = (
            parse_date_any(row.get("Final Order Date"))
            or parse_date_any(row.get("Final order date"))
            or parse_date_any(row.get("Last order date"))
            or page_sale
        )
        support = (
            parse_date_any(row.get("Final Support Date"))
            or parse_date_any(row.get("Final support date"))
        )
        if not product or not (part_number or sale or support or replacement):
            continue

        item = {
            "Product Name": product,
            "Part Number": part_number or product,
            "End of Sale": sale or "",
            "End of Support": support or "",
            "Replacement Products": replacement,
            "Product Status": (
                "discontinued product" if support or page_security or not sale else "end of sale"
            ),
            "_source_table": row.get("_source_table") or path.name,
            "_source_hint": (
                "2N discontinued product table"
                if support or page_security or not sale
                else "2N end-of-sale product table"
            ),
            "_review_policy": "2n_final_order_is_sales_end_final_support_is_support_end",
            "_prefer_model": True,
        }
        if page_security:
            item["End of Security Updates"] = page_security
        if not sale and not support and not page_security:
            item.update(
                {
                    "_status_only_review": True,
                    "_review_policy": "2n_discontinued_no_exact_support_date",
                    "_review_reason": (
                        "2N identifies this product as discontinued or replaced, "
                        "but this captured row does not provide an exact support "
                        "or security-update end date."
                    ),
                }
            )
        rows.append(item)

    rows.extend(extract_2n_voiceblue_rows(path))
    return rows


def extract_antaira_phaseout_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("phaseout_") or path.suffix.lower() not in {".html", ".htm"}:
        return []

    category = path.stem.removeprefix("phaseout_").replace("_", " ")
    rows = []
    for row in extract_html_tables(path):
        model = cleaned_vendor_cell(row.get("EOL Model"))
        if not model or normalize_header(model) in {"eol model", "model"}:
            continue
        notification = parse_date_any(row.get("Notification Date")) or ""
        phase_out_start = parse_date_any(row.get("Phase Out Start Date")) or ""
        rows.append(
            {
                "Model": model,
                "Product Name": model,
                "Description": category,
                "Product Status": "phase out",
                "Announcement Date": notification,
                "Phase Out Start Date": phase_out_start,
                "Replacement Products": cleaned_vendor_cell(row.get("Alternative Model")),
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "Antaira phase-out product notice table",
                "_status_only_review": True,
                "_review_policy": "antaira_phaseout_not_security_eol",
                "_review_reason": (
                    "Antaira lists this model in a phase-out/EOL notice, but "
                    "the table does not provide an exact support or "
                    "security-update end date."
                ),
                "_prefer_model": True,
            }
        )
    return rows


def parse_tippingpoint_date(value: Any) -> str:
    text = cleaned_vendor_cell(value)
    if not text:
        return ""
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    match = re.match(r"^([A-Za-z]{3,9})/(\d{1,2})/(\d{4})$", text)
    if not match:
        return ""
    month_name, day_text, year_text = match.groups()
    try:
        month = datetime.strptime(month_name[:3].title(), "%b").month
        return date(int(year_text), month, int(day_text)).isoformat()
    except ValueError:
        return ""


def split_tippingpoint_skus(value: Any) -> list[str]:
    text = cleaned_vendor_cell(value)
    if not text:
        return []
    return [
        cleaned_vendor_cell(part)
        for part in re.split(r"/|,", text)
        if cleaned_vendor_cell(part)
    ]


def extract_tippingpoint_eol_dates_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "tippingpoint_eol_dates.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        source_table = row.get("_source_table") or path.name
        if "Device" in row:
            device = cleaned_vendor_cell(row.get("Device"))
            sku = cleaned_vendor_cell(row.get('"J" SKU') or row.get("J SKU"))
            if not device or normalize_header(device) == "supported":
                continue
            announcement = parse_tippingpoint_date(row.get("Announcement Date"))
            end_sale = parse_tippingpoint_date(row.get("End of Sale"))
            end_life = parse_tippingpoint_date(row.get("End of Life"))
            if not (end_sale or end_life):
                continue
            aliases = split_tippingpoint_skus(sku)
            rows.append(
                {
                    "Model": device,
                    "Part Number": sku or device,
                    "Product Name": f"TippingPoint {device}",
                    "Description": "TippingPoint hardware appliance or module",
                    "Announcement Date": announcement,
                    "End of Sale": end_sale,
                    "End of Life": end_life,
                    "End of Support": end_life,
                    "End of Security Updates": end_life,
                    "Bulletin Number": cleaned_vendor_cell(row.get("Bulletin Number")),
                    "_source_table": source_table,
                    "_source_hint": "TippingPoint official EOL dates table",
                    "_review_policy": "tippingpoint_eol_is_maintenance_end",
                    "_aliases": aliases,
                    "_prefer_model": True,
                }
            )
            continue

        version = cleaned_vendor_cell(row.get("End-of-Life"))
        product = cleaned_vendor_cell(row.get("End-of-Life 2"))
        bulletin = cleaned_vendor_cell(row.get("End-of-Life 3"))
        announcement = parse_tippingpoint_date(row.get("End-of-Life 4"))
        end_life = parse_tippingpoint_date(row.get("End-of-Life 5"))
        if not product or normalize_header(product) == "supported" or not version or not end_life:
            continue
        rows.append(
            {
                "Model": product,
                "Part Number": f"{product} {version}",
                "Product Name": f"TippingPoint {product} software {version}",
                "Version": version,
                "Description": "TippingPoint software or operating-system lifecycle",
                "Announcement Date": announcement,
                "End of Life": end_life,
                "End of Support": end_life,
                "End of Security Updates": end_life,
                "Bulletin Number": bulletin,
                "_source_table": source_table,
                "_source_hint": "TippingPoint official EOL dates table",
                "_review_policy": "tippingpoint_eol_is_maintenance_end",
                "_prefer_model": True,
            }
        )
    return rows


def patton_model_identity(value: Any) -> tuple[str, str, list[str]]:
    product_name = cleaned_vendor_cell(value)
    if not product_name:
        return "", "", []
    model = re.sub(r"^Model\s+", "", product_name, flags=re.I).strip()
    aliases = [product_name]
    if model != product_name:
        aliases.append(model)
        aliases.append(f"Patton Model {model}")
    for part in re.split(r"\s*(?:,|&)\s*", model):
        part = cleaned_vendor_cell(part)
        if not part or "/" in part or " " in part:
            continue
        aliases.extend([part, f"Model {part}", f"Patton Model {part}"])
    return model or product_name, product_name, list(dict.fromkeys(aliases))


def patton_replacement_from_description(value: Any) -> str:
    text = cleaned_vendor_cell(value)
    if not text:
        return ""
    if "no replacement" in text.lower():
        return "No replacement"
    match = re.search(
        r"(?:please see|see)\s+Patton'?s?\s+(.+?)(?:\.|$)",
        text,
        flags=re.I,
    )
    if not match:
        return ""
    replacement = normalize_text(match.group(1))
    replacement = re.sub(r"^(?:SmartNode\s+)?Models?\s+", "", replacement, flags=re.I)
    return replacement


def extract_patton_sunset_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "sunset_eol_products.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        visible = [(key, value) for key, value in row.items() if not str(key).startswith("_")]
        if len(visible) < 2:
            continue
        product_value = visible[0][1]
        description_value = visible[1][1]
        model, product_name, aliases = patton_model_identity(product_value)
        if not model or normalize_header(model) in {"name", "description"}:
            continue
        description = cleaned_vendor_cell(description_value)
        rows.append(
            {
                "Model": model,
                "Product Name": product_name,
                "Part Number": model,
                "Description": description or "Patton sunset or EOL product",
                "Product Status": "sunset or end-of-life product",
                "Replacement Products": patton_replacement_from_description(description),
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "Patton Sunset & EOL Products catalog",
                "_status_only_review": True,
                "_review_policy": "patton_legacy_eol_or_sunset_no_exact_support_date",
                "_review_reason": (
                    "Patton lists this product in its Sunset & EOL Products "
                    "catalog, but this catalog row does not provide an exact "
                    "support or security-update end date."
                ),
                "_aliases": aliases,
                "_prefer_model": True,
            }
        )
    return rows


def extract_multitech_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "multitech_eol_products.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        order_part = normalize_text(row.get("Ordering Part #"))
        eol_date = normalize_text(row.get("EOL DATE"))
        if not order_part or not eol_date:
            continue
        rows.append(
            {
                "Tradename": normalize_text(row.get("Tradename")),
                "Ordering Part #": order_part,
                "MultiTech P/N": normalize_text(row.get("MultiTech P/N")),
                "Announcement": normalize_text(row.get("NEOL")),
                "End of Sale": eol_date,
                "Replacement Model Number": normalize_text(row.get("Replacement Model Number")),
                "Replacement 9-level": normalize_text(row.get("Replacement 9-level")),
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "MultiTech lifecycle products table",
                "_review_policy": "multitech_eol_date_is_sales_end_not_security_eol",
            }
        )
    return rows


def extract_sangoma_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_life_eol.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        product_name = normalize_text(row.get("Product Name"))
        sku = normalize_text(row.get("SKU"))
        support_end = normalize_text(row.get("Support End"))
        effective_date = normalize_text(row.get("Effective Date"))
        if not product_name or not sku or not (support_end or effective_date):
            continue
        rows.append(
            {
                "Product Name": product_name,
                "SKU": sku,
                "Category": normalize_text(row.get("Category")),
                "End of Life": effective_date,
                "End of Support": support_end,
                "Announcement": normalize_text(row.get("Added to EOL")),
                "Replacement Product": normalize_text(row.get("Replacement Product")),
                "Replacement SKU": normalize_text(row.get("Replacement SKU")),
                "Detailed Information": normalize_text(row.get("Detailed Information")),
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "Sangoma End-Of-Life table",
                "_review_policy": "sangoma_eol_effective_date_with_support_end",
            }
        )
    return rows


def clavister_product_and_replacement(value: Any) -> tuple[str, str]:
    text = normalize_text(value)
    if not text:
        return "", ""
    product = re.split(
        r"\bThe designated replacement product is\b|\bThere is no designated replacement product\b|\bFor legacy information\b",
        text,
        maxsplit=1,
        flags=re.I,
    )[0]
    product = re.sub(r"\s*\(pdf\)\s*", " ", product, flags=re.I)
    product = normalize_text(product)

    replacement = ""
    match = re.search(
        r"The designated replacement product is\s+(.+?)(?:\.|For legacy information|$)",
        text,
        flags=re.I,
    )
    if match:
        replacement = normalize_text(match.group(1))
    return product, replacement


def extract_clavister_end_of_sales_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_sales.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        product_field = row.get("Hardware Products") or row.get("Software and services")
        product, replacement = clavister_product_and_replacement(product_field)
        sale = parse_date_any(row.get("End of sales date"))
        eol = parse_date_any(row.get("End of life date")) or first_parsed_date(
            normalize_text(row.get("End of life date"))
        )
        if not product or not (sale or eol):
            continue
        rows.append(
            {
                "Product Name": product,
                "End of Sale": sale or "",
                "End of Life": eol or "",
                "Replacement Product": replacement,
                "Description": (
                    "Hardware product"
                    if row.get("Hardware Products")
                    else "Software or service"
                ),
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "Clavister End-of-Sales table",
                "_review_policy": "clavister_eos_supported_until_eol",
            }
        )
    return rows


def netgate_product_identity(value: Any) -> tuple[str, str, str, list[str]]:
    text = normalize_text(value)
    if not text:
        return "", "", "", []

    replacement = ""
    product = text
    replaced_match = re.search(r"\bReplaced by:\s*(.+)$", text, flags=re.I)
    if replaced_match:
        product = text[: replaced_match.start()]
        replacement = replaced_match.group(1)
    else:
        no_replacement_match = re.search(
            r"\bThere is no replacement product\.?$",
            text,
            flags=re.I,
        )
        if no_replacement_match:
            product = text[: no_replacement_match.start()]
            replacement = "No replacement"

    product = normalize_text(product).rstrip(" .")
    replacement = normalize_text(replacement).rstrip(" .")
    if not product:
        return "", "", replacement, []

    model = re.sub(r"^Netgate\s+", "", product, flags=re.I).strip()
    model = normalize_text(model) or product
    aliases = [product, model]
    if not product.lower().startswith("netgate "):
        aliases.append(f"Netgate {model}")
    return model, product, replacement, list(dict.fromkeys(aliases))


def extract_netgate_product_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product_lifecycle.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        model, product_name, replacement, aliases = netgate_product_identity(
            row.get("Product Information")
        )
        eos = parse_date_any(row.get("EOS Date"))
        eol = parse_date_any(row.get("EOL Date"))
        if not model or not (eos or eol):
            continue
        rows.append(
            {
                "Model": model,
                "Product Name": product_name,
                "Part Number": model,
                "Description": "Netgate firewall or security gateway appliance",
                "End of Sale": eos or "",
                "End of Life": eol or "",
                "Replacement Products": replacement,
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "Netgate Product Lifecycle table",
                "_force_lifecycle_review": True,
                "_review_policy": "netgate_eol_date_not_uniform_security_update_proof",
                "_review_reason": (
                    "Netgate publishes hardware EOS/EOL dates, but public "
                    "lifecycle wording does not prove that firmware or "
                    "security updates stop for every hardware platform at the "
                    "EOL date. Review exact appliance and software support "
                    "before issuing a hard unsupported finding."
                ),
                "_aliases": aliases,
                "_prefer_model": True,
            }
        )
    return rows


def extract_stormshield_firewall_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "matrices_firewalls.html":
        return []

    rows = []
    for row in extract_html_tables(path):
        product = normalize_text(row.get("Product"))
        end_sale = parse_date_any(row.get("End of Sales"))
        end_life = parse_date_any(row.get("End of Life"))
        if not product or not (end_sale or end_life):
            continue
        rows.append(
            {
                "Model": product,
                "Product Name": f"Stormshield {product}",
                "Part Number": product,
                "Description": "Stormshield Network Security physical firewall",
                "End of Sale": end_sale or "",
                "End of Life": end_life or "",
                "End of Support": end_life or "",
                "End of Security Updates": end_life or "",
                "_source_table": row.get("_source_table") or path.name,
                "_source_hint": "Stormshield physical firewall lifecycle matrix",
                "_review_policy": "stormshield_eol_stops_maintenance_and_support",
                "_aliases": [product, f"Stormshield {product}"],
                "_prefer_model": True,
            }
        )
    return rows


def glinet_article_context(path: Path) -> tuple[str, str, str]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    article = soup.select_one("#blog-post-content") or soup.select_one("article")
    text = normalize_text(article.get_text(" ", strip=True) if article else soup.get_text(" ", strip=True))
    source_url = ""
    if tag := soup.find("meta", attrs={"property": "og:url"}):
        source_url = normalize_text(tag.get("content"))
    published = ""
    if tag := soup.find("meta", attrs={"property": "article:published_time"}):
        published = first_parsed_date(tag.get("content")) or parse_date_any(tag.get("content")) or ""
    return text, source_url, published


def glinet_model_variants(value: Any) -> list[dict[str, Any]]:
    text = normalize_text(value)
    if not text:
        return []

    version = ""
    version_match = re.search(r"\bwith\s+(.+)$", text, flags=re.I)
    if version_match and "(" in text and ")" in text:
        version = normalize_text(version_match.group(1))

    match = re.search(r"^(?P<label>.+?)\s*\((?P<codes>[^)]+)\)(?P<tail>.*)$", text)
    if match:
        label = normalize_text(match.group("label"))
        codes = [
            normalize_text(code)
            for code in re.split(r"\s*[/,;]\s*", match.group("codes"))
            if normalize_text(code)
        ]
        tail = normalize_text(match.group("tail"))
        variants = []
        for code in codes:
            product_name = normalize_text(f"{label} ({code}) {tail}")
            aliases = [code, product_name]
            if label:
                aliases.append(label)
            variants.append(
                {
                    "model": code,
                    "product_name": product_name or code,
                    "hardware_version": version,
                    "aliases": list(dict.fromkeys(aliases)),
                }
            )
        return variants

    variants = []
    for item in [
        normalize_text(part)
        for part in re.split(r"\s*[/,;]\s*", text)
        if normalize_text(part)
    ]:
        variants.append(
            {
                "model": item,
                "product_name": item,
                "hardware_version": "",
                "aliases": [item],
            }
        )
    return variants


def add_glinet_rows(
    rows: list[dict[str, Any]],
    *,
    path: Path,
    model_text: str,
    replacement: str = "",
    effective: str = "",
    support_end: str = "",
    source_url: str = "",
    source_table: str = "",
) -> None:
    effective_date = first_parsed_date(effective) or parse_date_any(effective) or ""
    support_date = first_parsed_date(support_end) or parse_date_any(support_end) or ""
    if not support_date and not effective_date:
        return
    replacement_text = normalize_text(replacement)
    replacement_text = re.sub(r"\s+([,;/])", r"\1", replacement_text)
    replacement_text = re.sub(r"([,;/])\s*", r"\1 ", replacement_text).strip()
    for variant in glinet_model_variants(model_text):
        row = {
            "Model": variant["model"],
            "Product Name": variant["product_name"],
            "Part Number": variant["model"],
            "Hardware Version": variant["hardware_version"],
            "Description": "GL.iNet router product EOL notice",
            "End of Life": effective_date,
            "End of Support": support_date,
            "End of Security Updates": support_date,
            "Replacement Products": replacement_text,
            "_source_table": source_table or path.name,
            "_source_hint": "GL.iNet product EOL notice",
            "_review_policy": "glinet_eol_support_end_security_firmware_updates",
            "_aliases": variant["aliases"],
            "_prefer_model": True,
        }
        if source_url:
            row["_source_url"] = source_url
        rows.append(row)


def extract_glinet_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("blog_") or path.suffix.lower() not in {".html", ".htm"}:
        return []

    text, source_url, published = glinet_article_context(path)
    if "End of Life" not in text and "EOL" not in text and "Supported until:" not in text:
        return []

    rows: list[dict[str, Any]] = []
    for table_row in extract_html_tables(path):
        model = table_row.get("(EOL) Model Name") or table_row.get("EOL Model Name")
        support = table_row.get("(EOL) Support Ends") or table_row.get("EOL Support Ends")
        if not model or not support:
            continue
        add_glinet_rows(
            rows,
            path=path,
            model_text=model,
            replacement=table_row.get("Substitute Model") or "",
            effective=table_row.get("(EOL) Effective Datest")
            or table_row.get("(EOL) Effective Date")
            or "",
            support_end=support,
            source_url=source_url,
            source_table=table_row.get("_source_table") or path.name,
        )

    block_pattern = re.compile(
        r"Model Names?:\s*(?P<models>.+?)"
        r"(?:\s+Substitute Models?:\s*(?P<replacement>.+?))?"
        r"(?:\s+\(EOL\) Effective Date:\s*(?P<effective>.+?))?"
        r"(?:\s+\(EOL\) Support Ends:\s*(?P<support>.+?))"
        r"(?=\s+Model Names?:|\s+We are discontinuing|\s+The firmware|\s+GL\.iNet values|\s+Learn more|$)",
        flags=re.I,
    )
    for match in block_pattern.finditer(text):
        add_glinet_rows(
            rows,
            path=path,
            model_text=match.group("models"),
            replacement=match.group("replacement") or "",
            effective=match.group("effective") or "",
            support_end=match.group("support") or "",
            source_url=source_url,
        )

    supported_until_pattern = re.compile(
        r"Model Name:\s*(?P<model>.+?)\s+Supported until:\s*(?P<support>.+?)\s*\(",
        flags=re.I,
    )
    for match in supported_until_pattern.finditer(text):
        add_glinet_rows(
            rows,
            path=path,
            model_text=match.group("model"),
            effective=published,
            support_end=match.group("support"),
            source_url=source_url,
        )

    mudi_pattern = re.compile(
        r"Model Name:\s*(?P<model>Mudi\s*\(GL-E750V2\)\s*with\s+vSIM Technology)"
        r"\s+EOL Effective Date:\s*(?P<effective>.+?)"
        r"\s+Support End Date:\s*(?P<support>.+?)\s*\(",
        flags=re.I,
    )
    for match in mudi_pattern.finditer(text):
        add_glinet_rows(
            rows,
            path=path,
            model_text=match.group("model"),
            effective=match.group("effective"),
            support_end=match.group("support"),
            source_url=source_url,
        )

    support_all_match = re.search(
        r"(?:The\s+)?firmware of the abovementioned EOL products will still be maintained "
        r"and supported for 2 years\s*\(until (?P<support>[^)]+)\)",
        text,
        flags=re.I,
    )
    if support_all_match:
        intro = text[: support_all_match.start()]
        simple_pattern = re.compile(
            r"Model Names?:\s*(?P<models>.+?)"
            r"(?:\s+Substitute Models?:\s*(?P<replacement>.+?))?"
            r"(?=\s+Model Names?:|\s+The firmware|$)",
            flags=re.I,
        )
        for match in simple_pattern.finditer(intro):
            add_glinet_rows(
                rows,
                path=path,
                model_text=match.group("models"),
                replacement=match.group("replacement") or "",
                effective=published,
                support_end=support_all_match.group("support"),
                source_url=source_url,
            )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (
            normalize_header(row.get("Model")),
            normalize_header(row.get("Hardware Version")),
            row.get("End of Support") or "",
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def extract_inhand_networks_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "inhand_networks_eol_products.html":
        return []

    rows = []
    for table_row in extract_html_tables(path):
        model = normalize_text(table_row.get("EOL Product"))
        support_end = parse_date_any(table_row.get("End of Support"))
        order_end = parse_date_any(table_row.get("End of Ordering"))
        if not model or not support_end:
            continue
        replacement = normalize_text(table_row.get("Replacement"))
        row = {
            "Model": model,
            "Product Name": model,
            "Part Number": model,
            "Description": "InHand Networks EOL product",
            "End of Sale": order_end or "",
            "End of Support": support_end,
            "End of Security Updates": support_end,
            "Replacement Products": replacement,
            "_source_table": table_row.get("_source_table") or path.name,
            "_source_hint": "InHand Networks EOL products table",
            "_source_url": "https://www.inhand.com/en/support/eol-products/",
            "_review_policy": "inhand_end_of_support_marks_support_end",
            "_aliases": [model],
            "_prefer_model": True,
        }
        rows.append(row)
    return rows


def extract_netmodule_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "netmodule_end_of_life.html":
        return []

    rows = []
    for table_row in extract_html_tables(path):
        product = normalize_text(table_row.get("Product"))
        support_end = parse_date_any(table_row.get("End of Support and repair"))
        if not product or not support_end:
            continue
        product_key = normalize_header(product)
        if " products" in f" {product_key}" or "/" in product:
            continue
        notice = normalize_text(table_row.get("Product Discontinuation Notice"))
        row = {
            "Model": product,
            "Product Name": product,
            "Part Number": product,
            "Description": "NetModule end-of-life product",
            "End of Support": support_end,
            "End of Security Updates": support_end,
            "_source_table": table_row.get("_source_table") or path.name,
            "_source_hint": "NetModule End of Life products table",
            "_source_url": "https://wiki.netmodule.com/documentation/end-of-life",
            "_review_policy": "netmodule_end_of_support_and_repair_marks_support_end",
            "_aliases": [product],
            "_prefer_model": True,
        }
        if notice:
            row["Product Discontinuation Notice"] = notice
        rows.append(row)
    return rows


def zte_lifecycle_source_url(path: Path) -> str:
    match = re.search(r"eom_eol_notice_(\d+)", path.name)
    if match:
        return f"https://support.zte.com.cn/support/news/NewsDetail.aspx?newsId={match.group(1)}"
    return ""


def zte_lifecycle_date(value: Any) -> str:
    text = normalize_text(value)
    if not text or normalize_header(text) in {"n a", "na", "none", "not applicable"}:
        return ""
    text = re.sub(r"(?<=\d)\s+(?=\d)", "", text)
    text = re.sub(r"([A-Za-z]{3,})\s+\.", r"\1.", text)
    text = re.sub(r"([A-Za-z]{3,})\.(?=\d)", r"\1. ", text)
    text = re.sub(r"\s+([,/.])", r"\1", text)
    text = re.sub(r"([,/])\s*", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return parse_date_any(text) or first_parsed_date(text) or ""


def zte_normalize_model(value: Any) -> str:
    text = normalize_text(value)
    if not text:
        return ""
    text = re.sub(r"\bZX\s+R\s*10\b", "ZXR10", text, flags=re.I)
    text = re.sub(r"\bZX\s+R10\b", "ZXR10", text, flags=re.I)
    text = re.sub(r"\bZX\s+UN\b", "ZXUN", text, flags=re.I)
    text = re.sub(r"\bZXHN\s+H\s+(?=\d)", "ZXHN H", text, flags=re.I)
    text = re.sub(r"-\s+", "-", text)
    text = re.sub(r"(?<=\d)\s+(?=[A-Z]\b)", "", text)
    text = re.sub(r"(?<=\d)\s+(?=\d+[A-Z]-)", "", text)
    return normalize_text(text)


def zte_product_models(value: Any) -> list[str]:
    text = normalize_text(value)
    if not text:
        return []
    return [
        model
        for model in (
            zte_normalize_model(part)
            for part in re.split(r"\s*[\u3001;]\s*", text)
        )
        if model
    ]


def zte_lifecycle_header_map(header: list[str]) -> dict[str, int]:
    normalized = [normalize_header(cell) for cell in header]
    if not normalized or normalized[0] not in {"product", "product name"}:
        return {}

    mapping: dict[str, int] = {"product": 0}
    for index, cell in enumerate(normalized):
        if cell == "eom" or cell == "product end of market date":
            mapping["eom"] = index
        elif cell == "ltbsp" or cell == "part end of market date":
            mapping["ltbsp"] = index
        elif cell == "eofs" or cell == "end of full support":
            mapping["eofs"] = index
        elif cell == "eos":
            mapping["eos"] = index
        elif cell == "eos plan":
            mapping["eos_plan"] = index
        elif cell in {"substitutes", "substitute", "replacement product"}:
            mapping["replacement"] = index
        elif cell == "end of service date":
            mapping["eos"] = index
    if "eom" not in mapping and "eos" not in mapping and "eos_plan" not in mapping:
        return {}
    return mapping


def extract_zte_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() not in {".html", ".htm"}:
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.get_text(" ", strip=True))
    source_url = zte_lifecycle_source_url(path)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = [
            [normalize_text(cell) for cell in row]
            for row in html_table_matrix(table)
            if any(normalize_text(cell) for cell in row)
        ]
        if len(matrix) < 2:
            continue
        mapping = zte_lifecycle_header_map(matrix[0])
        if not mapping:
            continue

        for raw_row in matrix[1:]:
            if normalize_header(raw_row[0] if raw_row else "") in {
                "full name",
                "name",
                "product",
            }:
                break
            cells = list(raw_row) + [""] * max(0, len(matrix[0]) - len(raw_row))
            models = zte_product_models(cells[mapping["product"]])
            if not models:
                continue
            end_sale = zte_lifecycle_date(cells[mapping["eom"]]) if "eom" in mapping else ""
            eofs = zte_lifecycle_date(cells[mapping["eofs"]]) if "eofs" in mapping else ""
            eos = zte_lifecycle_date(cells[mapping["eos"]]) if "eos" in mapping else ""
            eos_plan = (
                zte_lifecycle_date(cells[mapping["eos_plan"]])
                if "eos_plan" in mapping
                else ""
            )
            if not end_sale and not eofs and not eos and not eos_plan:
                continue
            ltbsp = zte_lifecycle_date(cells[mapping["ltbsp"]]) if "ltbsp" in mapping else ""
            replacement = (
                zte_normalize_model(cells[mapping["replacement"]])
                if "replacement" in mapping
                else ""
            )

            for model in models:
                row = {
                    "Model": model,
                    "Product Name": model,
                    "Part Number": model,
                    "Description": "ZTE product lifecycle notice",
                    "End of Sale": end_sale,
                    "Last Time Buy of Spare Parts": ltbsp,
                    "End of Service": eos,
                    "End of Security Updates": eofs or eos,
                    "Replacement Products": replacement,
                    "_source_table": f"{path.name} table {table_index}",
                    "_source_hint": "ZTE product lifecycle notice table",
                    "_review_policy": "zte_eom_market_eos_service_support",
                    "_aliases": [model, f"ZTE {model}"],
                    "_prefer_model": True,
                }
                if eos_plan and not eos:
                    row.pop("End of Service", None)
                    row.pop("End of Security Updates", None)
                    row["Planned EOS"] = eos_plan
                    row["_force_lifecycle_review"] = True
                if "ZXR10" in title and not model.startswith("ZXR10"):
                    row["_aliases"].append(f"ZXR10 {model}")
                if source_url:
                    row["_source_url"] = source_url
                key = (model, end_sale, eofs, eos or eos_plan)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(row)
    return rows


ETHERWAN_EOL_NOTICE_URL = "https://www.etherwan.com/us/support/eol-notice"


def etherwan_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel="canonical")
    href = normalize_text(canonical.get("href") if canonical else "")
    return href or ETHERWAN_EOL_NOTICE_URL


def etherwan_notice_body(soup: BeautifulSoup) -> tuple[str, str, str]:
    article = soup.find("article") or soup
    title_node = article.find("h1")
    title = normalize_text(title_node.get_text(" ", strip=True)) if title_node else ""
    body_node = article.find(class_="field--name-body") or article
    body = normalize_text(body_node.get_text(" ", strip=True))
    return title, body, normalize_header(f"{title} {body}")


def etherwan_is_lifecycle_notice(normalized_body: str) -> bool:
    has_lifecycle_wording = any(
        phrase in normalized_body
        for phrase in (
            "product eol",
            "product end life",
            "product end of life",
            "end of life",
            "end of life for",
            "end of life notice",
            "end of life eol",
            "end of life phase out",
            "end of life phaseout",
            "end of life product",
            "end of life for the following",
            "strategically announce the end of life",
            "strategically announce end of life",
            "eol notice",
            "phase out",
            "phasing out",
            "discontinue",
            "discontinuing",
            "discontinued",
        )
    )
    if not has_lifecycle_wording:
        return False
    if "engineering change notice" in normalized_body and not any(
        phrase in normalized_body
        for phrase in (
            "end of life",
            "product eol",
            "phase out",
            "phasing out",
            "discontinue",
            "discontinuing",
            "discontinued",
        )
    ):
        return False
    return True


def etherwan_date_text(value: Any) -> str:
    text = normalize_text(value)
    text = re.sub(r"(\d{1,2})\s+(st|nd|rd|th)\b", r"\1\2", text, flags=re.I)
    text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
    text = re.sub(r"\b([A-Za-z]{3,9})\.", r"\1", text)
    text = re.sub(r"\bfor limited stock\b", "", text, flags=re.I)
    text = re.sub(r"\blimited stock\b", "", text, flags=re.I)
    text = re.sub(r"\s*,\s*", ", ", text)
    return normalize_text(text)


def etherwan_parse_date(value: Any) -> str | None:
    text = etherwan_date_text(value)
    if not text:
        return None
    for candidate in (text, text.replace(",", "")):
        parsed = parse_date_any(candidate)
        if parsed:
            return parsed
        month_day_year = re.fullmatch(
            r"([A-Za-z]{3,9})\s+(\d{1,2})\s+(\d{4})",
            candidate,
            flags=re.I,
        )
        if month_day_year:
            parsed = parse_date_any(
                f"{month_day_year.group(1)} {month_day_year.group(2)}, "
                f"{month_day_year.group(3)}"
            )
            if parsed:
                return parsed
    return first_parsed_date(text)


def etherwan_label_date(body: str, labels: tuple[str, ...]) -> str | None:
    for label in labels:
        pattern = rf"\b{re.escape(label)}\s*:\s*([A-Za-z0-9.,/\- ]{{4,40}})"
        match = re.search(pattern, body, flags=re.I)
        if not match:
            continue
        parsed = etherwan_parse_date(match.group(1))
        if parsed:
            return parsed
    return None


def etherwan_header_map(headers: list[str]) -> dict[str, list[int] | int] | None:
    normalized = [normalize_header(header) for header in headers]
    product_idx = next(
        (
            idx
            for idx, header in enumerate(normalized)
            if header in {"product name", "old part number"}
            or "product name" in header
            or "old part number" in header
        ),
        None,
    )
    if product_idx is None:
        return None

    end_sale_idx = next(
        (
            idx
            for idx, header in enumerate(normalized)
            if "last buy" in header
            or "last order" in header
            or "last time buy" in header
        ),
        None,
    )
    if end_sale_idx is None:
        return None

    result: dict[str, list[int] | int] = {"product": product_idx, "end_sale": end_sale_idx}
    announcement_idx = next(
        (idx for idx, header in enumerate(normalized) if "notification date" in header),
        None,
    )
    if announcement_idx is not None:
        result["announcement"] = announcement_idx
    shipment_idx = next(
        (idx for idx, header in enumerate(normalized) if "last shipment" in header),
        None,
    )
    if shipment_idx is not None:
        result["shipment"] = shipment_idx
    replacement_indexes = [
        idx
        for idx, header in enumerate(normalized)
        if any(
            word in header
            for word in ("replacement", "successor", "alternative", "replacing")
        )
    ]
    if replacement_indexes:
        result["replacement"] = replacement_indexes
    return result


def etherwan_clean_table_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none"}:
        return ""
    if re.fullmatch(r"-+", text):
        return ""
    return text


def etherwan_split_product_values(value: Any) -> list[str]:
    products: list[str] = []
    model_token_re = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9][A-Za-z0-9-]{2,}$")
    for part in split_multiline_values(value):
        product = etherwan_clean_table_value(part)
        if not product:
            continue
        if normalize_header(product) in {"product name", "old part number"}:
            continue
        product_key = normalize_header(product)
        if "series" not in product_key and "," not in product and "(" not in product:
            slash_parts = [item.strip() for item in product.split("/") if item.strip()]
            if len(slash_parts) > 1 and all(model_token_re.fullmatch(item) for item in slash_parts):
                products.extend(slash_parts)
                continue
            space_parts = [item.strip() for item in product.split() if item.strip()]
            if len(space_parts) > 1 and all(model_token_re.fullmatch(item) for item in space_parts):
                products.extend(space_parts)
                continue
        products.append(product)
    return products


def extract_etherwan_eol_notice_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title, body, normalized_body = etherwan_notice_body(soup)
    if not etherwan_is_lifecycle_notice(normalized_body):
        return []

    source_url = etherwan_source_url(soup)
    notice_date = etherwan_label_date(
        body,
        (
            "Effective Date",
            "Issue Date",
            "Date",
        ),
    )
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator="\n")
        if len(matrix) < 2:
            continue
        header_pos = None
        mapping = None
        for pos, row in enumerate(matrix[:4]):
            mapping = etherwan_header_map(row)
            if mapping:
                header_pos = pos
                break
        if header_pos is None or mapping is None:
            continue

        product_idx = int(mapping["product"])
        end_sale_idx = int(mapping["end_sale"])
        announcement_idx = mapping.get("announcement")
        shipment_idx = mapping.get("shipment")
        replacement_indexes = list(mapping.get("replacement") or [])
        for raw_row in matrix[header_pos + 1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[header_pos]) - len(raw_row))
            if product_idx >= len(cells) or end_sale_idx >= len(cells):
                continue
            raw_end_sale = normalize_text(cells[end_sale_idx])
            if normalize_header(raw_end_sale) == "immediate":
                end_sale = notice_date
            else:
                end_sale = etherwan_parse_date(raw_end_sale)
            if not end_sale:
                continue

            announcement = ""
            if isinstance(announcement_idx, int) and announcement_idx < len(cells):
                announcement = etherwan_parse_date(cells[announcement_idx]) or ""
            if not announcement:
                announcement = notice_date or ""

            shipment = ""
            if isinstance(shipment_idx, int) and shipment_idx < len(cells):
                shipment = etherwan_parse_date(cells[shipment_idx]) or ""

            replacements = [
                etherwan_clean_table_value(cells[idx])
                for idx in replacement_indexes
                if idx < len(cells) and etherwan_clean_table_value(cells[idx])
            ]
            replacement = "; ".join(dict.fromkeys(replacements))

            for model in etherwan_split_product_values(cells[product_idx]):
                key = (normalize_alias_dedupe_key(model), end_sale, replacement)
                if key in seen:
                    continue
                seen.add(key)
                description = "EtherWAN product lifecycle notice"
                if title:
                    description = f"{description}; {title}"
                if shipment:
                    description = f"{description}; last shipment {shipment}"
                row: dict[str, Any] = {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": model,
                    "Description": description,
                    "Product Status": "Sales/order milestone listed for affected product",
                    "End of Sale": end_sale,
                    "Replacement Products": replacement,
                    "_source_table": f"{path.name} EtherWAN EOL table {table_index}",
                    "_source_hint": "EtherWAN last-buy/order notice import",
                    "_source_url": source_url,
                    "_review_policy": "etherwan_last_buy_not_security_eol",
                    "_aliases": [model, f"EtherWAN {model}"],
                    "_prefer_model": True,
                }
                if announcement:
                    row["Announcement Date"] = announcement
                rows.append(row)
    return rows


ROBUSTEL_EOL_POLICY_URL = "https://robustel.com/eol-and-pcn/"


def robustel_clean_replacement(value: Any) -> str:
    text = normalize_text(value)
    text = re.sub(r"\bNOTE:.*$", "", text, flags=re.I)
    if normalize_header(text) in {"", "n a", "na", "none"}:
        return ""
    return normalize_text(text)


def robustel_header(value: Any) -> str:
    return normalize_header(value).replace("eo l", "eol")


def extract_robustel_eol_policy_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "robustel_eol_and_pcn_policy.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator="\n")
        if len(matrix) < 2:
            continue
        header_pos = None
        header_map: dict[str, int] = {}
        for pos, row in enumerate(matrix[:4]):
            normalized = [robustel_header(cell) for cell in row]
            if "product name" not in normalized:
                continue
            candidate = {header: idx for idx, header in enumerate(normalized)}
            if not {
                "eol effective date",
                "end of sale date",
                "end of services date",
                "end of software support date",
            }.issubset(candidate):
                continue
            header_pos = pos
            header_map = candidate
            break
        if header_pos is None:
            continue
        for raw_row in matrix[header_pos + 1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[header_pos]) - len(raw_row))
            model = normalize_text(cells[header_map["product name"]])
            if not model or normalize_header(model) in {"product name", "product"}:
                continue
            announcement = parse_date_any(cells[header_map["eol effective date"]])
            end_sale = parse_date_any(cells[header_map["end of sale date"]])
            end_services = parse_date_any(cells[header_map["end of services date"]])
            end_software = parse_date_any(cells[header_map["end of software support date"]])
            if not (end_sale or end_services or end_software):
                continue
            replacement = robustel_clean_replacement(
                cells[header_map.get("replacement product", -1)]
                if "replacement product" in header_map
                else ""
            )
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": model,
                "Description": "Robustel product lifecycle policy row",
                "Product Status": "Lifecycle policy schedule",
                "_source_table": f"{path.name} table {table_index}",
                "_source_hint": "Robustel EOL policy table import",
                "_source_url": ROBUSTEL_EOL_POLICY_URL,
                "_review_policy": "robustel_services_and_software_support_end",
                "_aliases": [model, f"Robustel {model}"],
                "_prefer_model": True,
            }
            if announcement:
                row["Announcement Date"] = announcement
            if end_sale:
                row["End of Sale"] = end_sale
            if end_services:
                row["End of Service"] = end_services
                row["End of Support"] = end_services
            if end_software:
                row["End of Software Support"] = end_software
                row["End of Security Updates"] = end_software
            if replacement:
                row["Replacement Products"] = replacement
            rows.append(row)
    return rows


HILLSTONE_EOL_POLICY_URL = (
    "https://www.hillstonenet.com/more/services/end-of-life-policy-and-announcement/"
)


def hillstone_parse_date(value: Any) -> str | None:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none"}:
        return None
    text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
    text = re.sub(r"\b([A-Za-z]{3,9})\.", r"\1", text)
    text = re.sub(r"(\d{1,2})(?:st|nd|rd|th)\b", r"\1", text, flags=re.I)
    text = normalize_text(text)
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    month_day_year = re.fullmatch(r"([A-Za-z]{3,9})\s+(\d{1,2})\s+(\d{4})", text)
    if month_day_year:
        return parse_date_any(
            f"{month_day_year.group(1)} {month_day_year.group(2)}, "
            f"{month_day_year.group(3)}"
        )
    return first_parsed_date(text)


def hillstone_split_model_values(value: Any) -> list[str]:
    models: list[str] = []
    for item in split_comma_values(value):
        model = re.sub(r"^\s*Hillstone\s+", "", item, flags=re.I)
        model = re.sub(r"\s*\*\s*$", "", model)
        model = normalize_text(model)
        if model and normalize_header(model) not in {"models", "model"}:
            models.append(model)
    return models


def hillstone_model_identity(value: str) -> tuple[str, str]:
    product = normalize_text(value)
    code_match = re.match(
        r"^([A-Z]{1,5}(?:-[A-Z0-9]+)*-?\d[A-Za-z0-9+/-]*)(?:\s+(.+))?$",
        product,
    )
    if code_match:
        model = code_match.group(1)
        suffix = normalize_text(code_match.group(2))
        product_name = f"Hillstone {model}"
        if suffix:
            product_name = f"{product_name} {suffix}"
        return model, product_name
    return product, f"Hillstone {product}"


def extract_hillstone_eol_policy_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_life_policy_and_announcement.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = HILLSTONE_EOL_POLICY_URL
    canonical = soup.find("link", rel="canonical")
    if canonical:
        source_url = normalize_text(canonical.get("href")) or source_url

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator="\n")
        if len(matrix) < 2:
            continue

        header_pos = None
        header_map: dict[str, int] = {}
        for pos, row in enumerate(matrix[:4]):
            normalized = [normalize_header(cell) for cell in row]
            candidate = {header: idx for idx, header in enumerate(normalized)}
            if {
                "models",
                "end of sales date",
                "end of software support date",
                "end of hardware support date",
            }.issubset(candidate):
                header_pos = pos
                header_map = candidate
                break
        if header_pos is None:
            continue

        for raw_row in matrix[header_pos + 1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[header_pos]) - len(raw_row))
            raw_models = normalize_text(cells[header_map["models"]])
            end_sale = hillstone_parse_date(cells[header_map["end of sales date"]])
            software_support = hillstone_parse_date(
                cells[header_map["end of software support date"]]
            )
            hardware_support = hillstone_parse_date(
                cells[header_map["end of hardware support date"]]
            )
            if not raw_models or not (end_sale or software_support or hardware_support):
                continue
            for product in hillstone_split_model_values(raw_models):
                model, product_name = hillstone_model_identity(product)
                key = (
                    normalize_alias_dedupe_key(model),
                    end_sale or "",
                    software_support or "",
                    hardware_support or "",
                )
                if key in seen:
                    continue
                seen.add(key)
                row: dict[str, Any] = {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": product_name,
                    "Description": f"Hillstone EOS product list row; source group: {raw_models}",
                    "Product Status": "EOS product list",
                    "_source_table": f"{path.name} Hillstone EOS product list table {table_index}",
                    "_source_hint": "Hillstone EOS product list import",
                    "_source_url": source_url,
                    "_review_policy": "hillstone_eos_sales_and_software_support_end",
                    "_aliases": [model, product_name, f"Hillstone {model}"],
                    "_prefer_model": True,
                }
                if end_sale:
                    row["End of Sale"] = end_sale
                if software_support:
                    row["End of Software Support"] = software_support
                    row["End of Security Updates"] = software_support
                elif hardware_support:
                    row["End of Support"] = hardware_support
                if hardware_support:
                    row["End of Hardware Support Date"] = hardware_support
                rows.append(row)
    return rows


NEOUSYS_EOL_PRODUCTS_URL = (
    "https://www.neousys-tech.com/en/product/end-of-life-products/"
    "eol-products-and-suggested-replacements"
)


def neousys_source_url(soup: BeautifulSoup) -> str:
    og_url = soup.find("meta", property="og:url")
    if og_url:
        url = normalize_text(og_url.get("content"))
        if url:
            return url
    base = soup.find("base")
    href = normalize_text(base.get("href") if base else "")
    return href or NEOUSYS_EOL_PRODUCTS_URL


def neousys_clean_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none", "null"}:
        return ""
    return text


def neousys_parse_date(value: Any) -> str | None:
    text = neousys_clean_value(value)
    if not text:
        return None
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    return first_parsed_date(text)


def extract_neousys_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_life_products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = neousys_source_url(soup)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator="\n")
        if len(matrix) < 2:
            continue
        header_pos = None
        header_map: dict[str, int] = {}
        for pos, row in enumerate(matrix[:4]):
            normalized = [normalize_header(cell) for cell in row]
            candidate = {header: idx for idx, header in enumerate(normalized)}
            if {"model", "suggested replacement", "eol date"}.issubset(candidate):
                header_pos = pos
                header_map = candidate
                break
        if header_pos is None:
            continue
        for raw_row in matrix[header_pos + 1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[header_pos]) - len(raw_row))
            model = neousys_clean_value(cells[header_map["model"]])
            eol_date = neousys_parse_date(cells[header_map["eol date"]])
            if not model or not eol_date:
                continue
            replacement = neousys_clean_value(cells[header_map["suggested replacement"]])
            key = (normalize_alias_dedupe_key(model), eol_date, replacement)
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Neousys {model}",
                "Description": "Neousys EOL products and suggested replacements row",
                "Product Status": "End of Life product table",
                "End of Life": eol_date,
                "_source_table": f"{path.name} Neousys EOL products table {table_index}",
                "_source_hint": "Neousys EOL products table import",
                "_source_url": source_url,
                "_review_policy": "neousys_eol_date_not_security_eol",
                "_review_reason": (
                    "Neousys lists this model on an End Of Life Products table "
                    "with an EOL date, but the source does not define that date "
                    "as a final support or security-update cutoff."
                ),
                "_force_lifecycle_review": True,
                "_aliases": [model, f"Neousys {model}"],
                "_prefer_model": True,
            }
            if replacement:
                row["Replacement Products"] = replacement
            rows.append(row)
    return rows


AXIOMTEK_NEWSLETTER_URL = "https://www.axiomtek.com/ePaperView.aspx?ItemId=4865&t=278"
AXIOMTEK_SUPPORT_POLICY_URL = (
    "https://us.axiomtek.com/Default.aspx?C=Support+and+Service&ItemId=183&MenuId=AboutUs"
)


def axiomtek_source_url(soup: BeautifulSoup) -> str:
    og_url = soup.find("meta", property="og:url")
    if og_url:
        url = normalize_text(og_url.get("content"))
        if url:
            return url
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    for link in soup.find_all("a", href=True):
        href = normalize_text(link.get("href"))
        if "ePaperView.aspx" not in href:
            continue
        if href.startswith("http"):
            return href
        if href.startswith("/"):
            return f"https://www.axiomtek.com{href}"
    return AXIOMTEK_NEWSLETTER_URL


def axiomtek_clean_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none", "null"}:
        return ""
    return text


def axiomtek_parse_date(value: Any) -> str | None:
    text = axiomtek_clean_value(value)
    if not text:
        return None
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    return first_parsed_date(text)


def extract_axiomtek_product_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "product_eol_notice_2022_07.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = axiomtek_source_url(soup)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator="\n")
        if len(matrix) < 2:
            continue
        header_pos = None
        header_map: dict[str, int] = {}
        for pos, row in enumerate(matrix[:4]):
            normalized = [normalize_header(cell) for cell in row]
            candidate = {header: idx for idx, header in enumerate(normalized)}
            if {"model name", "last order date", "eol date", "replacement"}.issubset(candidate):
                header_pos = pos
                header_map = candidate
                break
        if header_pos is None:
            continue
        for raw_row in matrix[header_pos + 1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[header_pos]) - len(raw_row))
            model = axiomtek_clean_value(cells[header_map["model name"]])
            last_order = axiomtek_parse_date(cells[header_map["last order date"]])
            eol_date = axiomtek_parse_date(cells[header_map["eol date"]])
            if not model or not (last_order or eol_date):
                continue
            replacement = axiomtek_clean_value(cells[header_map["replacement"]])
            key = (normalize_alias_dedupe_key(model), last_order or "", eol_date or "")
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Axiomtek {model}",
                "Description": "Axiomtek product EOL newsletter notice",
                "Product Status": "Product EOL notice with last-order and EOL dates",
                "_source_table": f"{path.name} product EOL notice table {table_index}",
                "_source_hint": "Axiomtek product EOL newsletter import",
                "_source_url": source_url,
                "_review_policy": "axiomtek_eol_not_final_security_support_end",
                "_review_reason": (
                    "Axiomtek lists last-order and EOL dates, but its support "
                    "policy says extended technical support and repairs can "
                    "continue after EOL while original replacement parts are "
                    "available; no exact security-update cutoff is published."
                ),
                "_force_lifecycle_review": True,
                "_aliases": [model, f"Axiomtek {model}"],
                "_prefer_model": True,
            }
            if last_order:
                row["End of Sale"] = last_order
            if eol_date:
                row["End of Life"] = eol_date
            if replacement:
                row["Replacement Products"] = replacement
            rows.append(row)
    return rows


BCM_EOL_NOTICES_URL = "https://www.bcmcom.com/bcm_eol_notices.html"
BCM_MODEL_TOKEN_RE = re.compile(
    r"\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)*(?:\s+[Ss]eries)?\b"
)
BCM_MODEL_EXCLUDE_KEYS = {
    "atx",
    "bcm",
    "bto",
    "come",
    "cpu",
    "eol",
    "h81",
    "hm86",
    "intel",
    "itx",
    "ncnr",
    "pcn",
    "pcn846571-00",
    "pdf",
    "po",
    "qm77",
    "qm87",
    "q87",
    "sandy bridge",
    "skylake",
}


def bcm_clean_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none", "null"}:
        return ""
    return text


def bcm_notice_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return BCM_EOL_NOTICES_URL


def bcm_notice_date(value: Any) -> str | None:
    text = bcm_clean_value(value)
    if not text:
        return None
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    return first_parsed_date(text)


def bcm_last_order_date(description: str) -> str | None:
    patterns = (
        r"(?:last[- ]time\s+(?:buy|by)\s+orders?|last time buy orders)"
        r".{0,80}?\bthrough\s+([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})",
        r"\borders\s+will\s+be\s+accepted\s+through\s+"
        r"([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})",
        r"\bcontinue\s+to\s+accept\s+orders\b.{0,80}?\bthrough\s+"
        r"([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})",
        r"\bNCNR\s+PO\s+no\s+later\s+than\s+"
        r"([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})",
    )
    for pattern in patterns:
        match = re.search(pattern, description, flags=re.I)
        if not match:
            continue
        parsed = parse_date_any(match.group(1))
        if parsed:
            return parsed
    return None


def bcm_affected_text(description: str) -> str:
    text = normalize_text(description)
    list_match = re.search(r"\bEOL Product List:\s*(.+)$", text, flags=re.I)
    if list_match:
        return list_match.group(1)
    for marker in (
        "Recommended replacement products",
        "replacement products to consider",
        "replacement products for",
        "replacement product",
        "For a replacement product",
        "BCM would like to recommend",
    ):
        idx = text.lower().find(marker.lower())
        if idx >= 0:
            text = text[:idx]
    return text


def bcm_model_tokens(description: str) -> list[str]:
    text = bcm_affected_text(description)
    text = re.sub(r"\([^)]*(?:pdf|uATX|mini-ITX|Micro-ATX|PDF)[^)]*\)", " ", text, flags=re.I)
    text = text.replace("/", " ")
    models: list[str] = []
    seen: set[str] = set()
    for match in BCM_MODEL_TOKEN_RE.finditer(text):
        token = bcm_clean_value(match.group(0).strip(".,:;"))
        if not token:
            continue
        key = normalize_alias_dedupe_key(token)
        if key in BCM_MODEL_EXCLUDE_KEYS or key.startswith("pcn"):
            continue
        if not (re.search(r"\d", token) or token.startswith(("ESM-", "EMX-", "OFT-"))):
            continue
        if key in seen:
            continue
        seen.add(key)
        models.append(token)
    return models


def extract_bcm_advanced_research_eol_notice_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "bcm_eol_notices.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = bcm_notice_source_url(soup)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator=" ")
        for raw_row in matrix:
            if len(raw_row) < 2:
                continue
            announcement = bcm_notice_date(raw_row[0])
            description = bcm_clean_value(raw_row[1])
            normalized_description = normalize_header(description)
            if not announcement or (
                "eol" not in normalized_description
                and "end of life" not in normalized_description
            ):
                continue
            models = bcm_model_tokens(description)
            if not models:
                continue
            end_sale = bcm_last_order_date(description)
            for model in models:
                key = (normalize_alias_dedupe_key(model), announcement)
                if key in seen:
                    continue
                seen.add(key)
                row: dict[str, Any] = {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": f"BCM Advanced Research {model}",
                    "Description": "BCM Advanced Research product EOL notice",
                    "Product Status": description,
                    "Announcement Date": announcement,
                    "_source_table": f"{path.name} EOL notice table {table_index}",
                    "_source_hint": "BCM Advanced Research EOL notice import",
                    "_source_url": source_url,
                    "_status_only_review": True,
                    "_review_policy": "bcm_eol_notice_not_security_eol",
                    "_review_reason": (
                        "BCM Advanced Research publishes product EOL notices "
                        "and, for some notices, last-time-buy dates, but the "
                        "page does not publish an exact support, vulnerability-"
                        "support, or security-update cutoff."
                    ),
                    "_aliases": [model, f"BCM {model}", f"BCM Advanced Research {model}"],
                    "_prefer_model": True,
                }
                if end_sale:
                    row["End of Sale"] = end_sale
                rows.append(row)
    return rows


MILESIGHT_EOL_PAGE_RE = re.compile(r"^product_end_of_life_announcement_.*\.html$")
MILESIGHT_KNOWN_TYPES = {
    "lorawan gateway",
    "router",
    "sensor",
    "x infinity sensing cameras",
}


def milesight_source_url(soup: BeautifulSoup) -> str:
    og_url = soup.find("meta", property="og:url")
    if og_url:
        url = normalize_text(og_url.get("content"))
        if url:
            return url
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return ""


def milesight_clean_value(value: Any) -> str:
    text = normalize_text(value).replace("®", "")
    text = re.sub(r"\s+", " ", text).strip()
    if normalize_header(text) in {"", "n a", "na", "none", "null"}:
        return ""
    return text


def milesight_parse_date(value: str) -> str | None:
    text = normalize_text(value)
    text = re.sub(r"\b(\d{1,2})\s+(st|nd|rd|th)\b", r"\1\2", text, flags=re.I)
    text = text.replace("ᵗʰ", "th")
    text = re.sub(r"\s+,", ",", text)
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    return first_parsed_date(text)


def milesight_announcement_date(soup: BeautifulSoup) -> str | None:
    text = soup.get_text(" ", strip=True)
    match = re.search(
        r"Xiamen,\s*China,\s*([^–-]+?)\s*[–-]\s*Milesight",
        text,
        flags=re.I,
    )
    if match:
        return milesight_parse_date(match.group(1))
    return None


def milesight_table_eol_date(table: Any) -> str | None:
    fragments: list[str] = []
    node = table
    for _ in range(12):
        node = node.find_previous(string=True)
        if node is None:
            break
        text = normalize_text(node)
        if not text:
            continue
        fragments.append(text)
        candidate = " ".join(reversed(fragments))
        if "End-of-Life Date" in candidate:
            parsed = milesight_parse_date(candidate)
            if parsed:
                return parsed
    return None


def milesight_replacement_value(value: str) -> str:
    text = milesight_clean_value(value)
    if normalize_header(text) in {"", "no recommended replacement", "no replacement"}:
        return ""
    return text


def extract_milesight_eol_announcement_rows(path: Path) -> list[dict[str, Any]]:
    if not MILESIGHT_EOL_PAGE_RE.match(path.name):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = milesight_source_url(soup)
    announcement = milesight_announcement_date(soup)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator=" ")
        if len(matrix) < 2:
            continue
        header = [normalize_header(cell) for cell in matrix[0]]
        if header[:3] != ["type", "eol model", "recommended replacement"]:
            continue
        eol_date = milesight_table_eol_date(table)
        current_type = ""
        current_replacement = ""
        for raw_row in matrix[1:]:
            cells = [milesight_clean_value(cell) for cell in raw_row if milesight_clean_value(cell)]
            if not cells:
                continue
            product_type = current_type
            model = ""
            replacement = current_replacement
            if len(cells) >= 3:
                product_type, model, replacement = cells[0], cells[1], cells[2]
            elif len(cells) == 2:
                if normalize_header(cells[0]) in MILESIGHT_KNOWN_TYPES:
                    product_type, model = cells[0], cells[1]
                else:
                    model, replacement = cells[0], cells[1]
            else:
                model = cells[0]
            if product_type:
                current_type = product_type
            replacement = milesight_replacement_value(replacement)
            if replacement:
                current_replacement = replacement
            elif len(cells) >= 3 or (
                len(cells) == 2 and normalize_header(cells[0]) not in MILESIGHT_KNOWN_TYPES
            ):
                current_replacement = ""
            model = milesight_clean_value(model)
            if not model or normalize_header(model) == "eol model":
                continue
            key = (normalize_alias_dedupe_key(model), eol_date or announcement or "")
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Milesight {model}",
                "Description": product_type or "Milesight product EOL announcement",
                "Product Status": (
                    "Product end-of-life announcement; affected product no "
                    "longer available for sale"
                ),
                "_source_table": f"{path.name} Milesight EOL table {table_index}",
                "_source_hint": "Milesight product EOL announcement import",
                "_source_url": source_url,
                "_review_policy": "milesight_eol_not_security_eol",
                "_review_reason": (
                    "Milesight announces product discontinuation and an "
                    "End-of-Life Date, but the checked source does not publish "
                    "an exact support, vulnerability-support, or security-update cutoff."
                ),
                "_force_lifecycle_review": True,
                "_aliases": [model, f"Milesight {model}"],
                "_prefer_model": True,
            }
            if announcement:
                row["Announcement Date"] = announcement
            if eol_date:
                row["End of Life"] = eol_date
                row["End of Sale"] = eol_date
            if replacement:
                row["Replacement Products"] = replacement
            rows.append(row)
    return rows


DIGITAL_LOGGERS_PRODUCTS_URL = "https://www.digital-loggers.com/dli.products.html"
DIGITAL_LOGGERS_SUPPORT_URL = "https://www.digital-loggers.com/dli.support.html"
DIGITAL_LOGGERS_INFO_LINK_WORDS = {
    "accessories",
    "complete online documentation",
    "demo",
    "detailed information",
    "faqs",
    "firmware",
    "firmware revision history",
    "github",
    "git hub",
    "hw",
    "manual",
    "overview",
    "quick-start guide",
    "quick start guide",
    "rma",
    "scripts",
    "software",
    "specs",
}


def digital_loggers_source_url(path: Path, soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    if path.name == "digital_loggers_support_superseded_discontinued.html":
        return DIGITAL_LOGGERS_SUPPORT_URL
    return DIGITAL_LOGGERS_PRODUCTS_URL


def digital_loggers_table_section(table: Any) -> str:
    for previous in table.find_all_previous(["h1", "h2", "h3", "strong"]):
        text = normalize_text(previous.get_text(" ", strip=True))
        if text and "superseded and discontinued products" not in text.lower():
            return text
    return ""


def digital_loggers_product_from_cell(cell: Any) -> tuple[str, str, list[str]]:
    pieces = []
    for raw_piece in cell.stripped_strings:
        piece = normalize_text(raw_piece)
        if not piece:
            continue
        if normalize_header(piece) in DIGITAL_LOGGERS_INFO_LINK_WORDS:
            continue
        if piece.startswith("http://") or piece.startswith("https://"):
            continue
        pieces.append(piece)
    if not pieces:
        return "", "", []

    product = normalize_text(" ".join(pieces))
    aliases = [product]
    model = product
    code_match = re.search(r"\(([^()]{2,40})\)\s*$", product)
    if code_match and normalize_header(code_match.group(1)) not in {"special order"}:
        code = normalize_text(code_match.group(1))
        product = normalize_text(product[: code_match.start()])
        model = code
        aliases.extend([product, code])
    elif re.fullmatch(r"[A-Z0-9][A-Z0-9 /-]{2,40}", product):
        model = product

    return model, product, aliases


def extract_digital_loggers_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "digital_loggers_products_superseded_discontinued.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = digital_loggers_source_url(path, soup)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        section = digital_loggers_table_section(table)
        in_discontinued = False
        for table_row in table.find_all("tr"):
            row_text = normalize_text(table_row.get_text(" ", strip=True))
            row_header = normalize_header(row_text)
            if "superseded and discontinued products" in row_header:
                in_discontinued = True
                continue
            if not in_discontinued:
                continue
            if (
                row_header.startswith("current products")
                or row_header.startswith("energy control")
                or row_header.startswith("communications recording")
            ):
                in_discontinued = False
                continue

            for cell in table_row.find_all(["td", "th"]):
                model, product, aliases = digital_loggers_product_from_cell(cell)
                if not model:
                    continue
                model_key = normalize_alias_dedupe_key(model)
                if not model_key or model_key in seen:
                    continue
                seen.add(model_key)
                row: dict[str, Any] = {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": product or model,
                    "Description": section or "Digital Loggers superseded/discontinued product",
                    "Product Status": "Superseded and Discontinued Products",
                    "_source_table": (
                        f"{path.name} superseded/discontinued table {table_index}"
                    ),
                    "_source_hint": "Digital Loggers superseded/discontinued product list import",
                    "_source_url": source_url,
                    "_status_only_review": True,
                    "_review_policy": "digital_loggers_discontinued_not_security_eol",
                    "_review_reason": (
                        "Digital Loggers lists this product under Superseded "
                        "and Discontinued Products, but the checked source does "
                        "not publish an exact support, vulnerability-support, "
                        "or security-update cutoff."
                    ),
                    "_aliases": aliases,
                    "_prefer_model": True,
                }
                rows.append(row)
    return rows


NETSKOPE_SDWAN_LIFECYCLE_URL = "https://www.netskope.com/sd-wan-lifecycle-announcements"


def netskope_sdwan_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return NETSKOPE_SDWAN_LIFECYCLE_URL


def netskope_sdwan_parse_date(value: Any) -> str:
    text = normalize_text(value)
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    month_year = re.fullmatch(r"([A-Za-z]{3,9}),\s*(\d{4})", text)
    if month_year:
        return parse_date_any(f"{month_year.group(1)} {month_year.group(2)}") or ""
    return ""


def extract_netskope_sdwan_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "netskope_sdwan_lifecycle_announcements.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = netskope_sdwan_source_url(soup)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator=" ")
        if len(matrix) < 2:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        header_map = {header: idx for idx, header in enumerate(headers)}
        if not {"product", "announcement date", "end of sale date"}.issubset(header_map):
            continue
        support_idx = None
        for header, idx in header_map.items():
            if "end of support" in header and "end of life" in header:
                support_idx = idx
                break
        if support_idx is None:
            continue
        for raw_row in matrix[1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[0]) - len(raw_row))
            model = normalize_text(cells[header_map["product"]])
            if not model or normalize_header(model) == "product":
                continue
            key = normalize_alias_dedupe_key(model)
            if not key or key in seen:
                continue
            seen.add(key)
            announcement = netskope_sdwan_parse_date(cells[header_map["announcement date"]])
            end_of_sale = netskope_sdwan_parse_date(cells[header_map["end of sale date"]])
            end_of_support = netskope_sdwan_parse_date(cells[support_idx])
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Netskope One SD-WAN {model}",
                "Description": "Netskope One SD-WAN hardware product",
                "Product Status": (
                    "Netskope One SD-WAN end-of-sale and end-of-support/"
                    "end-of-life announcement"
                ),
                "_source_table": f"{path.name} lifecycle announcements table {table_index}",
                "_source_hint": "Netskope One SD-WAN lifecycle announcements import",
                "_source_url": source_url,
                "_aliases": [model, f"Netskope {model}", f"Netskope One SD-WAN {model}"],
                "_prefer_model": True,
            }
            if announcement:
                row["Announcement Date"] = announcement
            if end_of_sale:
                row["End of Sale"] = end_of_sale
            if end_of_support:
                row["End of Support"] = end_of_support
                row["End of Life"] = end_of_support
            rows.append(row)
    return rows


PICA8_PRODUCT_BULLETIN_URL = "https://www.pica8.com/support/warranty-and-agreements/"


def pica8_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return PICA8_PRODUCT_BULLETIN_URL


def extract_pica8_product_bulletin_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "pica8_warranty_and_agreements_product_bulletin.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = pica8_source_url(soup)
    milestone_dates: dict[str, str] = {}
    product_rows: list[tuple[int, str, str]] = []

    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table, separator=" ")
        if len(matrix) < 2:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        header_set = set(headers)
        if {"milestone", "definition", "date"}.issubset(header_set):
            header_map = {header: idx for idx, header in enumerate(headers)}
            for raw_row in matrix[1:]:
                cells = list(raw_row) + [""] * max(0, len(headers) - len(raw_row))
                milestone = normalize_header(cells[header_map["milestone"]])
                parsed = parse_date_any(cells[header_map["date"]])
                if not parsed:
                    continue
                if milestone == "last day of order":
                    milestone_dates["end_of_sale"] = parsed
                elif milestone == "end of support":
                    milestone_dates["end_of_support"] = parsed
            continue
        if (
            "end of sale product part number" in header_set
            and "product description" in header_set
        ):
            header_map = {header: idx for idx, header in enumerate(headers)}
            part_idx = header_map["end of sale product part number"]
            desc_idx = header_map["product description"]
            for raw_row in matrix[1:]:
                cells = list(raw_row) + [""] * max(0, len(headers) - len(raw_row))
                part_number = normalize_text(cells[part_idx])
                description = normalize_text(cells[desc_idx])
                if not re.fullmatch(r"P-\d{3,5}", part_number):
                    continue
                product_rows.append((table_index, part_number, description))

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, part_number, description in product_rows:
        key = normalize_alias_dedupe_key(part_number)
        if not key or key in seen:
            continue
        seen.add(key)
        row: dict[str, Any] = {
            "Model": part_number,
            "Part Number": part_number,
            "Product Name": f"Pica8 {part_number}",
            "Description": description or "Pica8 network switch",
            "Product Status": (
                "Pica8 product bulletin: end-of-sale and end-of-support/"
                "end-of-life milestones"
            ),
            "_source_table": f"{path.name} product bulletin table {table_index}",
            "_source_hint": "Pica8 product bulletin support milestone import",
            "_source_url": source_url,
            "_aliases": [part_number, f"PICA8 {part_number}", f"Pica8 {part_number}"],
            "_prefer_model": True,
        }
        if milestone_dates.get("end_of_sale"):
            row["End of Sale"] = milestone_dates["end_of_sale"]
        if milestone_dates.get("end_of_support"):
            row["End of Support"] = milestone_dates["end_of_support"]
        rows.append(row)
    return rows


THREEONEDATA_DISCONTINUED_URL = "https://www.3onedata.com/notice/discontinued.html"


def threeonedata_model_from_notice_title(title: str) -> str:
    text = normalize_text(title)
    text = re.sub(r"\.pdf$", "", text, flags=re.I)
    text = re.sub(r"^EOL announcement for\s+", "", text, flags=re.I)
    if normalize_header(text) in {"usb converters"}:
        return ""
    if normalize_header(text).startswith("product end of life notice"):
        return ""
    if not re.search(r"\b[A-Z]{2,}\d|\bMODEL\d|\bIES\d|\bNP\d|\bGW\d|\bSW\d", text):
        return ""
    return text


def extract_threeonedata_discontinued_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "discontinued_products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix_with_rowspans(table, separator=" ")
        if len(matrix) < 2:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        if "series product" not in headers or "notes comments" not in headers or "date" not in headers:
            continue
        header_map = {header: idx for idx, header in enumerate(headers)}
        for raw_row in matrix[1:]:
            cells = list(raw_row) + [""] * max(0, len(headers) - len(raw_row))
            status_text = normalize_text(cells[header_map["notes comments"]])
            if normalize_header(status_text) != "no longer manufactured":
                continue
            title = normalize_text(cells[header_map["series product"]])
            model = threeonedata_model_from_notice_title(title)
            if not model:
                continue
            key = normalize_alias_dedupe_key(model)
            if not key or key in seen:
                continue
            seen.add(key)
            announcement = parse_date_any(cells[header_map["date"]])
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"3onedata {model}",
                "Description": "3onedata discontinued product listing",
                "Product Status": "No longer manufactured",
                "_source_table": f"{path.name} discontinued table {table_index}",
                "_source_hint": "3onedata discontinued products list review import",
                "_source_url": THREEONEDATA_DISCONTINUED_URL,
                "_status_only_review": True,
                "_review_policy": "threeonedata_no_longer_manufactured_not_security_eol",
                "_review_reason": (
                    "3onedata lists this product as no longer manufactured, "
                    "but the checked list does not itself prove that support, "
                    "firmware, or security updates have ended."
                ),
                "_aliases": [model, f"3onedata {model}"],
                "_prefer_model": True,
            }
            if announcement:
                row["Announcement Date"] = announcement
            rows.append(row)
    return rows


KRAMER_DISCONTINUED_URL = "https://k.kramerav.com/products/discontinued.asp"


def kramer_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return KRAMER_DISCONTINUED_URL


def kramer_product_status_note(soup: BeautifulSoup, model: str) -> str:
    model_key = normalize_header(model)
    for span in soup.find_all("span"):
        text = normalize_text(span.get_text(" "))
        normalized = normalize_header(text)
        if not text or model_key not in normalized:
            continue
        if (
            "has reached end of life status" in normalized
            or "device is end of life" in normalized
            or "is end of life and has been replaced" in normalized
        ):
            return text
    return ""


def kramer_replacement_products(soup: BeautifulSoup) -> str:
    replacements: list[str] = []
    seen: set[str] = set()
    for link in soup.select(".price-block a[href*='/product/']"):
        value = normalize_text(link.get_text(" "))
        key = normalize_alias_dedupe_key(value)
        if value and key and key not in seen:
            replacements.append(value)
            seen.add(key)
    return ", ".join(replacements)


def extract_kramer_product_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_") or path.suffix.lower() not in {".html", ".htm"}:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    heading = soup.select_one("h1.prodNameTitle") or soup.find("h1")
    model = normalize_text(heading.get_text(" ")) if heading else ""
    if not model:
        return []
    status_note = kramer_product_status_note(soup, model)
    if not status_note:
        return []

    subtitle = soup.find("p", class_="subTitle")
    description = normalize_text(subtitle.get_text(" ")) if subtitle else ""
    replacements = kramer_replacement_products(soup)
    source_url = kramer_source_url(soup)
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": f"Kramer {model}",
        "Description": description or "Kramer network/control product",
        "Product Status": status_note,
        "_source_table": f"{path.name} product page status note",
        "_source_hint": "Kramer product page end-of-life status import",
        "_source_url": source_url,
        "_status_only_review": True,
        "_review_policy": "kramer_product_eol_not_security_eol",
        "_review_reason": (
            "Kramer states this exact model is end of life and replacement-listed, "
            "but the product page does not publish an exact support, firmware, "
            "or security-update end date."
        ),
        "_aliases": [model, f"Kramer {model}"],
        "_prefer_model": True,
    }
    if replacements:
        row["Replacement Products"] = replacements
    return [row]


IEI_NETWORKING_EOL_URL = "https://www.ieiworld.com/en/product/eol_list.php?CA=2"


def iei_source_url(soup: BeautifulSoup) -> str:
    og_url = soup.find("meta", property="og:url")
    href = normalize_text(og_url.get("content") if og_url else "")
    return href or IEI_NETWORKING_EOL_URL


def extract_iei_networking_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "eol_list_ca_2_networking_and_servers.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = iei_source_url(soup)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, card in enumerate(soup.select(".card__content"), start=1):
        heading = card.find("h2")
        model = normalize_text(heading.get_text(" ")) if heading else ""
        if not model:
            continue
        status = normalize_text(card.select_one(".eol__tag").get_text(" ") if card.select_one(".eol__tag") else "")
        if normalize_header(status) != "end of life":
            continue
        key = normalize_alias_dedupe_key(model)
        if not key or key in seen:
            continue
        seen.add(key)
        description = normalize_text(
            card.select_one(".card__description").get_text(" ")
            if card.select_one(".card__description")
            else ""
        )
        if not description:
            image = card.select_one("img.card__img")
            description = normalize_text(image.get("alt") if image else "")
        rows.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": f"IEI {model}",
                "Description": description or "IEI networking/server product",
                "Product Status": "End of Life",
                "_source_table": f"{path.name} networking/server card {index}",
                "_source_hint": "IEI networking and servers EOL product card import",
                "_source_url": source_url,
                "_status_only_review": True,
                "_review_policy": "iei_eol_list_not_security_eol",
                "_review_reason": (
                    "IEI lists this exact product in the Networking and Servers "
                    "End-of-Life category, but the page does not publish exact "
                    "support, firmware, vulnerability-support, or security-update "
                    "end dates."
                ),
                "_aliases": [model, f"IEI {model}"],
                "_prefer_model": True,
            }
        )
    return rows


RUIJIE_PRODUCT_LIFECYCLE_URL = "https://www.ruijie.com/en-global/support/productLifecycle"


def ruijie_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return RUIJIE_PRODUCT_LIFECYCLE_URL


def ruijie_article_title(soup: BeautifulSoup) -> str:
    title = soup.find("h2", id="h_Title")
    if title:
        text = normalize_text(title.get_text(" ", strip=True))
        if text:
            return text
    if soup.title:
        return normalize_text(soup.title.get_text(" ", strip=True))
    return "Ruijie product lifecycle announcement"


def ruijie_article_date(soup: BeautifulSoup) -> str:
    content = soup.find(id="d_content") or soup
    for text in content.stripped_strings:
        normalized = normalize_text(text)
        match = re.search(
            r"\bDate\s*:\s*([A-Za-z]{3,9}\s+\d{1,2},\s*\d{4}|\d{4}-\d{1,2}-\d{1,2})",
            normalized,
            flags=re.I,
        )
        if match:
            parsed = parse_date_any(match.group(1))
            if parsed:
                return parsed
    return ""


def ruijie_model_key(value: str) -> str:
    key = normalize_header(value)
    key = re.sub(r"^rg\s+", "", key)
    return key


def ruijie_models_match(product_model: str, service_model: str) -> bool:
    product_key = ruijie_model_key(product_model)
    service_key = ruijie_model_key(service_model)
    if not product_key or not service_key:
        return False
    return product_key == service_key or product_key in service_key


def ruijie_clean_optional(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "na", "n a", "none", "nil", "not applicable"}:
        return ""
    return text


def ruijie_clean_model(value: Any) -> str:
    text = normalize_text(value)
    text = re.sub(r"\bRG-\s+", "RG-", text)
    text = re.sub(r"(?<=\d)\s+(?=[A-Z]-)", "", text)
    return text


def ruijie_split_models(value: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    text = normalize_multiline_text(value)
    text = re.sub(r"\bRG-\n+([A-Z0-9]+)\n+([A-Z]-)", r"RG-\1\2", text)
    for line in split_multiline_values(text):
        line = ruijie_clean_model(line)
        candidates = split_model_group(line) if re.search(r"\s+/\s*|/\s+", line) else [line]
        expanded: list[str] = []
        for candidate in candidates:
            expanded.extend(
                normalize_text(part)
                for part in re.split(r"\s*&\s*|\s*;\s*", candidate)
                if normalize_text(part)
            )
        for candidate in expanded or candidates:
            key = normalize_alias_dedupe_key(candidate)
            if key and key not in seen:
                result.append(candidate)
                seen.add(key)
    return result


def ruijie_set_date(dates: dict[str, str], label: str, value: Any) -> None:
    parsed = parse_date_any(ruijie_clean_optional(value))
    if not parsed:
        return
    header = normalize_header(label)
    if any(
        needle in header
        for needle in (
            "contract renewal",
            "new service attachment",
            "new life attachment",
            "official software release",
            "production",
        )
    ):
        return
    if "end of sale" in header:
        dates.setdefault("End of Sale", parsed)
    elif "software maintenance" in header:
        dates.setdefault("End of Support", parsed)
    elif header == "last date of support" or "all support" in header:
        dates.setdefault("End of Service", parsed)
    elif header in {"end of life date", "end of life eol date"}:
        dates.setdefault("End of Life", parsed)
        dates.setdefault("End of Support", parsed)


def ruijie_dates_from_row(headers: list[str], row: list[str]) -> dict[str, str]:
    dates: dict[str, str] = {}
    for idx, header in enumerate(headers):
        if idx >= len(row):
            continue
        ruijie_set_date(dates, header, row[idx])
    return dates


def ruijie_product_indexes(headers: list[str]) -> dict[str, int] | None:
    model_idx = None
    description_idx = None
    replacement_idx = None
    region_idx = None
    for idx, header in enumerate(headers):
        if model_idx is None and header in {
            "end of sale model",
            "eol product",
            "eos product",
        }:
            model_idx = idx
        elif description_idx is None and "product description" in header:
            description_idx = idx
        elif replacement_idx is None and header in {
            "replacement model",
            "replacement product",
        }:
            replacement_idx = idx
        elif region_idx is None and header in {"country or region", "region"}:
            region_idx = idx
    if model_idx is None:
        return None
    result = {"model": model_idx}
    if description_idx is not None:
        result["description"] = description_idx
    if replacement_idx is not None:
        result["replacement"] = replacement_idx
    if region_idx is not None:
        result["region"] = region_idx
    return result


def ruijie_product_infos_from_rows(
    table_index: int,
    rows: list[list[str]],
) -> list[dict[str, Any]]:
    if len(rows) < 2:
        return []
    headers = [normalize_header(cell) for cell in rows[0]]
    if any("date" in header or header == "last date of support" for header in headers):
        return []
    indexes = ruijie_product_indexes(headers)
    if not indexes:
        return []
    infos: list[dict[str, Any]] = []
    for row in rows[1:]:
        if len(row) <= indexes["model"]:
            continue
        for model in ruijie_split_models(row[indexes["model"]]):
            info = {
                "model": model,
                "description": "",
                "replacement": "",
                "region": "",
                "source_table": table_index,
            }
            if "description" in indexes and len(row) > indexes["description"]:
                info["description"] = ruijie_clean_optional(row[indexes["description"]])
            if "replacement" in indexes and len(row) > indexes["replacement"]:
                info["replacement"] = ruijie_clean_model(
                    ruijie_clean_optional(row[indexes["replacement"]])
                )
            if "region" in indexes and len(row) > indexes["region"]:
                info["region"] = ruijie_clean_optional(row[indexes["region"]])
            infos.append(info)
    return infos


def ruijie_milestone_entries_from_rows(
    table_index: int,
    rows: list[list[str]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if len(rows) < 2:
        return [], {}
    headers = [normalize_header(cell) for cell in rows[0]]
    header_set = set(headers)
    page_dates: dict[str, str] = {}
    entries: list[dict[str, Any]] = []

    if {"milestone", "definition", "date"}.issubset(header_set):
        header_map = {header: idx for idx, header in enumerate(headers)}
        for row in rows[1:]:
            if len(row) <= max(header_map["milestone"], header_map["date"]):
                continue
            ruijie_set_date(
                page_dates,
                row[header_map["milestone"]],
                row[header_map["date"]],
            )
        return entries, page_dates

    indexes = ruijie_product_indexes(headers)
    date_headers = [
        idx
        for idx, header in enumerate(headers)
        if "date" in header or header == "last date of support"
    ]
    if indexes and date_headers:
        for row in rows[1:]:
            if len(row) <= indexes["model"]:
                continue
            model = ruijie_clean_optional(row[indexes["model"]])
            dates = ruijie_dates_from_row(headers, row)
            if model and dates:
                entries.append(
                    {
                        "model": model,
                        "dates": dates,
                        "region": (
                            ruijie_clean_optional(row[indexes["region"]])
                            if "region" in indexes and len(row) > indexes["region"]
                            else ""
                        ),
                        "source_table": table_index,
                    }
                )
        return entries, page_dates

    if "product service plan" in headers[0] and len(rows[0]) > 1:
        models = [ruijie_clean_optional(model) for model in rows[0][1:]]
        per_model = [{"model": model, "dates": {}, "region": "", "source_table": table_index} for model in models]
        for row in rows[1:]:
            if not row:
                continue
            label = row[0]
            for idx, entry in enumerate(per_model, start=1):
                if idx >= len(row):
                    continue
                if normalize_header(label) in {"country or region", "region"}:
                    entry["region"] = ruijie_clean_optional(row[idx])
                    continue
                ruijie_set_date(entry["dates"], label, row[idx])
        entries.extend(
            entry
            for entry in per_model
            if entry["model"] and any(entry["dates"].values())
        )
    return entries, page_dates


def ruijie_match_milestone_entry(
    model: str,
    milestone_entries: list[dict[str, Any]],
) -> dict[str, Any] | None:
    for entry in milestone_entries:
        if ruijie_model_key(model) == ruijie_model_key(entry["model"]):
            return entry
    for entry in milestone_entries:
        if ruijie_models_match(model, entry["model"]):
            return entry
    if len(milestone_entries) == 1:
        return milestone_entries[0]
    return None


def ruijie_extra_aliases(model: str, matched_model: str = "") -> list[str]:
    aliases = [model, f"Ruijie {model}"]
    if matched_model and matched_model != model:
        aliases.append(matched_model)
        aliases.extend(ruijie_split_models(matched_model))
    if not model.upper().startswith("RG-") and re.match(r"^[A-Z]{2,}\d", model):
        aliases.append(f"RG-{model}")
    return aliases


def extract_ruijie_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() not in {".html", ".htm"}:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = ruijie_article_title(soup)
    if "end of sale" not in normalize_header(title) and "end of life" not in normalize_header(title):
        return []

    source_url = ruijie_source_url(soup)
    announcement = ruijie_article_date(soup)
    tables = [
        (table_index, html_table_matrix_with_rowspans(table, separator="\n"))
        for table_index, table in enumerate(soup.find_all("table"), start=1)
    ]
    product_infos: list[dict[str, Any]] = []
    milestone_entries: list[dict[str, Any]] = []
    page_dates: dict[str, str] = {}
    for table_index, rows in tables:
        product_infos.extend(ruijie_product_infos_from_rows(table_index, rows))
        entries, dates = ruijie_milestone_entries_from_rows(table_index, rows)
        milestone_entries.extend(entries)
        for key, value in dates.items():
            page_dates.setdefault(key, value)

    product_by_key: dict[str, dict[str, Any]] = {}
    for info in product_infos:
        key = normalize_alias_dedupe_key(info["model"])
        if key and key not in product_by_key:
            product_by_key[key] = info

    rows: list[dict[str, Any]] = []
    used_keys: set[str] = set()
    for info in product_by_key.values():
        matched = ruijie_match_milestone_entry(info["model"], milestone_entries)
        dates = dict(matched["dates"]) if matched else dict(page_dates)
        if not any(dates.values()):
            continue
        region = info["region"] or (matched.get("region") if matched else "")
        row: dict[str, Any] = {
            "Model": info["model"],
            "Part Number": info["model"],
            "Product Name": f"Ruijie {info['model']}",
            "Description": info["description"] or "Ruijie network product",
            "Product Status": title,
            "_source_table": f"{path.name} table {info['source_table']}",
            "_source_hint": "Ruijie product lifecycle announcement import",
            "_source_url": source_url,
            "_aliases": ruijie_extra_aliases(
                info["model"],
                matched["model"] if matched else "",
            ),
            "_prefer_model": True,
        }
        if region:
            row["Region"] = region
        if info["replacement"]:
            row["Replacement"] = info["replacement"]
        if announcement:
            row["Announcement Date"] = announcement
        row.update(dates)
        rows.append(row)
        used_keys.add(normalize_alias_dedupe_key(info["model"]))

    if product_by_key:
        return rows

    for entry in milestone_entries:
        for model in ruijie_split_models(entry["model"]):
            key = normalize_alias_dedupe_key(model)
            if not key or key in used_keys:
                continue
            row = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Ruijie {model}",
                "Description": "Ruijie network product",
                "Product Status": title,
                "_source_table": f"{path.name} table {entry['source_table']}",
                "_source_hint": "Ruijie product lifecycle announcement import",
                "_source_url": source_url,
                "_aliases": ruijie_extra_aliases(model, entry["model"]),
                "_prefer_model": True,
            }
            if entry.get("region"):
                row["Region"] = entry["region"]
            if announcement:
                row["Announcement Date"] = announcement
            row.update(entry["dates"])
            rows.append(row)
            used_keys.add(key)
    return rows


VOLKTEK_EOS_EOL_URL = "https://www.volktek.com/support_en_3.php"


def volktek_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
    if canonical:
        href = normalize_text(canonical.get("href"))
        if href:
            return href
    return VOLKTEK_EOS_EOL_URL


def volktek_clean_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "n a", "na", "none", "null"}:
        return ""
    return text


def volktek_previous_heading(table: Any) -> str:
    previous = table.find_previous(string=True)
    while previous is not None:
        text = normalize_text(previous)
        if text:
            return text
        previous = previous.find_previous(string=True)
    return ""


def extract_volktek_eos_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "support_eos_eol.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = volktek_source_url(soup)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        heading = volktek_previous_heading(table)
        normalized_heading = normalize_header(heading)
        if normalized_heading not in {"eos end of sale", "eol end of life"}:
            continue
        matrix = html_table_matrix(table, separator="\n")
        if len(matrix) < 2:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        header_map = {header: idx for idx, header in enumerate(headers)}
        if "model name" not in header_map or "substituted product" not in header_map:
            continue
        status_text = (
            f"{heading}; Volktek says listed products are no longer being "
            "sold or supported"
        )
        for raw_row in matrix[1:]:
            cells = list(raw_row) + [""] * max(0, len(matrix[0]) - len(raw_row))
            model = volktek_clean_value(cells[header_map["model name"]])
            if not model:
                continue
            replacement = volktek_clean_value(cells[header_map["substituted product"]])
            key = (normalize_alias_dedupe_key(model), normalized_heading, replacement)
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"Volktek {model}",
                "Description": "Volktek EOS/EOL product status table row",
                "Product Status": status_text,
                "_source_table": f"{path.name} {heading} table {table_index}",
                "_source_hint": "Volktek EOS/EOL status table import",
                "_source_url": source_url,
                "_status_only_review": True,
                "_review_policy": "volktek_eos_eol_status_without_dates",
                "_review_reason": (
                    "Volktek lists this model as no longer being sold or "
                    "supported, but the source does not publish an exact "
                    "support, vulnerability-support, or security-update end date."
                ),
                "_aliases": [model, f"Volktek {model}"],
                "_prefer_model": True,
            }
            if replacement:
                row["Replacement Products"] = replacement
            rows.append(row)
    return rows


NVT_PHYBRIDGE_EOL_URL = "https://www.nvtphybridge.com/eol/"


def nvt_phybridge_clean_value(value: Any) -> str:
    text = normalize_text(value).replace("\xa0", " ")
    if normalize_header(text) in {"", "n a", "na", "nan", "none", "null"}:
        return ""
    return normalize_text(text)


def nvt_phybridge_parse_date(value: Any) -> str | None:
    text = nvt_phybridge_clean_value(value)
    if not text:
        return None
    text = re.sub(r"\bEOL Notice\b", "", text, flags=re.I)
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    return first_parsed_date(text)


def nvt_phybridge_source_url(soup: BeautifulSoup) -> str:
    canonical = soup.find("link", rel="canonical")
    href = normalize_text(canonical.get("href") if canonical else "")
    return href or NVT_PHYBRIDGE_EOL_URL


def nvt_phybridge_milestones(matrix: list[list[str]]) -> dict[str, str]:
    if not matrix:
        return {}
    header = [normalize_header(cell) for cell in matrix[0]]
    if not {"milestone", "definition", "date"}.issubset(set(header)):
        return {}
    dates: dict[str, str] = {}
    for row in matrix[1:]:
        if len(row) < 3:
            continue
        label = normalize_header(row[0])
        parsed = nvt_phybridge_parse_date(row[2])
        if not parsed:
            continue
        if "end of sale" in label:
            dates.setdefault("End of Sale", parsed)
        elif "announcement" in label:
            dates.setdefault("Announcement Date", parsed)
        elif (
            "software hardware maintenance" in label
            or "software updates" in label
            or "software update" in label
            or "software fixes" in label
        ):
            dates.setdefault("End of Support", parsed)
            dates.setdefault("End of Security Updates", parsed)
        elif "last date of support" in label or "maintenance support" in label:
            dates.setdefault("End of Service", parsed)
        elif "maintenance agreement renewal" in label:
            dates.setdefault("Maintenance Agreement Renewal Date", parsed)
    return dates


def nvt_phybridge_affected_products(matrix: list[list[str]]) -> list[tuple[str, str]]:
    if len(matrix) < 2:
        return []
    header = [normalize_header(cell) for cell in matrix[0]]
    if not any("end of sale product part" in cell for cell in header):
        return []
    rows: list[tuple[str, str]] = []
    for row in matrix[1:]:
        if len(row) < 2:
            continue
        model = nvt_phybridge_clean_value(row[0])
        description = nvt_phybridge_clean_value(row[1])
        if not model or normalize_header(model) in {"end of sale product part numbers"}:
            continue
        rows.append((model, description))
    return rows


def nvt_phybridge_replacements(matrix: list[list[str]]) -> dict[str, str]:
    if len(matrix) < 2:
        return {}
    header = [normalize_header(cell) for cell in matrix[0]]
    if not any("end of life part number" in cell for cell in header):
        return {}
    result: dict[str, str] = {}
    for row in matrix[1:]:
        if len(row) < 2:
            continue
        model = nvt_phybridge_clean_value(row[0])
        replacement = nvt_phybridge_clean_value(row[1])
        if not model or not replacement:
            continue
        result[model] = replacement
    return result


def nvt_phybridge_analog_rows(
    matrix: list[list[str]],
    *,
    path: Path,
    table_index: int,
    source_url: str,
) -> list[dict[str, Any]]:
    if len(matrix) < 2:
        return []
    header_pos = None
    header_map: dict[str, int] = {}
    for pos, row in enumerate(matrix[:4]):
        normalized = [normalize_header(cell) for cell in row]
        candidate = {header: idx for idx, header in enumerate(normalized)}
        if {"product code", "product description", "final support date"}.issubset(candidate):
            header_pos = pos
            header_map = candidate
            break
    if header_pos is None:
        return []
    eol_idx = next(
        (
            idx
            for header, idx in header_map.items()
            if "date of eol" in header or "date of eol eos" in header
        ),
        None,
    )
    if eol_idx is None:
        return []
    replacement_idx = next(
        (idx for header, idx in header_map.items() if "replacement product" in header),
        None,
    )
    notes_idx = header_map.get("notes")
    rows: list[dict[str, Any]] = []
    for raw_row in matrix[header_pos + 1:]:
        cells = list(raw_row) + [""] * max(0, len(matrix[header_pos]) - len(raw_row))
        model = nvt_phybridge_clean_value(cells[header_map["product code"]])
        if not model or normalize_header(model) == "product code":
            continue
        product_description = nvt_phybridge_clean_value(cells[header_map["product description"]])
        end_life = nvt_phybridge_parse_date(cells[eol_idx])
        final_support = nvt_phybridge_parse_date(cells[header_map["final support date"]])
        if not (end_life or final_support):
            continue
        replacement = ""
        if isinstance(replacement_idx, int) and replacement_idx < len(cells):
            replacement = nvt_phybridge_clean_value(cells[replacement_idx])
        notes = ""
        if isinstance(notes_idx, int) and notes_idx < len(cells):
            notes = nvt_phybridge_clean_value(cells[notes_idx])
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"NVT Phybridge {model}",
            "Description": product_description or "NVT Phybridge analog EOL product",
            "Product Status": "Analog product EOL/EOS list",
            "_source_table": f"{path.name} NVT Phybridge analog table {table_index}",
            "_source_hint": "NVT Phybridge analog EOL/EOS table import",
            "_source_url": source_url,
            "_review_policy": "nvt_phybridge_final_support_date_security_end",
            "_aliases": [model, f"NVT Phybridge {model}"],
            "_prefer_model": True,
        }
        if end_life:
            row["End of Life"] = end_life
        if final_support:
            row["End of Support"] = final_support
            row["End of Security Updates"] = final_support
        if replacement:
            row["Replacement Products"] = replacement
        if notes:
            row["Notes"] = notes
        rows.append(row)
    return rows


def extract_nvt_phybridge_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_life_products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = nvt_phybridge_source_url(soup)
    matrices = [
        html_table_matrix(table, separator="\n")
        for table in soup.find_all("table")
    ]
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for index, matrix in enumerate(matrices, start=1):
        milestones = nvt_phybridge_milestones(matrix)
        if milestones:
            affected: list[tuple[str, str]] = []
            replacements: dict[str, str] = {}
            for follower in matrices[index:index + 3]:
                if not affected:
                    affected = nvt_phybridge_affected_products(follower)
                replacements.update(nvt_phybridge_replacements(follower))
            for model, product_description in affected:
                key = (
                    normalize_alias_dedupe_key(model),
                    milestones.get("End of Sale", ""),
                    milestones.get("End of Support", ""),
                    milestones.get("End of Service", ""),
                )
                if key in seen:
                    continue
                seen.add(key)
                row: dict[str, Any] = {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": f"NVT Phybridge {model}",
                    "Description": product_description or "NVT Phybridge EOL product",
                    "Product Status": "Product end-of-life notice",
                    "_source_table": f"{path.name} NVT Phybridge notice table {index}",
                    "_source_hint": "NVT Phybridge product EOL notice import",
                    "_source_url": source_url,
                    "_review_policy": "nvt_phybridge_software_updates_before_final_support",
                    "_aliases": [model, f"NVT Phybridge {model}"],
                    "_prefer_model": True,
                }
                row.update(milestones)
                replacement = nvt_phybridge_clean_value(replacements.get(model))
                if replacement:
                    row["Replacement Products"] = replacement
                rows.append(row)
            continue
        rows.extend(
            nvt_phybridge_analog_rows(
                matrix,
                path=path,
                table_index=index,
                source_url=source_url,
            )
        )
    return rows


LANTRONIX_DISCONTINUED_PRODUCTS_URL = (
    "https://www.lantronix.com/resources/discontinued-products/"
)
LANTRONIX_EOL_POLICY_URL = "https://www.lantronix.com/lantronix-eol-policy/"
LANTRONIX_DISCONTINUED_PRODUCT_FILES = {
    "nhedb__raw__discontinued-products.html",
    "nhedb__raw__discontinued-products-page-5.html",
}


def lantronix_source_url(href: str) -> str:
    href = normalize_text(href)
    if not href:
        return LANTRONIX_DISCONTINUED_PRODUCTS_URL
    if href.startswith(("http://", "https://")):
        return href
    if href.startswith("//"):
        return f"https:{href}"
    return f"https://www.lantronix.com/{href.lstrip('/')}"


def lantronix_clean_product_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {
        "",
        "n a",
        "na",
        "not available",
        "none",
        "view files",
    }:
        return ""
    if text in {"-", "--"}:
        return ""
    return text


def lantronix_product_description(sku: str, notice: str) -> str:
    sku_upper = sku.upper()
    if sku_upper.startswith("SGX"):
        kind = "IoT device gateway"
    elif sku_upper.startswith("NTC"):
        kind = "cellular gateway/router"
    elif sku_upper.startswith(("TN-CWDM", "TN-SFP")):
        kind = "network SFP transceiver"
    elif sku_upper.startswith("TN-EOT"):
        kind = "network extender or media-converter product"
    elif sku_upper.startswith("SRA-"):
        kind = "secure remote access appliance"
    else:
        kind = "network hardware"
    parts = [kind, "Lantronix / Transition Networks lifecycle table row"]
    if notice:
        parts.append(f"notice {notice}")
    return "; ".join(parts)


def extract_lantronix_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in LANTRONIX_DISCONTINUED_PRODUCT_FILES:
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix_with_rowspans(table)
        if not matrix:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        if "date of eol" not in headers or "sku" not in headers:
            continue
        header_map = {header: index for index, header in enumerate(headers) if header}
        required = {"date of eol", "name", "sku", "replacement part", "eol notice"}
        if not required.issubset(header_map):
            continue

        trs = [tr for tr in table.find_all("tr") if tr.find_all(["th", "td"])]
        for row_index, values in enumerate(matrix[1:], start=1):
            max_index = max(header_map.values())
            if len(values) <= max_index:
                continue
            sku = lantronix_clean_product_value(values[header_map["sku"]])
            if not sku or not re.search(r"[A-Za-z0-9]", sku):
                continue
            end_sale = parse_date_any(values[header_map["date of eol"]])
            if not end_sale:
                continue
            name = lantronix_clean_product_value(values[header_map["name"]]) or sku
            replacement = lantronix_clean_product_value(
                values[header_map["replacement part"]]
            )
            alternative = lantronix_clean_product_value(
                values[header_map.get("current alternatives", -1)]
                if "current alternatives" in header_map
                else ""
            )
            notice = lantronix_clean_product_value(values[header_map["eol notice"]])
            source_url = LANTRONIX_DISCONTINUED_PRODUCTS_URL
            if row_index < len(trs):
                cell_nodes = trs[row_index].find_all(["th", "td"])
                notice_index = header_map["eol notice"]
                if notice_index < len(cell_nodes):
                    link = cell_nodes[notice_index].find("a", href=True)
                    if link:
                        source_url = lantronix_source_url(link.get("href") or "")

            replacements = []
            for value in (replacement, alternative):
                if value and value not in replacements:
                    replacements.append(value)

            row: dict[str, Any] = {
                "Model": sku,
                "Part Number": sku,
                "Product Name": name,
                "Description": lantronix_product_description(sku, notice),
                "Lantronix Lifecycle Phase": "End of Sale",
                "End of Sale": end_sale,
                "_source_table": f"{path.name} date-of-eol table {table_index}",
                "_source_hint": "Lantronix product lifecycle date table import",
                "_source_url": source_url,
                "_replace_existing_raw_record": True,
                "_review_policy": "lantronix_eol_date_is_end_of_sale_not_security_eol",
                "_review_reason": (
                    "Lantronix policy defines End-of-Sale as the last date to "
                    "order and ship through channel partners; support, software "
                    "maintenance, and security updates are separate milestones."
                ),
                "_aliases": [name, sku],
                "_prefer_model": True,
                "Lifecycle Status Source": LANTRONIX_EOL_POLICY_URL,
            }
            if replacements:
                row["Replacement Products"] = "; ".join(replacements)
            if notice:
                row["Lifecycle Notice"] = notice
            rows.append(row)
    return rows


ARBOR_EOL_PRODUCTS_URL = "https://www.arbor-technology.com/en/product/end-of-life"


def arbor_clean_product_value(value: Any) -> str:
    text = normalize_text(value)
    if normalize_header(text) in {"", "na", "n a", "none", "not available", "no"}:
        return ""
    return text


def arbor_device_description(model: str) -> str:
    key = normalize_header(model)
    if key.startswith("lync"):
        return "Industrial panel PC"
    if key.startswith("aslan"):
        return "Industrial embedded computer"
    if key.startswith("scp"):
        return "Industrial computer"
    if key.startswith("fpc"):
        return "Industrial panel PC"
    if key.startswith("pbc"):
        return "Industrial embedded board computer"
    return "Industrial computing device"


def extract_arbor_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_life_products.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "html.parser")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "The EOL date corresponds to the last shipping date" not in page_text:
        return []
    template = soup.find("template", class_="b-product-list__group-data")
    if not template:
        return []
    fragment = BeautifulSoup(template.decode_contents(), "html.parser")
    rows: list[dict[str, Any]] = []
    for row_index, tr in enumerate(fragment.find_all("tr"), start=1):
        model_node = tr.select_one(".b-eol__data-title-txt")
        replacement_node = tr.select_one(".b-eol__data-alternativeProducts-txt")
        date_node = tr.select_one(".b-eol__data-date-txt")
        model = arbor_clean_product_value(
            model_node.get_text(" ", strip=True) if model_node else ""
        )
        replacement = arbor_clean_product_value(
            replacement_node.get_text(" ", strip=True) if replacement_node else ""
        )
        last_shipment = parse_date_any(
            date_node.get_text(" ", strip=True) if date_node else ""
        )
        if not model or not last_shipment:
            continue
        aliases = [model, f"ARBOR {model}"]
        if replacement:
            aliases.append(replacement)
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": model,
            "Description": arbor_device_description(model),
            "Product Status": "Last shipping date published by ARBOR",
            "End of Sale": last_shipment,
            "Last Sale": last_shipment,
            "Lifecycle Status Source": ARBOR_EOL_PRODUCTS_URL,
            "_source_table": f"{path.name} template row {row_index}",
            "_source_hint": "ARBOR Technology last-shipment product table import",
            "_source_url": ARBOR_EOL_PRODUCTS_URL,
            "_review_policy": "arbor_eol_date_is_last_shipping_date_not_security_eol",
            "_review_reason": (
                "ARBOR defines the published EOL date as the last shipping date; "
                "the source does not publish a support, vulnerability, firmware, "
                "or security-update end date."
            ),
            "_aliases": aliases,
            "_prefer_model": True,
        }
        if replacement:
            row["Replacement Products"] = replacement
        rows.append(row)
    return rows


EPIPHAN_PEARL2_SUPPORT_URL = (
    "https://www.epiphan.com/support/pearl-2-software-documentation/"
)


def extract_epiphan_pearl_status_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "epiphan_pearl_2_support_page.html":
        return []
    soup = BeautifulSoup(
        path.read_text(encoding="utf-8", errors="ignore"),
        "html.parser",
    )
    text = normalize_text(soup.get_text(" ", strip=True))
    if "Pearl has officially reached its end of life and is discontinued" not in text:
        return []
    if "firmware updates continue to be made available for the Pearl models" not in text:
        return []
    return [
        {
            "Model": "Pearl",
            "Part Number": "Pearl",
            "Product Name": "Epiphan Pearl",
            "Description": "Network video encoder",
            "Product Status": (
                "End of life and discontinued; firmware updates continue"
            ),
            "Lifecycle Status Source": EPIPHAN_PEARL2_SUPPORT_URL,
            "_source_table": path.name,
            "_source_hint": "Epiphan Pearl support status notice import",
            "_source_url": EPIPHAN_PEARL2_SUPPORT_URL,
            "_status_only_review": True,
            "_review_policy": "epiphan_pearl_eol_firmware_updates_continue",
            "_review_reason": (
                "Epiphan says Pearl has reached end of life and is discontinued, "
                "but the same source says firmware updates continue for Pearl "
                "models; no support or security-update end date is published."
            ),
            "_aliases": ["Pearl", "Epiphan Pearl", "Pearl models"],
            "_prefer_model": True,
        }
    ]


NETAPP_VERSION_SUPPORT_URL = "https://mysupport.netapp.com/site/info/version-support"
NETAPP_SUPPORT_POLICIES_URL = (
    "https://mysupport.netapp.com/site/info/policies-and-offerings"
)


def netapp_parse_date(value: Any) -> str | None:
    text = normalize_text(value)
    if not text:
        return None
    text = text.replace("*", "")
    text = re.sub(r"\([^)]*\)", "", text)
    text = re.sub(r"\s*-\s*", "-", text)
    text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
    parsed = parse_date_any(text)
    if parsed:
        return parsed
    return first_parsed_date(text)


def netapp_empty_lifecycle_value(value: Any) -> bool:
    return normalize_header(value) in {
        "",
        "n a",
        "na",
        "none",
        "not applicable",
        "tbd",
        "to be determined",
    }


def netapp_clean_product(value: Any) -> str:
    text = normalize_text(value)
    if not text or len(text) > 180:
        return ""
    if len(re.findall(r"\d{1,2}[-\s][A-Za-z]{3,9}[-\s]\d{2,4}", text)) >= 2:
        return ""
    if normalize_header(text).startswith("note tbd"):
        return ""
    return text


def netapp_version_value(value: Any) -> str:
    text = normalize_text(value)
    if netapp_empty_lifecycle_value(text):
        return ""
    return text


def netapp_product_description(product: str, source_table: str = "") -> str:
    key = normalize_header(f"{product} {source_table}")
    if "workflow" in key or "pack" in key:
        return "Automation workflow pack software"
    if any(token in key for token in ("ontap", "santricity", "element", "storagegrid")):
        return "Operating system software"
    if any(
        token in key
        for token in (
            "unified manager",
            "deploy",
            "manager",
            "oncommand",
            "active iq",
            "monitoring",
            "api",
            "sdk",
        )
    ):
        return "Management software"
    return "NetApp software version"


def netapp_aliases(product: str, version: str, pack: str = "") -> list[str]:
    aliases = [product]
    if version:
        aliases.append(f"{product} {version}")
    if pack:
        aliases.extend([pack, f"{pack} {version}".strip()])
    formerly = re.search(r"\(formerly\s+([^)]+)\)", product, flags=re.I)
    if formerly:
        aliases.append(formerly.group(1))
        if version:
            aliases.append(f"{formerly.group(1)} {version}")
    without_parenthetical = normalize_text(re.sub(r"\([^)]*\)", "", product))
    if without_parenthetical and without_parenthetical != product:
        aliases.append(without_parenthetical)
        if version:
            aliases.append(f"{without_parenthetical} {version}")
    return aliases


def netapp_table_rows(table: Any, table_index: int, source_name: str) -> list[dict[str, Any]]:
    matrix = html_table_matrix(table)
    if not matrix:
        return []
    headers = [normalize_text(cell) for cell in matrix[0]]
    normalized_headers = [normalize_header(cell) for cell in headers]
    if "product" not in normalized_headers:
        return []
    if not any(
        header in normalized_headers
        for header in (
            "end of full support",
            "end of limited support",
            "end of engineering support",
            "end of version support",
        )
    ):
        return []

    rows: list[dict[str, Any]] = []
    current_product = ""
    current_pack = ""
    for raw_index, raw_row in enumerate(matrix[1:], start=2):
        row = [normalize_text(cell) for cell in raw_row]
        if not any(row):
            continue
        if len(row) == 1:
            product = netapp_clean_product(row[0])
            if product:
                current_product = product
                current_pack = ""
            continue
        if "packs" in normalized_headers and len(row) == len(headers) - 2:
            if current_product and current_pack:
                row = [current_product, current_pack] + row
            else:
                continue
        if len(row) == len(headers) - 1 and current_product:
            row = [current_product] + row
        if len(row) < len(headers):
            row = row + [""] * (len(headers) - len(row))
        if len(row) > len(headers):
            row = row[: len(headers)]

        data = dict(zip(normalized_headers, row))
        product = netapp_clean_product(data.get("product"))
        if not product:
            continue
        if product != current_product and not netapp_parse_date(product):
            current_product = product
            current_pack = ""
        if "packs" in data and netapp_clean_product(data.get("packs")):
            current_pack = netapp_clean_product(data.get("packs"))

        version = netapp_version_value(data.get("version"))
        pack = netapp_clean_product(data.get("packs"))
        model = product
        if normalize_header(product) == "automation store packs" and pack:
            model = pack
        part_number = f"{model} {version}".strip() if version else model

        full_support = netapp_parse_date(data.get("end of full support"))
        engineering_support = netapp_parse_date(data.get("end of engineering support"))
        patch_fix = netapp_parse_date(data.get("end of patch fix updates"))
        limited_support = netapp_parse_date(data.get("end of limited support"))
        version_support = netapp_parse_date(data.get("end of version support"))
        self_service = netapp_parse_date(data.get("end of self service support"))
        update_end = patch_fix or full_support or engineering_support
        support_end = limited_support or version_support
        if not update_end and not support_end and not self_service:
            continue

        status_parts = []
        if update_end:
            status_parts.append(f"software/service updates end {update_end}")
        if support_end:
            status_parts.append(f"version support ends {support_end}")
        if self_service:
            status_parts.append(f"self-service support ends {self_service}")

        row_data: dict[str, Any] = {
            "Model": model,
            "Part Number": part_number,
            "Product Name": part_number,
            "Description": netapp_product_description(product, f"table {table_index}"),
            "Product Status": "; ".join(status_parts),
            "Lifecycle Status Source": NETAPP_VERSION_SUPPORT_URL,
            "_source_table": f"{source_name} table {table_index} row {raw_index}",
            "_source_hint": "NetApp software version support table import",
            "_source_url": NETAPP_VERSION_SUPPORT_URL,
            "_review_policy": "netapp_full_support_end_is_service_update_end",
            "_review_reason": (
                "NetApp defines Full Support as including Service Updates and "
                "security vulnerability evaluation; Limited Support continues "
                "technical support but does not provide Service Updates, "
                "including software updates."
            ),
            "_aliases": netapp_aliases(product, version, pack or current_pack),
            "_prefer_model": True,
        }
        if version:
            row_data["Version"] = version
        if pack or current_pack:
            row_data["Pack"] = pack or current_pack
        if update_end:
            row_data["End of Security Updates"] = update_end
            row_data["_end_of_security_updates_override"] = update_end
        if support_end:
            row_data["End of Support"] = support_end
        if self_service:
            row_data["End of Service"] = self_service
        rows.append(row_data)
    return rows


def extract_netapp_software_version_support_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "software_version_support.json":
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    html = payload.get("localizedContent")
    if not isinstance(html, str) or not html.strip():
        return []

    soup = BeautifulSoup(html, "html.parser")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    required = (
        "Full Support",
        "Service Updates",
        "not provided for versions under limited support",
        "End of Version Support",
    )
    if not all(term in page_text for term in required):
        return []

    rows: list[dict[str, Any]] = []
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        rows.extend(netapp_table_rows(table, table_index, path.name))
    return rows


TELRAD_BREEZEVIEW_CENTOS7_URL = (
    "https://telrad.com/important-update-breezeview-os-update-required-centos-7-end-of-life/"
)
TELRAD_CPE8100_URL = "https://telrad.com/products/cpe8100-outdoor/"


def extract_telrad_breezeview_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "telrad_breezeview_centos7_end_of_life.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "BreezeVIEW" not in text and "Breezeview" not in text:
        return []
    if "CentOS 7" not in text or "no longer receives security updates" not in text:
        return []
    match = re.search(
        r"End of Life as of\s+([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    security_end = parse_date_any(match.group(1)) if match else None
    if not security_end:
        return []
    return [
        {
            "Model": "BreezeVIEW CentOS 7",
            "Part Number": "BreezeVIEW CentOS 7",
            "Product Name": "BreezeVIEW on CentOS 7",
            "Description": "Network management software",
            "Product Status": (
                "CentOS 7 reached End of Life; no longer receives security "
                "updates; no further BreezeVIEW versions for CentOS"
            ),
            "End of Support": security_end,
            "End of Security Updates": security_end,
            "Lifecycle Status Source": TELRAD_BREEZEVIEW_CENTOS7_URL,
            "_source_table": path.name,
            "_source_hint": "Telrad BreezeVIEW CentOS 7 end-of-life notice import",
            "_source_url": TELRAD_BREEZEVIEW_CENTOS7_URL,
            "_review_policy": "telrad_breezeview_centos7_security_updates_ended",
            "_aliases": ["BreezeVIEW", "BreezeView", "CentOS 7"],
            "_prefer_model": True,
        }
    ]


def ivanti_release_product_context(table: Any) -> tuple[str, str]:
    headings: list[str] = []
    node = table
    while True:
        node = node.find_previous(["h1", "h2"])
        if node is None:
            break
        text = normalize_text(node.get_text(" ", strip=True)).strip(":")
        if text and text not in headings:
            headings.append(text)
        if len(headings) >= 3:
            break
    joined = " ".join(reversed(headings))
    key = normalize_header(joined)
    if "mobile ivanti secure access client" in key:
        return "Ivanti Secure Access Client Mobile", "Mobile VPN client software"
    if "desktop ivanti secure access client" in key:
        return "Ivanti Secure Access Client Desktop", "Endpoint VPN client software"
    if "zero trust access" in key:
        return "Ivanti Neurons for Zero Trust Access", "Zero Trust Access gateway software"
    if "policy secure" in key:
        return "Ivanti Policy Secure", "Network access control gateway software"
    if "connect secure" in key:
        return "Ivanti Connect Secure", "VPN gateway software"
    return "", ""


def ivanti_release_table_rows(table: Any) -> list[list[str]]:
    rows: list[list[str]] = []
    for tr in table.find_all("tr"):
        cells = [normalize_text(cell.get_text(" ", strip=True)) for cell in tr.find_all(["th", "td"])]
        cells = [cell for cell in cells if cell]
        if cells:
            rows.append(cells)
    return rows


def extract_ivanti_pulse_release_matrix_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "granular_software_release_eol_matrix.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Granular Software Release EOL Timelines and Support Matrix" not in page_text:
        return []

    rows: list[dict[str, Any]] = []
    pending_header: list[str] | None = None
    seen: set[tuple[str, str, str]] = set()
    for table in soup.find_all("table"):
        table_rows = ivanti_release_table_rows(table)
        if not table_rows:
            continue
        first = [normalize_header(cell) for cell in table_rows[0]]
        first_joined = " ".join(first)
        if (
            ("release" in first_joined)
            and "launch date" in first_joined
            and "end of support" in first_joined.replace("end ofsupport", "end of support")
        ):
            pending_header = table_rows[0]
            data_rows = table_rows[1:]
        elif pending_header and len(table_rows[0]) >= 3:
            data_rows = table_rows
        else:
            continue

        product, description = ivanti_release_product_context(table)
        if not product:
            continue
        header = [normalize_header(cell).replace("end ofsupport", "end of support") for cell in pending_header]
        try:
            release_idx = next(i for i, cell in enumerate(header) if "release" in cell)
            launch_idx = next(i for i, cell in enumerate(header) if "launch date" in cell)
            support_idx = next(i for i, cell in enumerate(header) if "end of support" in cell)
        except StopIteration:
            continue
        engineering_idx = next(
            (i for i, cell in enumerate(header) if "end of engineering" in cell),
            None,
        )
        for data_row in data_rows:
            if len(data_row) <= max(release_idx, launch_idx, support_idx):
                continue
            release = normalize_text(data_row[release_idx]).replace("\xa0", " ")
            release = re.sub(r"\s*\((?:LTS\s+Release|LTS)\)\s*", " LTS", release, flags=re.I)
            launch = parse_date_any(data_row[launch_idx])
            support_end = parse_date_any(data_row[support_idx])
            engineering_end = (
                parse_date_any(data_row[engineering_idx])
                if engineering_idx is not None and len(data_row) > engineering_idx
                else None
            )
            if not release or not support_end:
                continue
            if not re.match(r"^\d{1,2}(?:\.\d+)*(?:R\d+)?(?:\.x|x)?(?:\s+LTS)?$", release, flags=re.I):
                continue
            model = f"{product} {release}"
            key = (product, normalize_alias_dedupe_key(release), support_end)
            if key in seen:
                continue
            seen.add(key)
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": model,
                "Description": description,
                "Product Status": (
                    f"Ivanti granular software release EOL matrix; launch date "
                    f"{launch or 'not stated'}; end of support {support_end}"
                ),
                "End of Support": support_end,
                "Lifecycle Status Source": path.name,
                "_source_table": f"{path.name} {product} release matrix",
                "_source_hint": "Ivanti granular software release EOL matrix HTML import",
                "_review_policy": "ivanti_release_end_of_support_matrix",
                "_aliases": [product, release, model],
                "_prefer_model": True,
            }
            if launch:
                row["Launch Date"] = launch
            if engineering_end:
                row["Vendor End of Engineering"] = engineering_end
            rows.append(row)
    return rows


def extract_vendor_html_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []
    if vendor_slug in {"arista", "h3c"}:
        extracted.extend(extract_split_milestone_rows(path, vendor_slug))
    if vendor_slug == "2n":
        extracted.extend(extract_2n_discontinued_rows(path))
    elif vendor_slug == "3onedata":
        extracted.extend(extract_threeonedata_discontinued_rows(path))
    if vendor_slug == "adlink":
        extracted.extend(extract_adlink_product_eol_rows(path))
    elif vendor_slug == "amcrest":
        extracted.extend(extract_amcrest_discontinued_firmware_rows(path))
    elif vendor_slug == "aaeon_network_appliances":
        extracted.extend(extract_aaeon_network_appliance_phaseout_rows(path))
    elif vendor_slug == "acrosser":
        extracted.extend(extract_acrosser_eol_product_rows(path))
    elif vendor_slug == "antaira":
        extracted.extend(extract_antaira_phaseout_rows(path))
    elif vendor_slug == "aiphone":
        extracted.extend(extract_aiphone_discontinued_product_rows(path))
    elif vendor_slug == "arbor_technology":
        extracted.extend(extract_arbor_eol_product_rows(path))
    elif vendor_slug == "aten":
        extracted.extend(extract_aten_japan_discontinued_rows(path))
    elif vendor_slug == "axiomtek":
        extracted.extend(extract_axiomtek_product_eol_rows(path))
    elif vendor_slug == "axis":
        extracted.extend(extract_axis_product_support_rows(path))
    elif vendor_slug == "asustor_nas":
        extracted.extend(extract_asustor_support_status_rows(path))
    elif vendor_slug == "auerswald":
        extracted.extend(extract_auerswald_lifecycle_rows(path))
    elif vendor_slug == "arris_commscope_cpe":
        extracted.extend(extract_arris_discontinued_rows(path))
    elif vendor_slug == "baicells":
        extracted.extend(extract_baicells_nova233_eol_rows(path))
    elif vendor_slug == "balluff":
        extracted.extend(extract_balluff_product_lifecycle_rows(path))
    elif vendor_slug == "birddog":
        extracted.extend(extract_birddog_previous_lines_rows(path))
    elif vendor_slug == "bcm_advanced_research":
        extracted.extend(extract_bcm_advanced_research_eol_notice_rows(path))
    elif vendor_slug == "beckhoff":
        extracted.extend(extract_beckhoff_service_product_rows(path))
    elif vendor_slug == "clavister":
        extracted.extend(extract_clavister_end_of_sales_rows(path))
    elif vendor_slug == "crestron":
        extracted.extend(extract_crestron_discontinued_product_rows(path))
    elif vendor_slug == "ctsystem":
        extracted.extend(extract_ctsystem_fos_ies_eol_rows(path))
    elif vendor_slug == "cincoze":
        extracted.extend(extract_cincoze_eol_rows(path))
    elif vendor_slug == "comnet":
        extracted.extend(extract_comnet_discontinued_product_rows(path))
    elif vendor_slug in {"atlona", "congatec", "portwell", "poynting"}:
        extracted.extend(extract_status_marked_product_page_rows(path, vendor_slug))
    elif vendor_slug == "digital_loggers":
        extracted.extend(extract_digital_loggers_discontinued_rows(path))
    elif vendor_slug == "dfi":
        extracted.extend(extract_dfi_product_status_rows(path))
    elif vendor_slug == "epiphan_video":
        extracted.extend(extract_epiphan_pearl_status_rows(path))
    elif vendor_slug == "ezurio":
        extracted.extend(extract_ezurio_part_eol_rows(path))
    elif vendor_slug == "broadcom_bluecoat":
        extracted.extend(extract_broadcom_bluecoat_packetshaper_rows(path))
    elif vendor_slug == "buffalo_nas":
        extracted.extend(extract_buffalo_nas_eol_rows(path))
    elif vendor_slug == "fiberhome":
        extracted.extend(extract_fiberhome_milestone_rows(path))
    elif vendor_slug == "fluke_networks":
        extracted.extend(extract_fluke_networks_dtx_eol_rows(path))
    elif vendor_slug == "exfo":
        extracted.extend(extract_exfo_discontinued_product_rows(path))
    elif vendor_slug == "hanwha":
        extracted.extend(extract_hanwha_discontinued_product_rows(path))
    elif vendor_slug == "hms_ewon":
        extracted.extend(extract_hms_ewon_eol_rows(path))
        extracted.extend(extract_hms_ewon_firmware_replacement_rows(path))
    elif vendor_slug == "icp_das":
        extracted.extend(extract_icp_das_lifecycle_rows(path))
    elif vendor_slug == "idis":
        extracted.extend(extract_idis_discontinued_product_rows(path))
    elif vendor_slug == "iei":
        extracted.extend(extract_iei_networking_eol_rows(path))
    elif vendor_slug == "inhand_networks":
        extracted.extend(extract_inhand_networks_eol_rows(path))
    elif vendor_slug == "insys_icom":
        extracted.extend(extract_insys_icom_discontinued_rows(path))
    elif vendor_slug == "ipro_panasonic":
        extracted.extend(extract_ipro_panasonic_discontinued_firmware_rows(path))
    elif vendor_slug == "ivanti_pulse_secure":
        extracted.extend(extract_ivanti_pulse_release_matrix_rows(path))
    elif vendor_slug == "ip_com":
        extracted.extend(extract_ip_com_eol_product_rows(path))
    elif vendor_slug == "kontron":
        extracted.extend(extract_kontron_product_eol_rows(path))
    elif vendor_slug == "kramer_av":
        extracted.extend(extract_kramer_product_eol_rows(path))
    elif vendor_slug == "kyocera_printers":
        extracted.extend(extract_kyocera_taskalfa_sales_end_rows(path))
    elif vendor_slug == "lantronix_transition":
        extracted.extend(extract_lantronix_discontinued_product_rows(path))
    elif vendor_slug == "lenovo_networking":
        extracted.extend(extract_lenovo_networking_withdrawn_product_rows(path))
    elif vendor_slug == "lexmark_printers":
        extracted.extend(extract_lexmark_product_eosl_rows(path))
    elif vendor_slug == "oring":
        extracted.extend(extract_oring_phase_out_rows(path))
    elif vendor_slug == "patton":
        extracted.extend(extract_patton_sunset_rows(path))
    elif vendor_slug == "phoenix_contact":
        extracted.extend(extract_phoenix_contact_sfn_rows(path))
    elif vendor_slug == "pica8":
        extracted.extend(extract_pica8_product_bulletin_rows(path))
    elif vendor_slug == "cradlepoint_ericsson":
        extracted.extend(extract_cradlepoint_ibr1700_eol_rows(path))
    elif vendor_slug == "acti":
        extracted.extend(extract_acti_discontinued_rows(path))
    elif vendor_slug == "perle":
        extracted.extend(extract_perle_discontinuation_rows(path))
    elif vendor_slug == "reolink":
        extracted.extend(extract_reolink_discontinuation_rows(path))
    elif vendor_slug == "vivotek":
        extracted.extend(extract_vivotek_status_rows(path))
    elif vendor_slug == "glinet":
        extracted.extend(extract_glinet_eol_rows(path))
    elif vendor_slug == "grandstream":
        extracted.extend(extract_grandstream_status_rows(path))
    elif vendor_slug == "yealink":
        extracted.extend(extract_yealink_lifecycle_rows(path))
    elif vendor_slug == "supermicro_networking":
        extracted.extend(extract_supermicro_status_rows(path))
    elif vendor_slug == "adtran":
        extracted.extend(extract_adtran_discontinued_page(path))
        extracted.extend(extract_adtran_aos_support_rows(path))
    elif vendor_slug == "akuvox":
        extracted.extend(extract_akuvox_security_update_rows(path))
    elif vendor_slug == "moxa":
        extracted.extend(extract_moxa_eol_product_page(path))
    elif vendor_slug == "milesight":
        extracted.extend(extract_milesight_eol_announcement_rows(path))
    elif vendor_slug == "mitel":
        extracted.extend(extract_mitel_lifecycle_rows(path))
    elif vendor_slug == "multitech":
        extracted.extend(extract_multitech_eol_product_rows(path))
    elif vendor_slug == "netally":
        extracted.extend(extract_netally_legacy_product_rows(path))
    elif vendor_slug == "netberg":
        extracted.extend(extract_netberg_lifecycle_rows(path))
    elif vendor_slug == "netgate":
        extracted.extend(extract_netgate_product_lifecycle_rows(path))
    elif vendor_slug == "netmodule":
        extracted.extend(extract_netmodule_eol_rows(path))
    elif vendor_slug == "netskope_sdwan":
        extracted.extend(extract_netskope_sdwan_lifecycle_rows(path))
    elif vendor_slug == "matrox_video":
        extracted.extend(extract_matrox_video_eol_rows(path))
    elif vendor_slug == "nexcom_aiot_mart":
        extracted.extend(extract_nexcom_aiot_mart_eol_product_rows(path))
    elif vendor_slug == "neousys":
        extracted.extend(extract_neousys_eol_product_rows(path))
    elif vendor_slug == "volktek":
        extracted.extend(extract_volktek_eos_eol_rows(path))
    elif vendor_slug == "imperva":
        extracted.extend(extract_imperva_hardware_schedule_rows(path))
    elif vendor_slug == "softing_industrial":
        extracted.extend(extract_softing_discontinued_rows(path))
    elif vendor_slug == "red_lion_ntron":
        extracted.extend(extract_red_lion_ntron_eol_rows(path))
    elif vendor_slug == "robustel":
        extracted.extend(extract_robustel_eol_policy_rows(path))
    elif vendor_slug == "ricoh_printers":
        extracted.extend(extract_ricoh_discontinued_printer_rows(path))
    elif vendor_slug == "ruijie_networks":
        extracted.extend(extract_ruijie_lifecycle_rows(path))
    elif vendor_slug == "qnap":
        extracted.extend(extract_qnap_product_status_api_rows(path))
        extracted.extend(extract_qnap_os_lifecycle_rows(path))
        extracted.extend(extract_qnap_support_status_rows(path))
    elif vendor_slug == "seagate_lacie_nas":
        extracted.extend(extract_seagate_lacie_nas_os4_rows(path))
    elif vendor_slug == "versa":
        extracted.extend(extract_versa_eol_rows(path))
    elif vendor_slug == "wd_my_cloud":
        extracted.extend(extract_wd_my_cloud_rows(path))
    elif vendor_slug == "screenbeam_actiontec":
        extracted.extend(extract_screenbeam_eol_rows(path))
    elif vendor_slug == "sangoma":
        extracted.extend(extract_sangoma_eol_rows(path))
    elif vendor_slug == "digi":
        extracted.extend(extract_digi_eol_model_rows(path))
    elif vendor_slug == "edgecore":
        extracted.extend(extract_edgecore_eol_rows(path))
    elif vendor_slug == "etherwan":
        extracted.extend(extract_etherwan_eol_notice_rows(path))
    elif vendor_slug == "fanvil":
        extracted.extend(extract_fanvil_eol_rows(path))
    elif vendor_slug == "sophos":
        extracted.extend(extract_sophos_product_lifecycle_rows(path))
    elif vendor_slug == "teradek":
        extracted.extend(extract_teradek_cube_serv_pro_eol_rows(path))
    elif vendor_slug == "telrad_networks":
        extracted.extend(extract_telrad_breezeview_rows(path))
    elif vendor_slug == "lorex":
        extracted.extend(extract_lorex_psti_rows(path))
    elif vendor_slug == "siedle":
        extracted.extend(extract_siedle_discontinued_product_rows(path))
    elif vendor_slug == "synology":
        extracted.extend(extract_synology_product_status_rows(path))
    elif vendor_slug == "stormshield":
        extracted.extend(extract_stormshield_firewall_lifecycle_rows(path))
    elif vendor_slug == "terramaster":
        extracted.extend(extract_terramaster_support_termination_rows(path))
    elif vendor_slug == "tippingpoint":
        extracted.extend(extract_tippingpoint_eol_dates_rows(path))
    elif vendor_slug == "uniview":
        extracted.extend(extract_uniview_discontinued_product_rows(path))
    elif vendor_slug == "uplogix_lantronix":
        extracted.extend(extract_uplogix_lantronix_rows(path))
    elif vendor_slug == "wago":
        extracted.extend(extract_wago_discontinued_product_rows(path))
    elif vendor_slug == "zebra_printers_scanners":
        extracted.extend(extract_zebra_discontinued_product_rows(path))
    elif vendor_slug == "zte_networking":
        extracted.extend(extract_zte_lifecycle_rows(path))
    elif vendor_slug == "hillstone":
        extracted.extend(extract_hillstone_eol_policy_rows(path))
    elif vendor_slug == "nvt_phybridge":
        extracted.extend(extract_nvt_phybridge_eol_rows(path))
    return extracted


ROCKWELL_LIFECYCLE_URL = (
    "https://www.rockwellautomation.com/en-us/support/product/"
    "product-compatibility-migration/product-lifecycle-status.html"
)


def rockwell_stratix_network_product(doc: dict[str, Any]) -> bool:
    catalog = normalize_text(doc.get("catalogNumber"))
    if not catalog.startswith("1783-"):
        return False
    text = " ".join(
        normalize_text(doc.get(key))
        for key in ("title", "description")
        if normalize_text(doc.get(key))
    )
    normalized = normalize_header(text)
    if "cam switch" in normalized:
        return False
    return any(
        token in normalized
        for token in (
            "stratix",
            "ethernet",
            "managed switch",
            "switch",
            "wireless ap",
            "wireless workgroup bridge",
            "sfp",
            "tap",
        )
    )


def extract_rockwell_stratix_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if not re.match(r"api_lifecycle_1783_page_\d+\.json$", path.name):
        return []
    try:
        data = load_json(path)
    except Exception:
        return []
    rows: list[dict[str, Any]] = []
    for doc in data.get("docs") or []:
        if not isinstance(doc, dict):
            continue
        if not rockwell_stratix_network_product(doc):
            continue
        status = normalize_text(doc.get("productLifeCycleStatus"))
        if status not in {"DISCONTINUED", "END_OF_LIFE"}:
            continue
        discontinued_raw = normalize_text(doc.get("discontinuedDate"))
        discontinued_date = parse_date_any(discontinued_raw.split("T", 1)[0])
        if not discontinued_date:
            continue
        catalog = normalize_text(doc.get("catalogNumber"))
        title = normalize_text(doc.get("title")) or catalog
        description = normalize_text(doc.get("description")) or title
        source_url = normalize_text(doc.get("url")) or ROCKWELL_LIFECYCLE_URL
        replacement = normalize_text(doc.get("replacementText"))
        replacement_url = normalize_text(doc.get("replacementUrl"))
        aliases = []
        for alias in (catalog, title, description):
            if alias and alias not in aliases:
                aliases.append(alias)
        row: dict[str, Any] = {
            "Model": catalog,
            "Part Number": catalog,
            "Product Name": title,
            "Description": description,
            "Rockwell Lifecycle": status.replace("_", " ").title(),
            "End of Sale": discontinued_date,
            "_source_table": f"{path.name} docs",
            "_source_hint": "Rockwell Automation Stratix lifecycle API import",
            "_source_url": source_url,
            "_review_policy": "rockwell_lifecycle_status_sales_end_not_security_eol",
            "_review_reason": (
                "Rockwell lifecycle status defines End of Life as discontinued-date "
                "announcement and last-time-buy planning, and Discontinued as no "
                "longer manufactured or procured with possible repair/exchange "
                "services; the source does not publish a support or security-update "
                "end date."
            ),
            "_aliases": aliases,
            "_prefer_model": True,
            "Lifecycle Status Source": ROCKWELL_LIFECYCLE_URL,
        }
        if replacement:
            row["Replacement Products"] = replacement
        if replacement_url:
            row["Replacement URL"] = replacement_url
        rows.append(row)
    return rows


AKUVOX_SECURITY_UPDATE_URL = "https://www.akuvox.com/securitycompliance/security-update"


def akuvox_device_type(model: str, category: str = "") -> str:
    category_key = normalize_header(category)
    if "door phone" in category_key:
        return "IP Door Phone"
    if "indoor monitor" in category_key:
        return "Indoor Monitor"
    if "access control" in category_key:
        return "Access Control Device"

    model_key = normalize_header(model)
    if model_key.startswith(("a", "ec")):
        return "Access Control Device"
    if model_key.startswith(("c", "it", "s56")) or model_key in {"x933", "x937"}:
        return "Indoor Monitor"
    if model_key.startswith(("r", "e", "x", "s")):
        return "IP Door Phone"
    return "Smart Intercom Device"


def akuvox_base_row(model: str, category: str = "") -> dict[str, Any]:
    return {
        "Model": model,
        "Part Number": model,
        "Product Name": f"Akuvox {model}",
        "Description": akuvox_device_type(model, category),
        "Lifecycle Status Source": AKUVOX_SECURITY_UPDATE_URL,
        "_source_table": "security_update_eol_product_list.html",
        "_source_hint": "Akuvox security update and EOL product list import",
        "_source_url": AKUVOX_SECURITY_UPDATE_URL,
        "_aliases": [model, f"Akuvox {model}"],
        "_prefer_model": True,
    }


def akuvox_table_rows(table: Any) -> list[list[str]]:
    return [
        [normalize_text(cell) for cell in row]
        for row in html_table_matrix(table)
        if any(normalize_text(cell) for cell in row)
    ]


def akuvox_parse_update_date(value: Any) -> str:
    parsed = parse_date_any(value)
    if parsed:
        return parsed
    text = normalize_text(value)
    match = re.match(r"^(20\d{2})/(\d{1,2})$", text)
    if not match:
        return ""
    year = int(match.group(1))
    month = int(match.group(2))
    if not 1 <= month <= 12:
        return ""
    return date(year, month, calendar.monthrange(year, month)[1]).isoformat()


def extract_akuvox_security_update_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "security_update_eol_product_list.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    rows: list[dict[str, Any]] = []
    section = ""
    category = ""

    for node in soup.find_all(["h2", "p", "table"]):
        if node.name != "table":
            text = normalize_text(node.get_text(" ", strip=True))
            key = normalize_header(text)
            if key == "security updates":
                section = "security_updates"
                category = ""
            elif key == "eol product list":
                section = "eol"
                category = ""
            elif key == "eol product list under maintenance":
                section = "under_maintenance"
                category = ""
            elif key == "eol product list no maintenance":
                section = "no_maintenance"
                category = ""
            elif key in {"door phone", "indoor monitor", "access control"}:
                category = text
            continue

        table_rows = akuvox_table_rows(node)
        if not table_rows:
            continue

        if section in {"security_updates", "under_maintenance"}:
            header = [normalize_header(cell) for cell in table_rows[0]]
            if len(header) < 2 or header[0] != "product" or "update" not in header[1]:
                continue
            for row in table_rows[1:]:
                if len(row) < 2:
                    continue
                model = normalize_text(row[0])
                update_until = akuvox_parse_update_date(row[1])
                if not model or not update_until:
                    continue
                item = akuvox_base_row(model, category)
                if section == "security_updates":
                    item["Product Status"] = f"Security update support until {update_until}"
                    item["_review_policy"] = "akuvox_security_update_until"
                else:
                    item["Product Status"] = (
                        f"EOL Product List (Under Maintenance); updates until {update_until}"
                    )
                    item["_review_policy"] = "akuvox_eol_under_maintenance_until"
                item["End of Security Updates"] = update_until
                item["End of Vulnerability Support"] = update_until
                rows.append(item)
            continue

        if section == "no_maintenance":
            for row in table_rows:
                for cell in row:
                    model = normalize_text(cell)
                    if not model or normalize_header(model) == "product":
                        continue
                    item = akuvox_base_row(model, category)
                    item.update(
                        {
                            "Product Status": (
                                "EOL Product List (No Maintenance); no longer "
                                "receives software, firmware, or security updates"
                            ),
                            "_allow_status_only": True,
                            "_security_updates_ended_without_exact_date": True,
                            "_review_policy": "akuvox_eol_no_maintenance_security_updates_ended",
                            "_review_reason": (
                                "Akuvox says EOL products without maintenance "
                                "deadlines no longer receive software or firmware "
                                "updates, including security updates, and that "
                                "security vulnerability reports may no longer be "
                                "addressed for these products. The source does "
                                "not publish exact end dates for No Maintenance rows."
                            ),
                        }
                    )
                    rows.append(item)

    return rows


PEPLINK_LEGACY_PRODUCTS_URL = "https://www.peplink.com/legacy-products/"


def peplink_device_type(model: str) -> str:
    key = normalize_header(model)
    if "switch" in key:
        return "Network Switch"
    if "ap one" in key or "ap pro" in key or "device connector" in key:
        return "Wireless Access Point"
    if "module" in key or "adapter" in key:
        return "Cellular Modem Module"
    if "speedfusion" in key or key == "epx":
        return "SD-WAN Appliance"
    if (
        "balance" in key
        or "max " in key
        or key.startswith("ubr")
        or "surf soho" in key
        or re.search(r"\bbr\d\b", key)
    ):
        return "Router"
    return "Network Device"


def peplink_split_replacements(value: str) -> list[str]:
    replacements = []
    for item in value.split("|"):
        item = normalize_text(item)
        if item:
            replacements.append(item)
    return replacements


def extract_peplink_legacy_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "legacy_product_feed.txt":
        return []

    text = path.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")
    if "Legacy Product Name:" not in text:
        return []

    rows: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[normalize_header(key)] = normalize_text(value)

        model = fields.get("legacy product name", "")
        if not model:
            continue
        replacements = peplink_split_replacements(
            fields.get("replacement product names", "")
        )
        row = {
            "Model": model,
            "Product Name": f"Peplink {model}",
            "Description": peplink_device_type(model),
            "Product Status": (
                "Legacy product; Peplink says it does not discontinue or EOL "
                "products and provides software updates that address security "
                "issues while the customer device is on warranty"
            ),
            "_source_table": f"{path.name} legacy product block",
            "_source_hint": "Peplink legacy products feed import",
            "_source_url": PEPLINK_LEGACY_PRODUCTS_URL,
            "_status_only_review": True,
            "_review_policy": "peplink_legacy_product_not_vendor_eol",
            "_review_reason": (
                "Peplink lists this model as a legacy product and explicitly "
                "says it does not discontinue or EOL products. The source does "
                "not publish an end-of-support or security-update end date, so "
                "this row is status-only lifecycle-review evidence."
            ),
            "_prefer_model": True,
        }
        if replacements:
            row["Replacement Products"] = "; ".join(replacements)
        rows.append(row)
    return rows


def extract_vendor_text_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug == "peplink":
        return extract_peplink_legacy_product_rows(path)
    return []


TERADEK_CUBE_SERV_PRO_EOL_URL = (
    "https://guide.teradek.com/a/"
    "1628428-end-of-life-notification-for-cube-6xx-cube-7xx-serv-pro"
)


def teradek_device_type(description: str) -> str:
    key = normalize_header(description)
    if "video server" in key:
        return "IP Video Server"
    if "encoder" in key and "decoder" in key:
        return "IP Video Encoder/Decoder"
    if "encoder" in key:
        return "IP Video Encoder"
    if "decoder" in key:
        return "IP Video Decoder"
    return "IP Video Device"


def teradek_product_aliases(sku: str, description: str) -> list[str]:
    aliases = [sku, description]
    for match in re.finditer(r"\b(?:Serv Pro|Cubelet [0-9/]+|Cube [0-9]{3})\b", description):
        aliases.append(match.group(0))
    return aliases


def extract_teradek_cube_serv_pro_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "teradek_cube_serv_pro_eol_article.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    if "End-of-Life Notification for Cube 6xx / Cube 7xx / Serv Pro" not in (
        soup.title.get_text(" ", strip=True) if soup.title else ""
    ):
        return []

    product_rows: list[tuple[str, str]] = []
    milestone_dates: dict[str, str] = {}
    for table in soup.find_all("table"):
        rows = html_table_matrix(table)
        if len(rows) < 2:
            continue
        header = [normalize_header(cell) for cell in rows[0]]
        if header[:2] == ["product sku", "product description"]:
            for row in rows[1:]:
                if len(row) < 2:
                    continue
                sku = normalize_text(row[0])
                description = normalize_text(row[1])
                if re.fullmatch(r"\d{2}-\d{4}", sku) and description:
                    product_rows.append((sku, description))
            continue
        if len(header) >= 3 and header[:3] == ["milestone", "definition", "date"]:
            for row in rows[1:]:
                if len(row) < 3:
                    continue
                milestone = normalize_header(row[0])
                parsed = parse_date_any(row[2])
                if not parsed:
                    continue
                if milestone == "end of life announcement":
                    milestone_dates["Announcement"] = parsed
                elif milestone == "end of sale":
                    milestone_dates["End of Sale"] = parsed
                elif milestone == "end of support":
                    milestone_dates["End of Support"] = parsed
                    milestone_dates["End of Service"] = parsed

    if not product_rows or not milestone_dates.get("End of Support"):
        return []

    rows: list[dict[str, Any]] = []
    for sku, description in product_rows:
        row = {
            "Model": sku,
            "Part Number": sku,
            "Product Name": description,
            "Description": teradek_device_type(description),
            "Product Status": (
                "End-of-Life process; full technical support and service "
                f"through {milestone_dates['End of Support']}; limited support after"
            ),
            "_source_table": f"{path.name} affected products and milestones",
            "_source_hint": "Teradek Cube/Serv Pro EOL notification import",
            "_source_url": TERADEK_CUBE_SERV_PRO_EOL_URL,
            "_force_lifecycle_review": True,
            "_review_policy": "teradek_full_support_end_limited_support_continues",
            "_review_reason": (
                "Teradek defines End-of-Support as the last day for full "
                "technical support and service, after which affected products "
                "transition to limited support. The source does not state that "
                "all support, vulnerability handling, or security updates end."
            ),
            "_aliases": teradek_product_aliases(sku, description),
            "_prefer_model": True,
        }
        row.update(milestone_dates)
        rows.append(row)
    return rows


FLUKE_DTX_EOL_ACCESSORIES_URL = (
    "https://www.flukenetworks.com/knowledge-base/dtx-cableanalyzertm/"
    "dtx-1800-series-cable-analyzer-end-life-accessories-parts"
)


def extract_fluke_networks_dtx_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "dtx_1800_series_end_of_life_accessories_parts.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "DTX-1800 Series Cable Analyzer End of Life" not in title:
        return []
    if "Fluke Service ended repair and calibration services as of June 30, 2018" not in text:
        return []

    rows: list[dict[str, Any]] = []
    for model in ("DTX-1800", "DTX-1200"):
        rows.append(
            {
                "Model": model,
                "Product Name": f"{model} CableAnalyzer",
                "Description": "Cable Certification Tester",
                "Product Status": (
                    "DTX-1800 Series end of life; Fluke Service ended repair "
                    "and calibration services as of 2018-06-30"
                ),
                "End of Service": "2018-06-30",
                "Replacement Products": "DSX CableAnalyzer Series",
                "_source_table": f"{path.name} DTX service/calibration notice",
                "_source_hint": "Fluke Networks DTX CableAnalyzer EOL notice import",
                "_source_url": FLUKE_DTX_EOL_ACCESSORIES_URL,
                "_force_lifecycle_review": True,
                "_review_policy": (
                    "fluke_networks_dtx_repair_calibration_end_not_security_eol"
                ),
                "_review_reason": (
                    "Fluke Networks says repair and calibration services ended "
                    "for DTX-1800 Series testers. This is service/calibration "
                    "lifecycle evidence, not firmware, vulnerability, or "
                    "security-update end evidence."
                ),
                "_aliases": [
                    model,
                    f"Fluke {model}",
                    f"Fluke Networks {model}",
                    f"{model} CableAnalyzer",
                    "DTX CableAnalyzer Series",
                ],
                "_prefer_model": True,
            }
        )
    return rows


def aiphone_source_url(path: Path) -> str:
    match = re.match(r"page_products_\d+_(.+)\.html$", path.name)
    if not match:
        return ""
    return f"https://www.aiphone.com/products/{match.group(1)}/"


def aiphone_device_type(description: str) -> str:
    key = normalize_header(description)
    if "network adaptor" in key or "network adapter" in key or "analog to ip" in key:
        return "Network Intercom Adapter"
    if "rain hood" in key or "module" in key:
        return "Intercom Mounting Accessory"
    return "Intercom Accessory"


def extract_aiphone_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if not re.match(r"page_products_\d+_.+\.html$", path.name):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    match = re.match(r"([A-Z0-9-]+)\s+\(Discontinued\)\s+-\s+Aiphone$", title)
    if not match:
        return []
    model = match.group(1)
    description = ""
    for attrs in ({"name": "description"}, {"property": "og:description"}):
        node = soup.find("meta", attrs=attrs)
        if node and node.get("content"):
            description = normalize_text(node.get("content"))
            break
    if not description:
        description = f"Aiphone discontinued product {model}"

    return [
        {
            "Model": model,
            "Product Name": f"Aiphone {model}",
            "Description": aiphone_device_type(description),
            "Product Status": "Discontinued product page",
            "_source_table": f"{path.name} product page title",
            "_source_hint": "Aiphone discontinued product page import",
            "_source_url": aiphone_source_url(path),
            "_status_only_review": True,
            "_review_policy": "aiphone_discontinued_product_page_status_only",
            "_review_reason": (
                "Aiphone marks this product page as discontinued, but the "
                "captured product page does not publish an exact support, "
                "service, vulnerability, or security-update end date."
            ),
            "_aliases": [model, f"Aiphone {model}", description],
            "_prefer_model": True,
        }
    ]


def crestron_product_source_url(soup: BeautifulSoup) -> str:
    node = soup.find("meta", attrs={"property": "og:url"})
    if node and node.get("content"):
        return normalize_text(node.get("content"))
    link = soup.find("link", attrs={"rel": "alternate", "hreflang": "en"})
    if link and link.get("href"):
        return normalize_text(link.get("href"))
    return ""


def crestron_product_jsonld(soup: BeautifulSoup) -> dict[str, Any]:
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(script.get_text("", strip=True))
        except json.JSONDecodeError:
            continue
        candidates = data if isinstance(data, list) else [data]
        for item in candidates:
            if not isinstance(item, dict):
                continue
            item_type = item.get("@type") or item.get("type")
            if str(item_type).lower() != "product":
                continue
            if item.get("sku") or item.get("name"):
                return item
    return {}


def crestron_device_type(model: str, description: str) -> str:
    key = normalize_header(f"{model} {description}")
    if "network attached storage" in key or " nas " in f" {key} ":
        return "NAS Storage"
    if (
        "ethernet switch" in key
        or "poe switch" in key
        or "po e switch" in key
        or "port switch" in key
    ):
        return "Network Switch"
    if "wireless access point" in key or "wap" in key:
        return "Wireless Access Point"
    if "airmedia" in key or "presentation system" in key:
        return "Wireless Presentation Gateway"
    if "control processor" in key or re.search(r"\bcp[234]\b", key):
        return "AV Control Processor"
    if "gateway" in key:
        return "Automation Gateway"
    if "server" in key or "fusion" in key:
        return "AV Management Server"
    if "video" in key or "audio" in key or "matrix" in key:
        return "AV Distribution Device"
    return "AV Control Device"


def extract_crestron_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    source_url = crestron_product_source_url(soup)
    if "/Products/Catalog/Inactive/Discontinued/" not in source_url:
        return []
    status = soup.find(class_=lambda value: value and "availability-header" in str(value))
    if not status or "discontinued" not in normalize_header(status.get_text(" ", strip=True)):
        return []

    product = crestron_product_jsonld(soup)
    model = normalize_text(product.get("sku") or product.get("name"))
    if not model:
        title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
        match = re.match(r"([A-Z0-9][A-Z0-9._+-]*)\s+\[Crestron", title)
        if match:
            model = match.group(1)
    if not model:
        return []

    product_name = normalize_text(product.get("name")) or model
    description = normalize_text(product.get("description"))
    if not description:
        for attrs in ({"name": "description"}, {"property": "og:description"}):
            node = soup.find("meta", attrs=attrs)
            if node and node.get("content"):
                description = normalize_text(node.get("content"))
                break
    device_type = crestron_device_type(model, description)
    aliases = [model, f"Crestron {model}", product_name, description, device_type]

    return [
        {
            "Model": model,
            "Product Name": product_name if product_name.startswith("Crestron ") else f"Crestron {product_name}",
            "Description": device_type,
            "Product Status": "Discontinued product page",
            "_source_table": f"{path.name} product page availability",
            "_source_hint": "Crestron discontinued product page import",
            "_source_url": source_url,
            "_status_only_review": True,
            "_review_policy": "crestron_discontinued_product_page_status_only",
            "_review_reason": (
                "Crestron marks this product page as discontinued, but the "
                "captured product page does not publish an exact end-of-sale, "
                "support, service, vulnerability, or security-update end date."
            ),
            "_aliases": [alias for alias in aliases if alias],
            "_prefer_model": True,
        }
    ]


def html_page_title(soup: BeautifulSoup) -> str:
    return html_lib.unescape(
        normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    )


def html_meta_content(soup: BeautifulSoup, *attrs: dict[str, str]) -> str:
    for attr in attrs:
        node = soup.find("meta", attrs=attr)
        if node and node.get("content"):
            return html_lib.unescape(normalize_text(node.get("content")))
    return ""


def html_product_page_source_url(soup: BeautifulSoup) -> str:
    source_url = html_meta_content(soup, {"property": "og:url"})
    if source_url:
        return source_url
    for link in soup.find_all("link"):
        rel = link.get("rel")
        rel_text = " ".join(rel) if isinstance(rel, list) else normalize_text(rel)
        if "canonical" not in rel_text.lower():
            continue
        href = normalize_text(link.get("href"))
        if href:
            return href
    return ""


def first_h1_text(soup: BeautifulSoup) -> str:
    for heading in soup.find_all("h1"):
        text = html_lib.unescape(normalize_text(heading.get_text(" ", strip=True)))
        if text:
            return text
    return ""


def status_page_device_type(text: str) -> str:
    key = normalize_header(text)
    if "camera" in key or "dome" in key or "bullet" in key or "fisheye" in key:
        return "IP Camera"
    if "nvr" in key or "network video recorder" in key or "recorder" in key:
        return "Network Video Recorder"
    if "dvr" in key or "xvr" in key or "decoder" in key or "encoder" in key:
        return "Video Surveillance Device"
    if "door reader" in key or "access controller" in key or "access control" in key:
        return "Access Control Device"
    if "alarm" in key:
        return "Alarm Device"
    if "environmental sensor" in key or "air quality" in key:
        return "Environmental Sensor"
    if "sfp" in key or "transceiver" in key:
        return "Network Module"
    if (
        "poe extender" in key
        or "po e extender" in key
        or "poe injector" in key
        or "po e injector" in key
    ):
        return "PoE Network Accessory"
    if "wireless access point" in key or "access point" in key:
        return "Wireless Access Point"
    if "router" in key:
        return "Router"
    if "ethernet switch" in key or "poe switch" in key or re.search(r"\bswitch\b", key):
        return "Network Switch"
    if "network appliance" in key:
        return "Network Appliance"
    if "embedded system" in key:
        return "Embedded System"
    if "com express" in key or "module" in key:
        return "Embedded Module"
    if "control gateway" in key or "control processor" in key:
        return "AV Control Gateway"
    if "gateway" in key:
        return "Gateway"
    if "matrix" in key or "switcher" in key:
        return "AV Matrix Switcher"
    if "extender" in key or "hdbaset" in key:
        return "AV Extender"
    if "antenna" in key or "mimo" in key or "wi fi" in key or "wifi" in key:
        return "Network Antenna"
    if "laser" in key or "fiber" in key or "optical" in key:
        return "Optical Network Test Equipment"
    return "Network Device"


def status_only_product_row(
    *,
    model: str,
    product_name: str,
    description: str,
    product_status: str,
    source_table: str,
    source_hint: str,
    source_url: str,
    review_policy: str,
    review_reason: str,
    aliases: list[str],
    replacement: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "Model": model,
        "Product Name": product_name,
        "Description": description,
        "Product Status": product_status,
        "_source_table": source_table,
        "_source_hint": source_hint,
        "_source_url": source_url,
        "_status_only_review": True,
        "_review_policy": review_policy,
        "_review_reason": review_reason,
        "_aliases": [alias for alias in aliases if alias],
        "_prefer_model": True,
    }
    if replacement:
        row["Replacement"] = replacement
    return row


def adlink_clean_model_name(value: str) -> str:
    model = html_lib.unescape(normalize_text(value))
    model = re.sub(r"\s*\|\s*ADLINK.*$", "", model, flags=re.I)
    model = re.sub(r"^ADLINK\s+", "", model, flags=re.I)
    return normalize_text(model.strip(" .:-"))


def adlink_model_from_slug(source_url: str) -> str:
    slug = normalize_text(source_url).rstrip("/").split("?", 1)[0].rsplit("/", 1)[-1]
    if not slug:
        return ""
    parts = [part for part in re.split(r"[_-]+", slug) if part]
    if not parts:
        return ""
    formatted = "-".join(part.upper() for part in parts)
    return formatted.replace("-SERIES", " Series")


def adlink_product_model(soup: BeautifulSoup, source_url: str, page_text: str) -> str:
    for selector in (".Product-name", "h2.Product-name"):
        node = soup.select_one(selector)
        if node:
            model = adlink_clean_model_name(node.get_text(" ", strip=True))
            if model:
                return model

    for pattern in (
        r"\bThe\s+([A-Z0-9][A-Z0-9._+/\- ]+?)\s+is scheduled for discontinuation",
        r"\b([A-Z0-9][A-Z0-9._+/\- ]+?)\s+is scheduled to be EOL\b",
    ):
        match = re.search(pattern, page_text, flags=re.I)
        if match:
            model = adlink_clean_model_name(match.group(1))
            if model:
                return model

    for candidate in (
        html_meta_content(soup, {"name": "title"}, {"property": "og:title"}),
        html_page_title(soup),
        adlink_model_from_slug(source_url),
    ):
        model = adlink_clean_model_name(candidate)
        if model and normalize_header(model) not in {
            "industrial pcs",
            "embedded computer",
        }:
            return model
    return ""


def adlink_replacement(soup: BeautifulSoup, page_text: str) -> str:
    for node in soup.select(".Product-eol"):
        links = [normalize_text(link.get_text(" ", strip=True)) for link in node.find_all("a")]
        links = [link for link in links if link]
        if links:
            return links[-1]

    for node in soup.select(".Product-sub, .Product-eol"):
        node_text = normalize_text(node.get_text(" ", strip=True))
        match = re.search(
            r"\b(?:recommended|suggested) replacement(?: product)? is\s+"
            r"([A-Z0-9][A-Z0-9._+/\- ]+?)$",
            node_text,
            flags=re.I,
        )
        if match:
            return normalize_text(match.group(1))

    match = re.search(
        r"\b(?:recommended|suggested) replacement(?: product)? is\s+"
        r"([A-Z0-9][A-Z0-9._+/\- ]+?)(?:[.;\n]|$)",
        page_text,
        flags=re.I,
    )
    if match:
        return normalize_text(match.group(1))

    match = re.search(
        r"\bReplacement:\s*([A-Z0-9][A-Z0-9._+/\- ]+?)(?:\s|<|$)",
        page_text,
        flags=re.I,
    )
    return normalize_text(match.group(1)) if match else ""


def adlink_lifecycle_dates(page_text: str) -> dict[str, str]:
    dates: dict[str, str] = {}
    for label, header in (
        ("Last buy date", "End of Sale"),
        ("Last shipment date", "Last Shipment Date"),
    ):
        match = re.search(
            rf"{label}\s*:\s*"
            r"([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}|\d{4}/\d{1,2}/\d{1,2})",
            page_text,
            flags=re.I,
        )
        parsed = parse_date_any(match.group(1)) if match else None
        if parsed:
            dates[header] = parsed

    if "End of Sale" not in dates:
        match = re.search(
            r"scheduled for discontinuation as of\s+"
            r"([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}|\d{4}/\d{1,2}/\d{1,2})",
            page_text,
            flags=re.I,
        )
        parsed = parse_date_any(match.group(1)) if match else None
        if parsed:
            dates["End of Sale"] = parsed
    return dates


def extract_adlink_product_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "END OF LIFE" not in page_text and "This model is EOL" not in page_text:
        return []

    source_url = html_product_page_source_url(soup)
    model = adlink_product_model(soup, source_url, page_text)
    if not model:
        return []
    product_name = f"ADLINK {model}"
    product_sub = ""
    sub_node = soup.select_one(".Product-sub")
    if sub_node:
        product_sub = html_lib.unescape(normalize_text(sub_node.get_text(" ", strip=True)))
    description = status_page_device_type(
        " ".join(
            value
            for value in (
                model,
                product_sub,
                html_meta_content(
                    soup,
                    {"name": "description"},
                    {"property": "og:description"},
                ),
            )
            if value
        )
    )
    replacement = adlink_replacement(soup, page_text)
    row = status_only_product_row(
        model=model,
        product_name=product_name,
        description=description,
        product_status="END OF LIFE product page",
        source_table=f"{path.name} ADLINK product page status",
        source_hint="ADLINK END OF LIFE product page review import",
        source_url=source_url,
        review_policy="adlink_end_of_life_product_page_status_only",
        review_reason=(
            "ADLINK marks this product page as END OF LIFE and may publish "
            "last-buy, shipment, or replacement information, but the captured "
            "page does not publish an exact support, service, vulnerability, "
            "or security-update end date."
        ),
        aliases=[model, product_name, product_sub, replacement, source_url],
        replacement=replacement,
    )
    row.update(adlink_lifecycle_dates(page_text))
    return [row]


FANVIL_EOL_URL_RE = re.compile(r"^(\d{8})_(\d+)\.html$")
FANVIL_PRODUCT_SUFFIXES = (
    "High-quality IP Phone",
    "High-end IP Phone",
    "Entry Level IP Phone",
    "Essential Business Phone",
    "Android Video Phone",
    "Wall-mount IP Phone",
    "SIP Video Door Phone",
    "SIP Audio Door Phone",
    "SIP Paging Gateway",
    "SIP mini Intercom",
    "Video Intercom",
    "SIP Speaker",
    "Pedal Switch",
    "IP Phones",
    "IP Phone",
    "Speakerphone",
)


def fanvil_source_url(path: Path) -> str:
    match = FANVIL_EOL_URL_RE.match(path.name)
    if not match:
        return ""
    ymd, page_id = match.groups()
    return f"https://www.fanvil.com/products/p8/{ymd}/{page_id}.html"


def fanvil_model_group_from_title(title: str) -> str:
    text = html_lib.unescape(normalize_text(title))
    text = re.sub(r"\s*EOL\s+Notice$", "", text, flags=re.I).strip()
    for suffix in FANVIL_PRODUCT_SUFFIXES:
        if text.lower().endswith(suffix.lower()):
            return normalize_text(text[: -len(suffix)])
    return text


def fanvil_split_model_group(group: str) -> list[str]:
    parts = [normalize_text(part) for part in group.split("/") if normalize_text(part)]
    if not parts:
        return []
    return parts


def fanvil_device_type(title: str) -> str:
    key = normalize_header(title)
    if "speakerphone" in key:
        return "Conference Speakerphone"
    if "sip speaker" in key:
        return "SIP Speaker"
    if "paging gateway" in key:
        return "VoIP Paging Gateway"
    if "intercom" in key or "door phone" in key:
        return "IP Intercom"
    if "pedal switch" in key:
        return "Telephony Accessory"
    return "IP Phone"


def fanvil_discontinued_date(page_text: str) -> str | None:
    match = re.search(
        r"\bdiscontinued since\s+([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        page_text,
        flags=re.I,
    )
    return parse_date_any(match.group(1)) if match else None


def extract_fanvil_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not FANVIL_EOL_URL_RE.match(path.name):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    h1 = first_h1_text(soup)
    if "EOL Notice" not in h1 and "EOL" not in h1:
        return []
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Fanvil" not in page_text or (
        "End-of-Life" not in page_text and "End of Life" not in page_text
    ):
        return []

    model_group = fanvil_model_group_from_title(h1)
    models = fanvil_split_model_group(model_group)
    if not models:
        return []

    discontinued = fanvil_discontinued_date(page_text)
    source_url = html_product_page_source_url(soup) or fanvil_source_url(path)
    device_type = fanvil_device_type(h1)
    rows = []
    for model in models:
        row = status_only_product_row(
            model=model,
            product_name=f"Fanvil {model}",
            description=device_type,
            product_status="Fanvil EOL Notice; product discontinued/end-of-life",
            source_table=f"{path.name} Fanvil EOL notice",
            source_hint="Fanvil EOL notice review import",
            source_url=source_url,
            review_policy="fanvil_eol_notice_status_only_support_continues",
            review_reason=(
                "Fanvil marks this product as discontinued/end-of-life and says "
                "new orders are not accepted after the EOL date, while also "
                "describing continued software and after-sales support after "
                "EOL. The captured notice does not publish an exact "
                "security-update end date."
            ),
            aliases=[model, model_group, h1],
        )
        if discontinued:
            row["End of Sale"] = discontinued
        rows.append(row)
    return rows


def ezurio_part_specs(soup: BeautifulSoup) -> dict[str, str]:
    specs: dict[str, str] = {}
    for row in soup.select(".spec-content"):
        label_node = row.select_one(".specification")
        value_node = row.select_one(".value")
        label = normalize_text(label_node.get_text(" ", strip=True) if label_node else "")
        value = normalize_text(value_node.get_text(" ", strip=True) if value_node else "")
        if label and value:
            specs[label] = value
    return specs


def ezurio_device_type(product_type: str, title: str, description: str) -> str:
    key = normalize_header(f"{product_type} {title} {description}")
    if "iot gateway" in key or "io t gateway" in key:
        return "IoT Gateway"
    if "iot sensor" in key or "io t sensor" in key:
        return "IoT Sensor"
    if "system on module" in key or "som" in key:
        return "System-on-Module"
    if "embedded module" in key or normalize_header(product_type) == "module":
        return "Embedded Module"
    if "development kit" in key:
        return "Development Kit"
    if "usb adapter" in key:
        return "USB Adapter"
    if "antenna" in key:
        return "RF Antenna"
    return product_type or "Wireless/Embedded Module"


def extract_ezurio_part_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("part_"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    heading = soup.find("h1", attrs={"data-part": True})
    model = normalize_text(heading.get("data-part") if heading else "")
    product_name = normalize_text(heading.get_text(" ", strip=True) if heading else "")
    lifecycle = normalize_text(
        soup.select_one(".lifecycle").get_text(" ", strip=True)
        if soup.select_one(".lifecycle")
        else ""
    )
    if not model or normalize_header(lifecycle) != "end of life eol":
        return []

    specs = ezurio_part_specs(soup)
    product_type = normalize_text(specs.get("Product Type"))
    description = normalize_text(
        specs.get("Description") or specs.get("Additional Description")
    )
    source_url = html_product_page_source_url(soup) or f"https://www.ezurio.com/part/{model}"
    title = html_page_title(soup)
    row = status_only_product_row(
        model=model,
        product_name=product_name or model,
        description=ezurio_device_type(product_type, product_name, description),
        product_status="Ezurio part page lifecycle status: End of Life (EOL)",
        source_table=f"{path.name} Ezurio part page",
        source_hint="Ezurio EOL part page review import",
        source_url=source_url,
        review_policy="ezurio_part_page_eol_status_only",
        review_reason=(
            "Ezurio marks this exact part page as End of Life (EOL), but the "
            "captured part page does not publish exact support, service, "
            "vulnerability, firmware, or security-update end dates."
        ),
        aliases=[model, product_name, title, product_type, description, source_url],
    )
    row["Part Number"] = model
    row["Lifecycle Status Source"] = source_url
    row["_suppress_description_aliases"] = True
    if product_type:
        row["Product Type"] = product_type
    if description:
        row["Source Description"] = description
    return [row]


def kontron_product_id_from_source(source_url: str, path: Path) -> str:
    match = re.search(r"/p(\d+)(?:\D|$)", normalize_text(source_url))
    if match:
        return match.group(1)
    match = re.search(r"_p(\d+)\.html$", path.name)
    return match.group(1) if match else ""


def kontron_device_type(model: str, subheadline: str, title: str) -> str:
    key = normalize_header(f"{model} {subheadline} {title}")
    if "ethernet switch" in key or "network switch" in key or "switches" in key:
        return "Network Switch"
    if "gateway router" in key or "gateway" in key:
        return "Gateway/Router"
    if "server" in key:
        return "Server"
    if "panel pc" in key or "flat panel pc" in key:
        return "Panel PC"
    if "industrial computer" in key or "computer platform" in key:
        return "Industrial Computer"
    if "single board computer" in key or re.search(r"\bsbc\b", key):
        return "Single Board Computer"
    if "carrier" in key:
        return "Carrier Board"
    if "mezzanine" in key or re.search(r"\bxmc\b", key):
        return "Mezzanine Card"
    if "workstation" in key:
        return "Industrial Workstation"
    return status_page_device_type(f"{model} {subheadline} {title}")


def kontron_replacement(status_text: str) -> str:
    match = re.search(
        r"Replacement product\s*:\s*(.+?)(?:More information|$)",
        status_text,
        flags=re.I,
    )
    return normalize_text(match.group(1)) if match else ""


def extract_kontron_product_eol_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    status_nodes = [
        normalize_text(node.get_text(" ", strip=True))
        for node in soup.select(".eol-warning")
    ]
    status_text = normalize_text(" ".join(status_nodes))
    if "not recommended for new designs" not in normalize_header(status_text):
        return []

    h1 = soup.find("h1")
    model = normalize_text(h1.get_text(" ", strip=True) if h1 else "")
    if not model:
        return []
    h2 = soup.find("h2", class_="h5") or soup.find("h2")
    subheadline = normalize_text(h2.get_text(" ", strip=True) if h2 else "")
    title = html_page_title(soup)
    source_url = html_product_page_source_url(soup)
    product_id = kontron_product_id_from_source(source_url, path)
    replacement = kontron_replacement(status_text)
    row = status_only_product_row(
        model=model,
        product_name=f"Kontron {model}",
        description=kontron_device_type(model, subheadline, title),
        product_status=f"Kontron product page status: {status_text}",
        source_table=f"{path.name} Kontron product page",
        source_hint="Kontron product page not-recommended review import",
        source_url=source_url,
        review_policy="kontron_not_recommended_for_new_designs_status_only",
        review_reason=(
            "Kontron marks this exact product page as not recommended for new "
            "designs, but the captured page does not publish exact support, "
            "service, vulnerability, firmware, or security-update end dates."
        ),
        aliases=[model, subheadline, title, product_id, replacement, source_url],
        replacement=replacement,
    )
    row["Part Number"] = model
    row["_suppress_description_aliases"] = True
    if product_id:
        row["Product ID"] = product_id
    if subheadline:
        row["Source Description"] = subheadline
    return [row]


PEPPERL_FUCHS_ARCHIVE_SOURCE_URLS = {
    "as_interface_safety_archive.json": (
        "https://www.pepperl-fuchs.com/usa/en/classid_2394.htm"
    ),
    "fieldbus_infrastructure_archive_page_1.json": (
        "https://www.pepperl-fuchs.com/usa/en/classid_260.htm?view=productgroupoverview"
    ),
    "fieldbus_infrastructure_archive_page_2.json": (
        "https://www.pepperl-fuchs.com/en-us/products-gp25581?class=33624&archived=true&size=61"
    ),
    "k_system_isolated_barriers_archive.json": (
        "https://www.pepperl-fuchs.com/global/en/classid_23.htm"
    ),
    "static_inclination_sensors_archive.json": (
        "https://www.pepperl-fuchs.com/usa/en/classid_2032.htm?view=productgroupoverview"
    ),
    "surge_protection_archive.json": (
        "https://www.pepperl-fuchs.com/global/en/classid_6198.htm"
    ),
    "ultrasonic_level_sensors_archive.json": (
        "https://www.pepperl-fuchs.com/usa/en/classid_492.htm?view=pro"
    ),
}

PEPPERL_FUCHS_ARCHIVE_DUPLICATE_SOURCE_KEYS = {
    # These two exact product rows are returned by both the fieldbus and surge
    # archive API captures. Keep the fieldbus copy and suppress the overlap.
    ("surge_protection_archive.json", "130018", "DP-LBF-I1.34"),
    ("surge_protection_archive.json", "130019", "DP-LBF-1.34"),
}


def pepperl_fuchs_clean_json_text(value: Any) -> str:
    text = html_lib.unescape(normalize_text(value))
    if "<" in text and ">" in text:
        text = BeautifulSoup(text, "lxml").get_text(" ", strip=True)
    text = re.sub(r"[\u00ae\u2122]", "", text)
    return normalize_text(text)


def pepperl_fuchs_device_type(
    source_name: str,
    short_name: str,
    description: str,
) -> str:
    key = normalize_header(f"{source_name} {short_name} {description}")
    if "as interface safety" in key or "safety monitor" in key:
        return "AS-Interface Safety Monitor"
    if "ultrasonic level" in key:
        return "Ultrasonic Level Sensor"
    if "inclination sensor" in key:
        return "Industrial Inclination Sensor"
    if "surge protector" in key or "surge protection" in key:
        return "Surge Protection Device"
    if "isolated barrier" in key or "barrier" in key:
        return "Isolated Barrier"
    if "fieldbus power hub" in key or "power hub" in key:
        return "Industrial Fieldbus Power Hub"
    if "segment protector" in key:
        return "Industrial Fieldbus Segment Protector"
    if "gateway" in key:
        return "Industrial Fieldbus Gateway"
    if "com port converter" in key or (
        "ethernet" in key and ("rs 232" in key or "rs 485" in key or "rs 422" in key)
    ):
        return "Serial-to-Ethernet Converter"
    if "valve coupler" in key or "device coupler" in key:
        return "Industrial Fieldbus Coupler"
    if "relay module" in key:
        return "Relay Module"
    if "sensor" in key:
        return "Industrial Sensor"
    return short_name or "Industrial Automation Device"


def extract_pepperl_fuchs_archive_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in PEPPERL_FUCHS_ARCHIVE_SOURCE_URLS:
        return []
    try:
        data = load_json(path)
    except Exception:
        return []
    docs = (
        (data.get("productResponse") or {})
        .get("response", {})
        .get("docs")
        or []
    )
    if not isinstance(docs, list):
        return []

    source_url = PEPPERL_FUCHS_ARCHIVE_SOURCE_URLS[path.name]
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if doc.get("content_type_s") != "product" or doc.get("state_s") != "ARCHIVE":
            continue
        if doc.get("isSoftware_b") is True:
            continue
        product_id = pepperl_fuchs_clean_json_text(doc.get("id"))
        product_name = pepperl_fuchs_clean_json_text(doc.get("name_s"))
        part_number = pepperl_fuchs_clean_json_text(doc.get("partNumber_s"))
        short_name = pepperl_fuchs_clean_json_text(doc.get("shortName_s"))
        description = pepperl_fuchs_clean_json_text(doc.get("longDescription_s"))
        marketing_alias = pepperl_fuchs_clean_json_text(doc.get("marketingAlias_s"))
        if not product_name or not part_number:
            continue
        duplicate_source_key = (path.name, part_number, product_name)
        if duplicate_source_key in PEPPERL_FUCHS_ARCHIVE_DUPLICATE_SOURCE_KEYS:
            continue
        key = (
            normalize_alias_dedupe_key(product_id),
            normalize_alias_dedupe_key(part_number),
            normalize_alias_dedupe_key(product_name),
        )
        if key in seen:
            continue
        seen.add(key)

        row = status_only_product_row(
            model=part_number,
            product_name=f"Pepperl+Fuchs {product_name}",
            description=pepperl_fuchs_device_type(path.name, short_name, description),
            product_status="Pepperl+Fuchs product archive state: ARCHIVE",
            source_table=f"{path.name} productResponse docs",
            source_hint="Pepperl+Fuchs archived product API review import",
            source_url=source_url,
            review_policy="pepperl_fuchs_archive_state_status_only",
            review_reason=(
                "Pepperl+Fuchs marks this exact API product row as archived, but "
                "the captured archive response does not publish exact support, "
                "service, vulnerability, firmware, or security-update end dates."
            ),
            aliases=[
                part_number,
                product_name,
                short_name,
                product_id,
                marketing_alias,
            ],
        )
        row["Part Number"] = part_number
        row["Pepperl+Fuchs Product Name"] = product_name
        row["Lifecycle Status Source"] = source_url
        row["_suppress_description_aliases"] = True
        if product_id:
            row["Pepperl+Fuchs Product ID"] = product_id
        if short_name:
            row["Source Short Name"] = short_name
        if description:
            row["Source Description"] = description[:1000]
        if marketing_alias:
            row["Marketing Alias"] = marketing_alias
        rows.append(row)
    return rows


def icp_das_source_url_from_product(model: str) -> str:
    return f"https://www.icpdas.com/en/product/{model}"


def icp_das_device_type(model: str, title: str, description: str) -> str:
    key = normalize_header(f"{model} {title} {description}")
    if "ethernet switch" in key or re.search(r"\bnsm?\b", key):
        return "Industrial Ethernet Switch"
    if "gateway" in key or "modbus tcp" in key or "m2m" in key or "grp" in key:
        return "Industrial Gateway"
    if "programmable automation controller" in key or "pac" in key:
        return "Programmable Automation Controller"
    if "controller" in key or "wise" in key or "upac" in key:
        return "Industrial Controller"
    return "Industrial Network Device"


def extract_icp_das_product_status_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title_area = soup.select_one(".pro_title_area")
    if not title_area:
        return []
    model_node = title_area.select_one("h2.st")
    model = normalize_text(model_node.get_text(" ", strip=True) if model_node else "")
    label_node = title_area.select_one(".tag_box label")
    status = normalize_text(label_node.get_text(" ", strip=True) if label_node else "")
    if normalize_header(status) not in {"phased out", "will be phased out"}:
        return []
    source_url = html_product_page_source_url(soup) or icp_das_source_url_from_product(model)
    title = html_page_title(soup)
    description = html_meta_content(
        soup,
        {"name": "description"},
        {"property": "og:description"},
    )
    row = status_only_product_row(
        model=model,
        product_name=f"ICP DAS {model}",
        description=icp_das_device_type(model, title, description),
        product_status=f"ICP DAS product status: {status}",
        source_table=f"{path.name} product status",
        source_hint="ICP DAS phased-out product page review import",
        source_url=source_url,
        review_policy="icp_das_product_page_phase_out_status_only",
        review_reason=(
            "ICP DAS marks this product page as phased out or planned for "
            "phase-out, but the captured product page does not publish an "
            "exact support, service, vulnerability, or security-update end "
            "date."
        ),
        aliases=[model, title, description],
    )
    return [row]


def icp_das_replacements(page_text: str) -> str:
    match = re.search(
        r"Suggested replacement device:\s*(.+?)(?:- Status:|Please refer|Product Status)",
        page_text,
        flags=re.I,
    )
    if not match:
        return ""
    text = normalize_text(match.group(1))
    text = re.sub(r"\bor\b", ";", text, flags=re.I)
    parts = [
        normalize_text(part)
        for part in re.split(r"[;,]", text)
        if normalize_text(part)
    ]
    return "; ".join(parts)


def extract_icp_das_eol_news_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("eol_news_"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "ICP DAS" not in page_text or "End of Life" not in page_text:
        return []
    model_match = re.search(r"Phased out model:\s*([A-Z0-9._+-]+)", page_text, flags=re.I)
    model = normalize_text(model_match.group(1)) if model_match else ""
    if not model:
        return []
    last_order_match = re.search(
        r"Last Order Date:\s*(\d{4}/\d{1,2}/\d{1,2})",
        page_text,
        flags=re.I,
    )
    last_order = parse_date_any(last_order_match.group(1)) if last_order_match else None
    replacement = icp_das_replacements(page_text)
    source_url = html_product_page_source_url(soup)
    row = status_only_product_row(
        model=model,
        product_name=f"ICP DAS {model}",
        description=icp_das_device_type(model, html_page_title(soup), page_text[:300]),
        product_status="ICP DAS EOL notice; manufacturing discontinued/end-of-life",
        source_table=f"{path.name} EOL news",
        source_hint="ICP DAS EOL news review import",
        source_url=source_url,
        review_policy="icp_das_eol_news_sale_only_support_continues",
        review_reason=(
            "ICP DAS announces manufacturing discontinuation and End of Life "
            "for this model and publishes a last-order date, while also saying "
            "after-sales service and technical support continue within the "
            "effective warranty period. The captured notice does not publish "
            "an exact security-update end date."
        ),
        aliases=[model, replacement],
        replacement=replacement,
    )
    if last_order:
        row["End of Sale"] = last_order
    return [row]


def extract_icp_das_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    return extract_icp_das_product_status_rows(path) + extract_icp_das_eol_news_rows(path)


NETBERG_PRODUCT_FILE_RE = re.compile(r"^product_aurora_(\d+)\.html$")
NETBERG_JULY_2025_EOL_NOTICE_URL = (
    "https://netbergtw.com/articles/2025-july-eol-notice/"
)


def netberg_product_source_url(model: str) -> str:
    slug = normalize_header(model).replace(" ", "-")
    return f"https://netbergtw.com/products/{slug}/"


def extract_netberg_product_page_rows(path: Path) -> list[dict[str, Any]]:
    if not NETBERG_PRODUCT_FILE_RE.match(path.name):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    match = re.search(r"\bEOL\s+(Aurora\s+\d+)\b", page_text, flags=re.I)
    if not match:
        return []
    model = normalize_text(match.group(1))
    source_url = html_product_page_source_url(soup) or netberg_product_source_url(model)
    row = status_only_product_row(
        model=model,
        product_name=f"Netberg {model}",
        description="Network Switch",
        product_status="Netberg product page marked EOL",
        source_table=f"{path.name} Netberg EOL product page",
        source_hint="Netberg EOL product page review import",
        source_url=source_url,
        review_policy="netberg_product_page_eol_status_only",
        review_reason=(
            "Netberg marks this product page as EOL, but the captured product "
            "page does not publish an exact support, service, vulnerability, "
            "or security-update end date."
        ),
        aliases=[model, f"Netberg {model}", source_url],
    )
    return [row]


def extract_netberg_july_2025_notice_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "article_2025_july_eol_notice.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    match = re.search(
        r"Effective\s+([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}):\s*"
        r"The following products are now End of Life \(EOL\):\s*(.+?)\.",
        page_text,
        flags=re.I,
    )
    if not match:
        return []
    eol_date = parse_date_any(match.group(1))
    models = []
    seen: set[str] = set()
    for model_match in re.finditer(r"\bAurora\s+\d+\b", match.group(2), flags=re.I):
        model = normalize_text(model_match.group(0))
        key = normalize_header(model)
        if key in seen:
            continue
        seen.add(key)
        models.append(model)
    if not eol_date or not models:
        return []

    rows = []
    for model in models:
        source_url = NETBERG_JULY_2025_EOL_NOTICE_URL
        row = status_only_product_row(
            model=model,
            product_name=f"Netberg {model}",
            description="Network Switch",
            product_status=(
                "Netberg July 2025 EOL notice; maintenance support remains "
                "available up to three years after EOL"
            ),
            source_table=f"{path.name} Netberg July 2025 EOL notice",
            source_hint="Netberg July 2025 EOL notice review import",
            source_url=source_url,
            review_policy="netberg_eol_notice_maintenance_support_continues",
            review_reason=(
                "Netberg publishes an exact EOL date for this model and says "
                "EOL products remain eligible for maintenance support up to "
                "three years after the EOL date. The notice does not publish "
                "an exact security-update end date."
            ),
            aliases=[model, f"Netberg {model}", source_url],
        )
        row["End of Life"] = eol_date
        rows.append(row)
    return rows


def extract_netberg_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    return extract_netberg_product_page_rows(path) + extract_netberg_july_2025_notice_rows(path)


def dfi_product_model(title: str) -> str:
    title = html_lib.unescape(normalize_text(title))
    for separator in ("\uff5c", "|"):
        if separator in title:
            title = title.split(separator, 1)[0]
            break
    return normalize_text(title.strip(" -"))


def dfi_device_type(title: str, description: str) -> str:
    key = normalize_header(f"{title} {description}")
    if "industrial computers" in key or "embedded system" in key:
        return "Industrial Computer"
    if "industrial motherboards" in key or "mini itx" in key or "sbc" in key:
        return "Industrial Motherboard"
    if "system on modules" in key or "com express" in key:
        return "System-on-Module"
    return status_page_device_type(f"{title} {description}")


def dfi_cpu_lifecycle_text(page_text: str) -> str:
    match = re.search(
        r"\b(?:\d+-Year\s+)?CPU Life Cycle Support Until\s+"
        r"(Q[1-4]'?\s*\d{2})(?:\s*\(Based on Intel IOTG Roadmap\))?",
        page_text,
        flags=re.I,
    )
    return normalize_text(match.group(0)) if match else ""


def extract_dfi_product_status_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if not re.search(r"\bStatus\s*:\s*EOL\b", page_text, flags=re.I):
        return []

    title = html_page_title(soup)
    model = dfi_product_model(title)
    if not model:
        return []
    description = html_meta_content(
        soup,
        {"name": "description"},
        {"property": "og:description"},
    )
    source_url = html_product_page_source_url(soup)
    cpu_lifecycle = dfi_cpu_lifecycle_text(page_text)
    status = "DFI product page status: EOL"
    if cpu_lifecycle:
        status = f"{status}; {cpu_lifecycle}"
    row = status_only_product_row(
        model=model,
        product_name=f"DFI {model}",
        description=dfi_device_type(title, description),
        product_status=status,
        source_table=f"{path.name} DFI product page status",
        source_hint="DFI EOL product page review import",
        source_url=source_url,
        review_policy="dfi_product_page_eol_status_only",
        review_reason=(
            "DFI marks this product page with Status: EOL and may show CPU "
            "life-cycle support timing based on the Intel IOTG roadmap, but "
            "the captured page does not publish an exact DFI support, service, "
            "vulnerability, or security-update end date."
        ),
        aliases=[model, title, description, source_url],
    )
    return [row]


CTC_UNION_FIELD_LABELS = (
    "EOL Model Name",
    "EOL Models",
    "Substitute Item",
    "Substitute Models",
    "Effective Date",
    "Last Buy Date",
    "Issue Date",
)


def ctc_union_clean_text(value: str) -> str:
    text = normalize_text(value)
    text = re.sub(r"[\u2010-\u2015\u2212]", "-", text)
    text = text.replace("::", ":")
    text = re.sub(r"-{2,}", "-", text)
    return normalize_text(text)


def ctc_union_field_value(lines: list[str], label: str) -> str:
    label_key = normalize_header(label)
    values: list[str] = []
    collecting = False
    for line in lines:
        line = ctc_union_clean_text(line)
        header = normalize_header(line)
        if not collecting:
            if not header.startswith(label_key):
                continue
            collecting = True
            remainder = re.sub(
                rf"^{re.escape(label)}s?\s*:?\s*",
                "",
                line,
                flags=re.I,
            )
            if remainder:
                values.append(remainder)
            continue

        if not line:
            break
        if any(
            normalize_header(line).startswith(normalize_header(other))
            for other in CTC_UNION_FIELD_LABELS
            if normalize_header(other) != label_key
        ):
            break
        if "please confirm" in header or "dear valued" in header:
            break
        values.append(line)
    return ctc_union_clean_text(" ".join(values))


def parse_ctc_union_date(value: str) -> str | None:
    text = ctc_union_clean_text(value)
    if not text or normalize_header(text) in {"n a", "na", "none", "not available"}:
        return None
    text = re.sub(r"\bNone(?=\d)", " ", text)
    text = re.sub(r"\b(\d{1,2})(?:st|nd|rd|th)\b", r"\1", text, flags=re.I)
    text = text.replace("..", ".")
    text = re.sub(r"\b([A-Za-z]{3,})\.(?=\d)", r"\1. ", text)
    text = re.sub(
        r"\b([A-Za-z]{3,})\.\s*(\d{1,2})\.\s*(\d{4})\b",
        r"\1 \2, \3",
        text,
    )
    text = re.sub(
        r"\b([A-Za-z]{3,})\.\s*(\d{1,2})\s+(\d{4})\b",
        r"\1 \2, \3",
        text,
    )
    text = re.sub(r"\b([A-Za-z]{3,})\.\s*(\d{1,2}),", r"\1 \2,", text)
    text = re.sub(r"\b([A-Za-z]{3,})\.\s*(\d{4})\b", r"\1 \2", text)
    return parse_date_any(text)


def ctc_union_model_token(value: str) -> str:
    text = ctc_union_clean_text(value).strip(" ,;")
    text = re.sub(r"^[A-Z]{2,}\s+(?=[A-Z0-9][A-Za-z0-9+/-]*\d)", "", text)
    text = text.strip(" ,;")
    has_digit = bool(re.search(r"\d", text))
    has_model_separator = bool(re.search(r"[-_/]", text)) and len(text) >= 6
    if not (has_digit or has_model_separator) or len(text) < 4:
        return ""
    return text


def ctc_union_split_model_values(value: str) -> list[str]:
    text = ctc_union_clean_text(value)
    if not text:
        return []
    if "(" in text and ")" in text and "," in text[text.find("(") : text.find(")")]:
        token = ctc_union_model_token(text)
        return [token] if token else []
    else:
        candidates = [
            item
            for item in re.split(r"\s*,\s*", text)
            if item and item.lower() not in {"n/a", "none"}
        ]

    tokens: list[str] = []
    token_re = re.compile(
        r"(?<![A-Za-z0-9])(?:"
        r"[A-Z][A-Za-z0-9+]*(?:[-_/][A-Za-z0-9()+.]+)+|"
        r"[A-Z]+[A-Za-z]*\d[A-Za-z0-9()+./-]*|"
        r"\d+[A-Za-z0-9]+-[A-Za-z0-9()+.]+"
        r")(?=$|[\s,;])"
    )
    for candidate in candidates:
        pieces = [match.group(0) for match in token_re.finditer(candidate)]
        if len(pieces) == 2 and pieces[0].endswith(pieces[1].split("-", 1)[0]):
            overlap = pieces[1].split("-", 1)[0]
            pieces = [pieces[0][: -len(overlap)] + pieces[1]]
        if pieces:
            for piece in pieces:
                token = ctc_union_model_token(piece)
                if token:
                    tokens.append(token)
            continue
        token = ctc_union_model_token(candidate)
        if token:
            tokens.append(token)

    result: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        key = normalize_header(token)
        if key and key not in seen:
            result.append(token)
            seen.add(key)
    return result


def ctc_union_clean_replacement(value: str) -> str:
    text = ctc_union_clean_text(value).strip(" -;,")
    if normalize_header(text) in {"n a", "na", "none", "not available"}:
        return ""
    kept: list[str] = []
    for part in text.split():
        if kept and kept[-1].endswith(part):
            continue
        kept.append(part)
    return ctc_union_clean_text(" ".join(kept)).strip(" -;,")


def ctc_union_device_type(model: str) -> str:
    key = normalize_header(model)
    if any(token in key for token in ("gsw", "ifs", "igs", "ics", "fsw", "switch")):
        return "Industrial Ethernet Switch"
    if any(token in key for token in ("frm", "fmc", "fth", "fib", "eoc", "vdtu")):
        return "Industrial Media Converter"
    if any(token in key for token in ("icr", "gw")):
        return "Industrial Router"
    return "Industrial Network Device"


def parse_ctc_union_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if not source_name.lower().startswith("ctc_union_eol"):
        return []
    if source_name == "ctc_union_eol-notice_frm220-1000eas_x-1series.pdf":
        return []
    normalized = normalize_header(text)
    if (
        "eol notification" not in normalized
        and "end of life notice" not in normalized
        and "upcoming end of life" not in normalized
    ):
        return []
    if "eol model" not in normalized:
        return []

    lines = text.splitlines()
    issue_date = parse_ctc_union_date(ctc_union_field_value(lines, "Issue Date"))
    model_value = (
        ctc_union_field_value(lines, "EOL Model Name")
        or ctc_union_field_value(lines, "EOL Models")
    )
    models = ctc_union_split_model_values(model_value)
    if not models:
        return []

    substitute = (
        ctc_union_field_value(lines, "Substitute Item")
        or ctc_union_field_value(lines, "Substitute Models")
    )
    effective_date = parse_ctc_union_date(ctc_union_field_value(lines, "Effective Date"))
    last_buy_date = parse_ctc_union_date(ctc_union_field_value(lines, "Last Buy Date"))
    end_of_sale = last_buy_date or effective_date
    if not end_of_sale:
        return []

    replacement = ctc_union_clean_replacement(substitute)

    rows: list[dict[str, Any]] = []
    for model in models:
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"CTC Union {model}",
            "Description": ctc_union_device_type(model),
            "Product Status": (
                "CTC Union product EOL/discontinuation notice; "
                f"effective date {effective_date or 'not stated'}; "
                f"last buy date {last_buy_date or 'not stated'}"
            ),
            "End of Sale": end_of_sale,
            "Lifecycle Status Source": source_name,
            "_source_table": f"{source_name} Product EOL Notification",
            "_source_hint": "CTC Union product EOL notification PDF import",
            "_review_policy": "ctc_union_eol_discontinuation_not_support_end",
            "_review_reason": (
                "The CTC Union notice identifies product EOL/discontinuation "
                "and last-buy/effective sales milestones, but does not publish "
                "an exact support, service, vulnerability, firmware, or "
                "security-update end date."
            ),
            "_aliases": [model, f"CTC Union {model}"],
            "_force_lifecycle_review": True,
            "_suppress_description_aliases": True,
            "_prefer_model": True,
        }
        if issue_date:
            row["Announcement Date"] = issue_date
        if replacement:
            row["Replacement"] = replacement
        rows.append(row)
    return rows


GARLAND_EOL_SOURCE_DESCRIPTIONS = {
    "EOL_EOS_Letter_AdvancedFeatures_2023.pdf": "PacketMax Advanced Features packet broker",
    "EOL_EOS_Letter_EdgeSafe_2023.pdf": "EdgeSafe bypass modular network TAP",
    "GarlandTechnology_AdvancedAggregators_EOL_Announcement-Letter.pdf": "Network packet broker",
    "GT-EOL_EOS_Letter_FABv2.pdf": "Filtering aggregating load balancer",
    "GT-EOL_EOS_Letter_INT.pdf": "EdgeLens inline security packet broker",
    "GT-EOL_EOS_Letter_M10G.pdf": "EdgeSafe 10G bypass modular network TAP",
}


def garland_part_numbers_between(lines: list[str], start_pattern: str, end_pattern: str) -> list[str]:
    collecting = False
    parts: list[str] = []
    for line in lines:
        text = normalize_text(line)
        header = normalize_header(text)
        if not collecting:
            if start_pattern in header:
                collecting = True
            continue
        if end_pattern in header:
            break
        for match in re.finditer(
            r"(?<![A-Za-z0-9])([A-Z]{1,5}[A-Za-z0-9+-]{3,})(?=$|[\s,;:])",
            text,
        ):
            token = match.group(1)
            if re.search(r"\d", token) and normalize_header(token) not in {
                "numbers",
                "product",
            }:
                parts.append(token)
    return list(dict.fromkeys(parts))


def garland_date_from_line(line: str) -> str | None:
    date_match = re.search(
        r"\b(?:\d{1,2}/\d{1,2}/\d{4}|[A-Za-z]+\s+\d{1,2},\s+\d{4})\b",
        normalize_text(line),
    )
    return parse_date_any(date_match.group(0)) if date_match else None


def garland_dates_in_window(lines: list[str]) -> dict[str, str | None]:
    dates = {"eol": None, "eos": None, "support": None}
    for line in lines:
        header = normalize_header(line)
        parsed = garland_date_from_line(line)
        if not parsed:
            continue
        if "end of support" in header:
            dates["support"] = dates["support"] or parsed
        elif "end of sales" in header or "end of sales date" in header:
            dates["eos"] = dates["eos"] or parsed
        elif "end of life end of sales" in header:
            dates["eos"] = dates["eos"] or parsed
        elif "end of life" in header:
            dates["eol"] = dates["eol"] or parsed
    return dates


def parse_garland_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    description = GARLAND_EOL_SOURCE_DESCRIPTIONS.get(source_name)
    if not description:
        return []
    normalized = normalize_header(text)
    if "eol eos announcement" not in normalized or "garland part numbers affected" not in normalized:
        return []

    lines = text.splitlines()
    parts = garland_part_numbers_between(lines, "end of life part", "key dates")
    if not parts:
        return []

    part_dates: dict[str, dict[str, str | None]] = {}
    if source_name == "EOL_EOS_Letter_AdvancedFeatures_2023.pdf":
        first_index = next(
            (index for index, line in enumerate(lines) if normalize_text(line) == "AF1G40AC"),
            -1,
        )
        second_index = next(
            (
                index
                for index, line in enumerate(lines)
                if "AF1G40DC" in normalize_text(line)
                and "AF100G4DCE" in normalize_text(line)
            ),
            -1,
        )
        if first_index >= 0:
            part_dates["AF1G40AC"] = garland_dates_in_window(lines[first_index : first_index + 10])
        if second_index >= 0:
            grouped = garland_dates_in_window(lines[second_index : second_index + 12])
            for part in parts:
                if part != "AF1G40AC":
                    part_dates[part] = grouped
    else:
        dates = garland_dates_in_window(lines)
        for part in parts:
            part_dates[part] = dates

    rows: list[dict[str, Any]] = []
    for part in parts:
        dates = part_dates.get(part) or {}
        end_of_sale = dates.get("eos") or dates.get("eol")
        end_of_support = dates.get("support")
        if not end_of_sale and not end_of_support:
            continue
        row: dict[str, Any] = {
            "Model": part,
            "Part Number": part,
            "Product Name": f"Garland Technology {part}",
            "Description": description,
            "Product Status": (
                "Garland Technology EOL/EOS announcement; "
                f"end of sale {end_of_sale or 'not stated'}; "
                f"end of support {end_of_support or 'not stated'}"
            ),
            "Lifecycle Status Source": source_name,
            "_source_table": f"{source_name} Garland Part Numbers affected",
            "_source_hint": "Garland Technology EOL/EOS announcement PDF import",
            "_review_policy": (
                "garland_eol_eos_with_support_date"
                if end_of_support
                else "garland_eol_eos_without_support_date"
            ),
            "_aliases": [part, f"Garland {part}", f"Garland Technology {part}"],
            "_suppress_description_aliases": True,
            "_prefer_model": True,
        }
        if end_of_sale:
            row["End of Sale"] = end_of_sale
        if end_of_support:
            row["End of Support"] = end_of_support
            if dates.get("eol"):
                row["End of Life"] = dates["eol"]
        else:
            row["_force_lifecycle_review"] = True
            row["_review_reason"] = (
                "The Garland Technology notice publishes EOL/EOS sales "
                "milestones but does not publish an exact support, service, "
                "vulnerability, firmware, or security-update end date."
            )
        rows.append(row)
    return rows


MATROX_VIDEO_EOL_PAGES = {
    "matrox_maevex_5100_series.html": {
        "model": "Maevex 5100 Series",
        "h1": "Maevex 5100 Series Encoder & Decoder",
        "description": "Video encoder/decoder appliance",
        "replacements": ["Maevex 6100 Series"],
    },
    "matrox_maevex_6020_remote_recorder.html": {
        "model": "Maevex 6020 Remote Recorder",
        "h1": "Maevex 6020 Remote Recorder",
        "description": "Video recorder appliance",
        "replacements": ["Maevex 7100 Series", "Maevex 6100 Series"],
    },
    "matrox_monarch_hd.html": {
        "model": "Monarch HD",
        "h1": "Monarch HD Encoder Appliance",
        "description": "Video encoder appliance",
        "replacements": ["Maevex 7100 Series", "Monarch LCS"],
    },
    "matrox_monarch_hdx.html": {
        "model": "Monarch HDX",
        "h1": "Monarch HDX Encoder Appliance",
        "description": "Video encoder appliance",
        "replacements": ["Maevex 7100 Series", "Monarch LCS"],
    },
}


def extract_matrox_video_eol_rows(path: Path) -> list[dict[str, Any]]:
    config = MATROX_VIDEO_EOL_PAGES.get(path.name)
    if not config:
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = html_lib.unescape(normalize_text(soup.get_text(" ", strip=True)))
    model = str(config["model"])
    if (
        "Matrox Video has publicly announced end-of-life (EOL) notification"
        not in text
        or model not in text
    ):
        return []

    notice_match = re.search(
        r"publicly announced end-of-life \(EOL\) notification in "
        r"([A-Za-z]+)\s+of\s+(\d{4})\s+for\s+the\s+(.+?)(?:\.| and )",
        text,
        flags=re.I,
    )
    if not notice_match:
        return []
    notice_month = f"{notice_match.group(1)} {notice_match.group(2)}"

    last_buy_match = re.search(
        r"Last time buy orders of this product will be accepted until "
        r"([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    last_sale = parse_date_any(last_buy_match.group(1)) if last_buy_match else None

    sold_out = "this product is sold out" in text.lower()
    status_parts = [
        f"Matrox Video announced EOL notification in {notice_month} for {model}",
    ]
    if last_sale:
        status_parts.append(f"last time buy orders accepted until {last_sale}")
    elif sold_out:
        status_parts.append("product is sold out")

    replacement = "; ".join(str(item) for item in config["replacements"])
    row = status_only_product_row(
        model=model,
        product_name=f"Matrox {model}",
        description=str(config["description"]),
        product_status="; ".join(status_parts),
        source_table=f"{path.name} product EOL notice",
        source_hint="Matrox Video product-page EOL notification import",
        source_url=html_product_page_source_url(soup),
        review_policy="matrox_video_eol_notification_status_only",
        review_reason=(
            "Matrox Video product page announces an EOL notification and may "
            "state last-buy or sold-out status, but it does not publish an "
            "exact support, service, vulnerability, firmware, or "
            "security-update end date."
        ),
        aliases=[model, f"Matrox {model}", str(config["h1"])],
        replacement=replacement,
    )
    if last_sale:
        row["End of Sale"] = last_sale
    row["_suppress_description_aliases"] = True
    row["_remove_aliases"] = [f"Matrox Video Matrox {model}"]
    return [row]


def wago_parse_ddmmyyyy_date(value: str) -> str | None:
    match = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4})", normalize_text(value))
    if not match:
        return None
    day, month, year = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def extract_wago_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []
    html = path.read_text(encoding="utf-8", errors="ignore")
    if "This item has been discontinued" not in html:
        return []

    soup = BeautifulSoup(html, "lxml")
    title = first_h1_text(soup)
    item_match = re.search(r"\bItem no\.\s*([0-9][0-9A-Za-z/-]+)", soup.get_text(" ", strip=True))
    item_no = normalize_text(item_match.group(1)) if item_match else ""
    if not item_no:
        product_code = normalize_text(
            (soup.find(attrs={"product-code": True}) or {}).get("product-code")
        )
        item_no = product_code
    if not item_no or not title:
        return []

    alert = ""
    alert_node = soup.find("wg-alert", attrs={"message": True})
    if alert_node:
        alert = html_lib.unescape(normalize_text(alert_node.get("message")))
    if not alert or "discontinued" not in alert.lower():
        return []

    end_of_sale = None
    unavailable_match = re.search(
        r"no longer available as of\s+(\d{2}/\d{2}/\d{4})",
        alert,
        flags=re.I,
    )
    if unavailable_match and '"events.date.pattern":"dd/MM/yyyy"' in html:
        end_of_sale = wago_parse_ddmmyyyy_date(unavailable_match.group(1))

    source_url = html_product_page_source_url(soup)
    row = status_only_product_row(
        model=item_no,
        product_name=f"WAGO {item_no}",
        description=title,
        product_status=(
            f"{alert}; product page title: {title}"
            if title not in alert
            else alert
        ),
        source_table=f"{path.name} discontinued product page",
        source_hint="WAGO discontinued product-page import",
        source_url=source_url,
        review_policy="wago_discontinued_product_page_status_only",
        review_reason=(
            "WAGO product page marks this exact item number discontinued and "
            "may state a no-longer-available date, but it does not publish an "
            "exact support, service, vulnerability, firmware, or "
            "security-update end date."
        ),
        aliases=[item_no, f"WAGO {item_no}"],
    )
    if end_of_sale:
        row["End of Sale"] = end_of_sale
    row["_suppress_description_aliases"] = True
    return [row]


def ctsystem_schedule_date(schedule: str, label: str) -> str | None:
    match = re.search(rf"{re.escape(label)}:\s*([0-9]{{1,2}}-[A-Za-z]{{3}}-[0-9]{{4}})", schedule)
    return parse_date_any(match.group(1)) if match else None


def ctsystem_model_list(value: str) -> list[str]:
    models = re.findall(
        r"\b[A-Z]{2,}[A-Z0-9]*(?:-[A-Z0-9]+)+(?:/[A-Z0-9-]+)?\b",
        normalize_text(value),
    )
    return list(dict.fromkeys(models))


def extract_ctsystem_fos_ies_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "eol_202008001_fos_5126_ies_3106.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if (
        "Product End-of-Life Notice: FOS-5126 and IES-3106" not in text
        or "End-of-Service date is the date after which any type of technical support"
        not in text
    ):
        return []

    table = soup.find("table")
    if not table:
        return []
    rows = [
        [cell.get_text(" ", strip=True) for cell in tr.find_all(["th", "td"])]
        for tr in table.find_all("tr")
    ]
    if len(rows) < 4 or rows[0][:3] != ["Product Family", "FOS-5126", "IES-3106"]:
        return []

    source_url = html_product_page_source_url(soup)
    result: list[dict[str, Any]] = []
    for column in (1, 2):
        family = rows[0][column]
        phase_models = ctsystem_model_list(rows[1][column])
        alternatives = ctsystem_model_list(rows[2][column])
        schedule = normalize_text(rows[3][column])
        announcement = ctsystem_schedule_date(schedule, "EOL Notification")
        end_of_sale = ctsystem_schedule_date(schedule, "Last Time Order Date")
        end_of_service = ctsystem_schedule_date(schedule, "End of Service Date*")
        if not phase_models or not end_of_service:
            continue

        for model in phase_models:
            row = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"CTS {model}",
                "Description": "Network Switch",
                "Product Status": (
                    f"Product family {family} phase-out; {schedule}; "
                    "End-of-Service means technical support will no longer be available"
                ),
                "Lifecycle Status Source": path.name,
                "_source_table": f"{path.name} Phase-out Model List",
                "_source_hint": "CTS FOS-5126 and IES-3106 EOL announcement import",
                "_source_url": source_url,
                "_review_policy": "ctsystem_end_of_service_no_technical_support",
                "_review_reason": (
                    "CTS defines End-of-Service as the date after which any "
                    "type of technical support, including manufactured, "
                    "improved, repaired, or maintained support, is no longer "
                    "available."
                ),
                "_aliases": [model, f"CTS {model}", f"CTSystem {model}"],
                "_remove_aliases": [f"Ctsystem CTS {model}"],
                "_suppress_description_aliases": True,
                "_prefer_model": True,
            }
            if alternatives:
                row["Replacement"] = "; ".join(alternatives)
            if announcement:
                row["Announcement Date"] = announcement
            if end_of_sale:
                row["End of Sale"] = end_of_sale
            row["End of Service"] = end_of_service
            result.append(row)
    return result


CTSYSTEM_EOL_PRODUCTS_PDF = "end_of_life_products_v1_9_02112026.pdf"
CTSYSTEM_PDF_DATE_RE = re.compile(r"\d{1,4}/\d{1,2}/\d{1,4}")
CTSYSTEM_PDF_MODEL_RE = re.compile(
    r"(?<![A-Z0-9])("
    r"[A-Z]{3,}[A-Z0-9]*(?:-[A-Z0-9]+)*"
    r"(?:\([A-Z0-9./~-]+\))?"
    r"(?:-[A-Z0-9]+)*(?:~[A-Z0-9]+)?"
    r"(?:\s+version\s+[A-Z])?"
    r")(?=\s|$)"
)


def ctsystem_pdf_model_column(line: str) -> str:
    return line[42:86] if len(line) > 42 else ""


def ctsystem_pdf_series_column(line: str) -> str:
    return line[22:42] if len(line) > 22 else ""


def ctsystem_pdf_model_candidates(value: str) -> list[str]:
    result: list[str] = []
    for match in CTSYSTEM_PDF_MODEL_RE.finditer(value):
        model = match.group(1).strip()
        if model == "EOL":
            continue
        if "-" not in model and not any(char.isdigit() for char in model):
            continue
        if model not in result:
            result.append(model)
    return result


def ctsystem_pdf_line_models(line: str) -> list[str]:
    return ctsystem_pdf_model_candidates(ctsystem_pdf_model_column(line))


def ctsystem_pdf_series_tokens(line: str) -> list[str]:
    column = ctsystem_pdf_series_column(line)
    candidates = ctsystem_pdf_model_candidates(column)
    if candidates:
        return candidates
    stripped = column.strip()
    if re.search(r"\b[A-Z]{3,}[A-Z0-9]*-?\d", stripped):
        return [stripped]
    return []


def ctsystem_pdf_series_signature(series: str) -> list[str]:
    cleaned = re.sub(r"\s+ver:.*", "", series).split()[0]
    return [part for part in re.split(r"[-_]+", cleaned) if part and part != "ver"]


def ctsystem_pdf_model_matches_series(model: str, series: str) -> bool:
    position = 0
    for token in ctsystem_pdf_series_signature(series):
        found = model.find(token, position)
        if found < 0:
            return False
        position = found + len(token)
    return True


def ctsystem_pdf_line_matches_series(line: str, series: str) -> bool:
    return any(
        ctsystem_pdf_model_matches_series(model, series)
        for model in ctsystem_pdf_line_models(line)
    )


def ctsystem_pdf_has_lifecycle_date(line: str) -> bool:
    return any(match.start() > 100 for match in CTSYSTEM_PDF_DATE_RE.finditer(line))


def ctsystem_pdf_has_service_date(line: str) -> bool:
    dates = [
        (match.group(0), match.start())
        for match in CTSYSTEM_PDF_DATE_RE.finditer(line)
        if match.start() > 100
    ]
    if not dates:
        return False
    if len(dates) >= 3:
        return True
    return dates[-1][1] >= 145 or (len(dates) == 2 and dates[-1][1] >= 140)


def ctsystem_pdf_take_trailing_series_lines(
    lines: list[str],
    series: str,
) -> list[str]:
    last_date_index = -1
    for index, line in enumerate(lines):
        if ctsystem_pdf_has_lifecycle_date(line):
            last_date_index = index

    cut_index: int | None = None
    for index in range(last_date_index + 1, len(lines)):
        if ctsystem_pdf_line_matches_series(lines[index], series):
            cut_index = index
            break
    if cut_index is None:
        return []

    moved = lines[cut_index:]
    del lines[cut_index:]
    return moved


def ctsystem_pdf_group_dates(lines: list[str]) -> tuple[str | None, str | None, str] | None:
    group_text = " ".join(lines).lower()
    if "(s/w)" in group_text or "(support)" in group_text:
        return None

    announcement: str | None = None
    end_of_sale: str | None = None
    end_of_service: str | None = None
    for line in lines:
        dates = [
            (match.group(0), match.start())
            for match in CTSYSTEM_PDF_DATE_RE.finditer(line)
            if match.start() > 100
        ]
        if not dates:
            continue

        service_dash = bool(re.search(r"\s-\s*$", line))
        if len(dates) >= 3:
            announcement = announcement or parse_date_any(dates[-3][0], dayfirst=False)
            end_of_sale = end_of_sale or parse_date_any(dates[-2][0], dayfirst=False)
            if not service_dash:
                end_of_service = end_of_service or parse_date_any(
                    dates[-1][0],
                    dayfirst=False,
                )
        elif len(dates) == 2:
            (first_date, first_position), (second_date, second_position) = dates
            if service_dash:
                announcement = announcement or parse_date_any(first_date, dayfirst=False)
                end_of_sale = end_of_sale or parse_date_any(second_date, dayfirst=False)
                continue
            if second_position >= 140:
                end_of_service = end_of_service or parse_date_any(
                    second_date,
                    dayfirst=False,
                )
                if first_position < 130 and second_position >= 150:
                    announcement = announcement or parse_date_any(
                        first_date,
                        dayfirst=False,
                    )
                else:
                    end_of_sale = end_of_sale or parse_date_any(
                        first_date,
                        dayfirst=False,
                    )
        else:
            date_text, position = dates[0]
            if service_dash:
                continue
            parsed = parse_date_any(date_text, dayfirst=False)
            if position >= 145:
                end_of_service = end_of_service or parsed
            elif position >= 130:
                end_of_sale = end_of_sale or parsed
            elif position >= 110:
                announcement = announcement or parsed

    if not end_of_service:
        return None
    if not announcement and not end_of_sale and "immediately" not in group_text:
        return None
    return announcement, end_of_sale, end_of_service


def parse_ctsystem_eol_products_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    if source_name != CTSYSTEM_EOL_PRODUCTS_PDF:
        return []
    if "End of Life Products" not in text or "Phase-out Models" not in text:
        return []

    groups: list[dict[str, Any]] = []
    current_group: dict[str, Any] | None = None
    pending_lines: list[str] = []

    def finish_group(group: dict[str, Any] | None) -> None:
        if not group:
            return
        models: list[str] = []
        for group_line in group["lines"]:
            for model in ctsystem_pdf_line_models(group_line):
                if model not in models:
                    models.append(model)
        dates = ctsystem_pdf_group_dates(group["lines"])
        if models and dates:
            groups.append(
                {
                    "series": group["series"],
                    "models": models,
                    "dates": dates,
                }
            )

    for raw_line in text.splitlines():
        line = raw_line.replace("\f", "")
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("Last update")
            or stripped.startswith("Taiwan")
            or "ctsystem.com" in stripped
            or stripped.startswith("+886")
            or stripped == "End of Life Products"
            or stripped.startswith("EOL#")
        ):
            continue

        series_tokens = ctsystem_pdf_series_tokens(line)
        if (
            re.search(r"EOL-[0-9]{6,}", line)
            and not ctsystem_pdf_line_models(line)
            and not series_tokens
            and not ctsystem_pdf_has_service_date(line)
        ):
            continue

        if series_tokens:
            moved_lines: list[str] = []
            if current_group is not None:
                moved_lines = ctsystem_pdf_take_trailing_series_lines(
                    current_group["lines"],
                    series_tokens[0],
                )
                finish_group(current_group)
            current_group = {
                "series": series_tokens[0],
                "lines": moved_lines + pending_lines + [line],
            }
            pending_lines = []
        elif current_group is not None:
            current_group["lines"].append(line)
        elif ctsystem_pdf_line_models(line):
            pending_lines.append(line)

    finish_group(current_group)

    rows: list[dict[str, Any]] = []
    for group in groups:
        announcement, end_of_sale, end_of_service = group["dates"]
        for model in group["models"]:
            row: dict[str, Any] = {
                "Model": model,
                "Part Number": model,
                "Product Name": f"CTS {model}",
                "Description": "Network Switch",
                "Product Status": (
                    "CTS End of Life Products PDF; "
                    f"phase-out series {group['series']}; "
                    f"end of sale {end_of_sale or 'not stated'}; "
                    f"end of service {end_of_service}"
                ),
                "Lifecycle Status Source": source_name,
                "_source_table": (
                    f"{source_name} End of Life Products phase-out model table"
                ),
                "_source_hint": "CTS End of Life Products PDF import",
                "_review_policy": "ctsystem_end_of_service_no_technical_support",
                "_review_reason": (
                    "CTS defines End-of-Service as the date after which any "
                    "type of technical support, including manufactured, "
                    "improved, repaired, or maintained support, is no longer "
                    "available. This parser imports only exact phase-out "
                    "models with a clean End of Service date in the PDF table."
                ),
                "_aliases": [model, f"CTS {model}", f"CTSystem {model}"],
                "_remove_aliases": [f"Ctsystem CTS {model}"],
                "_suppress_description_aliases": True,
                "_prefer_model": True,
            }
            if announcement:
                row["Announcement Date"] = announcement
            if end_of_sale:
                row["End of Sale"] = end_of_sale
            row["End of Service"] = end_of_service
            rows.append(row)
    return rows


RICOH_DISCONTINUED_STATUS_URLS = {
    "discontinued_color_laser_printers.html": (
        "https://www.ricoh.co.jp/products/discontinued/laser-printer-color"
    ),
    "discontinued_geljet_printers.html": (
        "https://www.ricoh.co.jp/products/discontinued/geljet-printer"
    ),
    "discontinued_monochrome_laser_printers.html": (
        "https://www.ricoh.co.jp/products/discontinued/laser-printer-mono"
    ),
    "discontinued_other_printers.html": (
        "https://www.ricoh.co.jp/products/discontinued/other-printer"
    ),
    "discontinued_printer_all_in_one.html": (
        "https://www.ricoh.co.jp/products/discontinued/printer-all-in-one"
    ),
}


def ricoh_discontinued_description(path_name: str, page_title: str) -> str:
    if "color" in path_name:
        return "Color laser printer"
    if "monochrome" in path_name:
        return "Monochrome laser printer"
    if "geljet" in path_name:
        return "GelJet printer"
    if "all_in_one" in path_name:
        return "Printer all-in-one"
    if "other" in path_name:
        return "Printer"
    if "カラーレーザー" in page_title:
        return "Color laser printer"
    if "モノクロレーザー" in page_title:
        return "Monochrome laser printer"
    if "ジェルジェット" in page_title:
        return "GelJet printer"
    if "複合機" in page_title:
        return "Printer all-in-one"
    return "Printer"


def ricoh_grouped_model_aliases(model: str) -> list[str]:
    aliases = [model]
    if "/" not in model:
        return aliases

    parts = [normalize_text(part) for part in model.split("/") if normalize_text(part)]
    if not parts:
        return aliases
    first = parts[0]
    aliases.append(first)
    words = first.split()
    if len(words) < 2:
        aliases.extend(parts[1:])
        return sorted(set(aliases))

    prefix_before_code = " ".join(words[:-1]) + " "
    brand_prefix = " ".join(words[:-2]) + " " if len(words) >= 3 else ""
    series_token = words[-2] if len(words) >= 2 else ""
    first_code = words[-1]
    code_alpha_match = re.match(r"([A-Za-z]+)-?\d", first_code)
    code_alpha = code_alpha_match.group(1) if code_alpha_match else ""
    brand_re = re.compile(r"^(?:RICOH|IPSiO|IPSIO|PC LASER)\b", flags=re.I)

    for part in parts[1:]:
        if brand_re.match(part):
            aliases.append(part)
            continue
        if (
            brand_prefix
            and series_token
            and not re.search(r"\d", series_token)
            and part.upper().startswith(series_token.upper())
        ):
            aliases.append(normalize_text(f"{brand_prefix}{part}"))
            continue
        if code_alpha and re.match(r"^\d", part):
            aliases.append(normalize_text(f"{prefix_before_code}{code_alpha}{part}"))
            continue
        aliases.append(normalize_text(f"{prefix_before_code}{part}"))
    return sorted(set(alias for alias in aliases if alias))


def extract_ricoh_discontinued_printer_rows(path: Path) -> list[dict[str, Any]]:
    if path.name not in RICOH_DISCONTINUED_STATUS_URLS:
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    if "販売終了品" not in title:
        return []

    description = ricoh_discontinued_description(path.name, title)
    source_url = html_product_page_source_url(soup) or RICOH_DISCONTINUED_STATUS_URLS[path.name]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cell in soup.select("td.c-products__name"):
        model = normalize_text(cell.get_text(" ", strip=True))
        if not model or model.lower() in seen:
            continue
        if not re.search(r"\d", model) and "Handy Printer" not in model:
            continue
        seen.add(model.lower())
        rows.append(
            status_only_product_row(
                model=model,
                product_name=model,
                description=description,
                product_status="Sales-ended product list (販売終了品)",
                source_table=f"{path.name} product name cells",
                source_hint="Ricoh discontinued printer product list import",
                source_url=source_url,
                review_policy="ricoh_discontinued_sales_ended_status_only",
                review_reason=(
                    "Ricoh lists this exact printer product on an official "
                    "sales-ended product page (販売終了品), but the captured page "
                    "does not publish an exact support, repair-service, "
                    "firmware, vulnerability, or security-update end date."
                ),
                aliases=ricoh_grouped_model_aliases(model),
            )
        )
        rows[-1]["_suppress_description_aliases"] = True
    return rows


IP_COM_EOL_PRODUCTS_URL = "https://www.ip-com.com.cn/us/eol/default.html"


def ip_com_clean_eol_model(value: str) -> tuple[str, str]:
    text = normalize_text(value)
    text = re.sub(r"\((?:EOL|End of Life)\)", " ", text, flags=re.I)
    text = normalize_text(text)
    version = ""
    version_match = re.search(r"\b(v\d+(?:\.\d+)?)\b$", text, flags=re.I)
    if version_match:
        version = version_match.group(1)
    return text, version


def ip_com_skip_eol_model(model: str, description: str) -> bool:
    key = normalize_header(model)
    desc = normalize_header(description)
    if key in {"b", "test2", "profi", "openvpn client"}:
        return True
    if desc in {"b", "test", "oneword show vv"}:
        return True
    if not re.search(r"\d", model) and not (
        key.startswith("iuap ") or key.startswith("i uap ")
    ):
        return True
    return False


def extract_ip_com_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "ip_com_us_end_of_life_products.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "EOL-IP-COM" not in title or "IP-COM End of Life Products" not in page_text:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table)
        if not matrix:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        if "models" not in headers or "description" not in headers:
            continue
        model_index = headers.index("models")
        description_index = headers.index("description")
        for table_row in matrix[1:]:
            if len(table_row) <= max(model_index, description_index):
                continue
            raw_model = normalize_text(table_row[model_index])
            description = normalize_text(table_row[description_index])
            model, version = ip_com_clean_eol_model(raw_model)
            if not model or model.lower() in seen:
                continue
            if ip_com_skip_eol_model(model, description):
                continue
            seen.add(model.lower())
            row = status_only_product_row(
                model=model,
                product_name=f"IP-COM {model}",
                description=status_page_device_type(f"{model} {description}"),
                product_status="End of Life products table",
                source_table=f"{path.name} table {table_index}",
                source_hint="IP-COM End of Life products table import",
                source_url=IP_COM_EOL_PRODUCTS_URL,
                review_policy="ip_com_eol_products_table_status_only",
                review_reason=(
                    "IP-COM lists this exact model on its End of Life Products "
                    "table, but the captured page does not publish an exact "
                    "support, service, vulnerability, firmware, or "
                    "security-update end date."
                ),
                aliases=[model, raw_model],
            )
            if version:
                row["Hardware Version"] = version
            row["_suppress_description_aliases"] = True
            rows.append(row)
    return rows


THECUS_LINUX_ARCHIVE_URL = "https://www.thecus.com/Linux-archive"
THECUS_ARCHIVE_CAT_TYPES = {
    "linux_archive_large_business_rackmount.json": "largeBusinessRackmount",
    "linux_archive_large_business_tower.json": "largeBusinessTower",
    "linux_archive_smb_rackmount.json": "smbRackmount",
    "linux_archive_smb_tower.json": "smbTower",
    "linux_archive_soho_home.json": "sohoHome",
    "linux_archive_special_bundle.json": "specialBundles",
}


def thecus_archive_description(path_name: str) -> str:
    if "special_bundle" in path_name:
        return "NAS special bundle"
    if "rackmount" in path_name:
        return "Rackmount NAS"
    if "tower" in path_name:
        return "Tower NAS"
    if "soho_home" in path_name:
        return "SOHO/Home NAS"
    return "NAS"


def extract_thecus_nas_archive_rows(path: Path) -> list[dict[str, Any]]:
    cat_type = THECUS_ARCHIVE_CAT_TYPES.get(path.name)
    if not cat_type:
        return []
    try:
        data = load_json(path)
    except Exception:
        return []
    if not isinstance(data, list):
        return []

    description = thecus_archive_description(path.name)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        model = normalize_text(item.get("PROD_NAME"))
        product_id = normalize_text(item.get("PROD_ID"))
        if not model or model.lower() in seen:
            continue
        seen.add(model.lower())
        source_url = (
            f"https://www.thecus.com/product?cat=linux_nas&cat_type={cat_type}&PROD_ID={product_id}"
            if product_id
            else THECUS_LINUX_ARCHIVE_URL
        )
        row = status_only_product_row(
            model=model,
            product_name=f"Thecus {model}",
            description=description,
            product_status="Linux NAS archive product list",
            source_table=path.name,
            source_hint="Thecus Linux NAS archive product list import",
            source_url=source_url,
            review_policy="thecus_linux_nas_archive_status_only",
            review_reason=(
                "Thecus lists this exact NAS product in its Linux NAS Archive, "
                "but the captured source does not publish an exact support, "
                "service, vulnerability, firmware, or security-update end date."
            ),
            aliases=[model],
        )
        row["_suppress_description_aliases"] = True
        rows.append(row)
    return rows


BIRDDOG_PREVIOUS_LINES_URL = "https://birddog.tv/previous-lines/"


def birddog_previous_lines_aliases(model: str) -> list[str]:
    aliases = [model]
    plain = normalize_text(model.replace("\u2022", " "))
    if plain and plain != model:
        aliases.append(plain)
    return sorted(set(alias for alias in aliases if alias))


def extract_birddog_previous_lines_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "birddog_previous_lines.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Previous Lines" not in html_page_title(soup):
        return []
    if "NO LONGER IN MANUFACTURING" not in page_text:
        return []
    if "Still Supported" not in page_text:
        return []

    source_url = html_product_page_source_url(soup) or BIRDDOG_PREVIOUS_LINES_URL
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table)
        if not matrix:
            continue
        header = [normalize_text(cell) for cell in matrix[0]]
        if not header or normalize_header(header[0]) != "model":
            continue
        for raw_model in header[1:]:
            model = normalize_text(raw_model)
            if not model or model.lower() in seen:
                continue
            if not re.search(r"\d", model):
                continue
            seen.add(model.lower())
            row = status_only_product_row(
                model=model,
                product_name=f"BirdDog {model}",
                description="Broadcast NDI camera",
                product_status="No longer in manufacturing; still supported",
                source_table=f"{path.name} table {table_index} model header",
                source_hint="BirdDog previous lines product table import",
                source_url=source_url,
                review_policy="birddog_previous_lines_status_only_still_supported",
                review_reason=(
                    "BirdDog lists this exact model on its Previous Lines page "
                    "under 'No Longer in Manufacturing' and says the line is "
                    "still supported, but the captured page does not publish an "
                    "exact support, service, vulnerability, firmware, or "
                    "security-update end date."
                ),
                aliases=birddog_previous_lines_aliases(model),
            )
            row["_suppress_description_aliases"] = True
            rows.append(row)
    return rows


UPLOGIX_OLDER_HARDWARE_EOL_URL = (
    "https://uplogix.com/2016/04/end-of-life-announced-for-older-hardware/"
)
UPLOGIX_CONTROL_CENTER_HARDWARE_SUPPORT_URL = (
    "https://uplogix.com/end-of-hardware-support-notice/"
)


def extract_uplogix_older_hardware_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "uplogix_older_hardware_eol.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "End-of-life announced for older hardware" not in html_page_title(soup):
        return []
    required = (
        "Uplogix is announcing the end-of-life of a few older hardware platforms",
        "effective December 31, 2016",
        "no longer offer maintenance renewal contracts",
    )
    if not all(text in page_text for text in required):
        return []

    source_url = html_product_page_source_url(soup) or UPLOGIX_OLDER_HARDWARE_EOL_URL
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    in_eol_section = False
    for heading in soup.find_all("h2"):
        text = normalize_text(heading.get_text(" ", strip=True))
        key = normalize_header(text)
        if key == "end of life hardware platforms":
            in_eol_section = True
            continue
        if not in_eol_section:
            continue
        if key in {
            "published",
            "share",
            "subscribe to blog updates",
            "more posts",
            "schedule a demo",
        }:
            break
        if not text.startswith("Uplogix ") or not re.search(r"\d", text):
            continue
        if text.lower() in seen:
            continue
        seen.add(text.lower())
        row = status_only_product_row(
            model=text,
            product_name=text,
            description="Out-of-band local manager",
            product_status=(
                "End-of-life announced for older hardware; maintenance renewal "
                "contracts no longer offered after 2016-12-31"
            ),
            source_table=f"{path.name} End-of-life hardware platforms section",
            source_hint="Uplogix older hardware EOL announcement import",
            source_url=source_url,
            review_policy="uplogix_older_hardware_maintenance_renewal_status_only",
            review_reason=(
                "Uplogix announces this exact older hardware platform as "
                "end-of-life and says maintenance renewal contracts were no "
                "longer offered after 2016-12-31, but the source does not "
                "publish an exact support, service, vulnerability, firmware, "
                "or security-update end date for all deployed units."
            ),
            aliases=[text],
        )
        row["_suppress_description_aliases"] = True
        rows.append(row)
    return rows


def extract_uplogix_control_center_hardware_support_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "uplogix_control_center_hardware_support.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "End of Hardware Support Notice" not in html_page_title(soup):
        return []
    if (
        "End of Hardware Support for all Uplogix Control Centers running on "
        "Dell PowerEdge 2850 and 2950 servers"
    ) not in page_text:
        return []
    support_date = parse_date_any("October 1, 2016")
    if not support_date or "will remain committed to supporting future releases" not in page_text:
        return []

    source_url = (
        html_product_page_source_url(soup)
        or UPLOGIX_CONTROL_CENTER_HARDWARE_SUPPORT_URL
    )
    rows: list[dict[str, Any]] = []
    for server in ("Dell PowerEdge 2850", "Dell PowerEdge 2950"):
        model = f"Uplogix Control Center on {server}"
        row = {
            "Model": model,
            "Part Number": model,
            "Product Name": model,
            "Description": "Out-of-band management control center server",
            "Product Status": (
                "End of Hardware Support Notice; hardware failures no longer "
                f"supported after {support_date}; future Control Center software "
                "releases may continue"
            ),
            "End of Support": support_date,
            "Lifecycle Status Source": source_url,
            "_source_table": path.name,
            "_source_hint": "Uplogix Control Center hardware support notice import",
            "_source_url": source_url,
            "_force_lifecycle_review": True,
            "_review_policy": (
                "uplogix_control_center_hardware_support_not_security_eol"
            ),
            "_review_reason": (
                "Uplogix publishes an End of Hardware Support date for Control "
                f"Centers running on {server} and says hardware failures are no "
                "longer supported after that date, but the same source says "
                "future Control Center software releases may continue and does "
                "not define the date as a security-update or firmware-update "
                "end date."
            ),
            "_aliases": [model, f"Control Center on {server}", server],
            "_prefer_model": True,
            "_suppress_description_aliases": True,
        }
        rows.append(row)
    return rows


def extract_uplogix_lantronix_rows(path: Path) -> list[dict[str, Any]]:
    return (
        extract_uplogix_older_hardware_rows(path)
        + extract_uplogix_control_center_hardware_support_rows(path)
    )


def looks_like_product_code(value: str) -> bool:
    text = normalize_text(value)
    if not text or len(text) > 80 or " " in text:
        return False
    if re.search(r"[\u00d7\u00f7]", text):
        return False
    return bool(re.search(r"[A-Za-z]", text) and re.search(r"[0-9-]", text))


def product_code_from_url(source_url: str) -> str:
    slug_match = re.search(r"/product/([^/?#]+)/?", source_url, flags=re.I)
    if not slug_match:
        return ""
    slug = re.sub(r"-discontinued$", "", slug_match.group(1), flags=re.I)
    slug = normalize_text(slug).strip("/")
    if not slug:
        return ""
    return slug.upper()


def atlona_product_model(
    *,
    title_candidate: str,
    description: str,
    source_url: str,
) -> str:
    title_candidate = normalize_text(title_candidate)
    if title_candidate.upper().startswith("AT-") and looks_like_product_code(title_candidate):
        return title_candidate
    for text in (description, source_url):
        match = re.search(r"\b(AT-[A-Z0-9][A-Z0-9-]*)\b", text, flags=re.I)
        if match:
            return match.group(1).upper()
    if looks_like_product_code(title_candidate):
        return title_candidate
    url_code = product_code_from_url(source_url)
    if looks_like_product_code(url_code):
        return url_code
    return title_candidate


def extract_aaeon_network_appliance_phaseout_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Phaseout Notice" not in page_text or "Last Buy Date" not in page_text:
        return []

    title = html_page_title(soup)
    match = re.match(r"([A-Z0-9][A-Z0-9._+-]+)\s*:", title)
    model = normalize_text(match.group(1) if match else "")
    if not model:
        meta_keywords = html_meta_content(soup, {"name": "keywords"})
        model_match = re.search(r"\b([A-Z]{2,}-\d{3,}[A-Z0-9._+-]*)\b", meta_keywords)
        model = normalize_text(model_match.group(1) if model_match else "")
    if not model:
        return []

    last_buy_match = re.search(
        r"Last Buy Date:\s*([A-Za-z]{3,9}\.?\s+\d{1,2},\s+\d{4})",
        page_text,
        flags=re.I,
    )
    last_buy = parse_date_any(
        last_buy_match.group(1).replace(".", "") if last_buy_match else ""
    )
    if not last_buy:
        return []

    replacement = ""
    replacement_match = re.search(
        r"Recommend Product:\s*([A-Z0-9][A-Z0-9._+-]+)",
        page_text,
        flags=re.I,
    )
    if replacement_match:
        replacement = normalize_text(replacement_match.group(1))
    description = html_meta_content(soup, {"name": "description"}) or "Network Appliance"
    source_url = html_product_page_source_url(soup)

    return [
        {
            "Model": model,
            "Product Name": f"AAEON {model}",
            "Description": status_page_device_type(f"{title} {description}"),
            "Product Status": f"Phaseout Notice; going to EOL; Last Buy Date {last_buy}",
            "End of Sale": last_buy,
            "Replacement": replacement,
            "_source_table": f"{path.name} phaseout notice",
            "_source_hint": "AAEON network appliance phaseout notice import",
            "_source_url": source_url,
            "_force_lifecycle_review": True,
            "_review_policy": "aaeon_phaseout_last_buy_date_not_security_eol",
            "_review_reason": (
                "AAEON publishes a Phaseout Notice and exact Last Buy Date for "
                "this product series. This is sale/lifecycle evidence, not proof "
                "that firmware, vulnerability, or security updates have ended."
            ),
            "_aliases": [model, title, description, replacement],
            "_prefer_model": True,
        }
    ]


def extract_exfo_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    if "Discontinued product" not in title or "EXFO" not in title:
        return []

    model = normalize_text(title.split("|", 1)[0])
    if not model:
        return []
    h1 = first_h1_text(soup)
    product_name = h1 or f"EXFO {model}"
    description = ""
    if h1 and " - " in h1:
        description = normalize_text(h1.split(" - ", 1)[1])
    description = (
        description
        or html_meta_content(soup, {"name": "description"}, {"property": "og:description"})
        or "Optical Network Test Equipment"
    )
    page_text = normalize_text(soup.get_text(" ", strip=True))
    discontinued_match = re.search(
        r"Discontinued date:\s*([0-9]{1,2}/[0-9]{1,2}/[0-9]{2,4})",
        page_text,
        flags=re.I,
    )
    support_match = re.search(
        r"End-of-service and support date:\s*([0-9]{1,2}/[0-9]{1,2}/[0-9]{2,4})",
        page_text,
        flags=re.I,
    )
    discontinued_date = parse_date_any(discontinued_match.group(1) if discontinued_match else "")
    support_date = parse_date_any(support_match.group(1) if support_match else "")
    if not discontinued_date and not support_date:
        return []

    row: dict[str, Any] = {
        "Model": model,
        "Product Name": product_name if product_name.startswith("EXFO ") else f"EXFO {product_name}",
        "Description": status_page_device_type(f"{model} {description}"),
        "Product Status": "Discontinued product page",
        "_source_table": f"{path.name} discontinued product page",
        "_source_hint": "EXFO discontinued product lifecycle page import",
        "_source_url": html_product_page_source_url(soup),
        "_review_policy": "exfo_discontinued_product_end_of_service_support",
        "_aliases": [model, h1, description],
        "_prefer_model": True,
    }
    if discontinued_date:
        row["End of Sale"] = discontinued_date
        row["Product Status"] = f"{row['Product Status']}; discontinued date {discontinued_date}"
    if support_date:
        row["End of Support"] = support_date
        row["End of Service"] = support_date
    else:
        row["_force_lifecycle_review"] = True
        row["_review_reason"] = (
            "EXFO marks this product as discontinued, but the captured page does "
            "not publish an exact support, service, vulnerability, or "
            "security-update end date."
        )
    return [row]


def extract_status_marked_product_page_rows(
    path: Path,
    vendor_slug: str,
) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    og_title = html_meta_content(soup, {"property": "og:title"})
    h1 = first_h1_text(soup)
    source_url = html_product_page_source_url(soup)
    description = html_meta_content(
        soup,
        {"name": "description"},
        {"property": "og:description"},
    )

    if vendor_slug == "atlona":
        marker_title = og_title or title
        match = re.match(r"(.+?)\s+\*{3}\s*Discontinued\s*\*{3}", marker_title, flags=re.I)
        if not match:
            return []
        title_candidate = normalize_text(match.group(1))
        model = atlona_product_model(
            title_candidate=title_candidate,
            description=description,
            source_url=source_url,
        )
        return [
            status_only_product_row(
                model=model,
                product_name=f"Atlona {model}",
                description=status_page_device_type(f"{marker_title} {description}"),
                product_status="Discontinued product page",
                source_table=f"{path.name} product page title",
                source_hint="Atlona discontinued product page import",
                source_url=source_url,
                review_policy="atlona_discontinued_product_page_status_only",
                review_reason=(
                    "Atlona marks this product page as discontinued, but the "
                    "captured product page does not publish an exact support, "
                    "service, vulnerability, or security-update end date."
                ),
                aliases=[model, title_candidate, marker_title, description],
            )
        ]

    if vendor_slug == "congatec":
        marker_title = h1 or title
        match = re.match(r"(.+?)\s+\(EOL\)", marker_title, flags=re.I)
        if not match:
            return []
        model = normalize_text(match.group(1))
        return [
            status_only_product_row(
                model=model,
                product_name=f"congatec {model}",
                description=status_page_device_type(f"{marker_title} {description}"),
                product_status="EOL product page",
                source_table=f"{path.name} product page title",
                source_hint="congatec EOL product page import",
                source_url=source_url,
                review_policy="congatec_eol_product_page_status_only",
                review_reason=(
                    "congatec marks this product page as EOL, but the captured "
                    "product page does not publish an exact support, service, "
                    "vulnerability, or security-update end date."
                ),
                aliases=[model, marker_title, description],
            )
        ]

    if vendor_slug == "portwell":
        page_text = normalize_text(soup.get_text(" ", strip=True))
        if "Status: EOL" not in page_text:
            return []
        model = h1 or normalize_text(title.split(",", 1)[0])
        if not model:
            return []
        replacement = ""
        replacement_match = re.search(
            r"Migration options:\s*([A-Z0-9][A-Z0-9._+-]+)",
            page_text,
            flags=re.I,
        )
        if replacement_match:
            replacement = normalize_text(replacement_match.group(1))
        return [
            status_only_product_row(
                model=model,
                product_name=f"Portwell {model}",
                description=status_page_device_type(f"{title} {description}"),
                product_status="Status: EOL product page",
                source_table=f"{path.name} product page status",
                source_hint="Portwell EOL product page import",
                source_url=source_url,
                review_policy="portwell_eol_product_page_status_only",
                review_reason=(
                    "Portwell marks this product page as EOL and may provide a "
                    "migration option, but the captured product page does not "
                    "publish an exact support, service, vulnerability, or "
                    "security-update end date."
                ),
                aliases=[model, title, description, replacement],
                replacement=replacement,
            )
        ]

    if vendor_slug == "poynting":
        marker_title = og_title or title
        match = re.search(r"\b(?:POYNTING\s+)?(.+?)\s+\(EOL\)", marker_title, flags=re.I)
        if not match:
            return []
        model = normalize_text(match.group(1))
        return [
            status_only_product_row(
                model=model,
                product_name=f"POYNTING {model}",
                description=status_page_device_type(f"{marker_title} {description}"),
                product_status="EOL product page",
                source_table=f"{path.name} product page title",
                source_hint="POYNTING EOL product page import",
                source_url=source_url,
                review_policy="poynting_eol_product_page_status_only",
                review_reason=(
                    "POYNTING marks this product page as EOL, but the captured "
                    "product page does not publish an exact support, service, "
                    "vulnerability, or security-update end date."
                ),
                aliases=[model, marker_title, description],
            )
        ]

    return []


def extract_nexcom_aiot_mart_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    if "[EOL]" not in title:
        return []

    page_text = normalize_text(soup.get_text(" ", strip=True))
    no_updates = (
        "No further software or firmware updates or maintenance will be released"
        in page_text
    )
    maintenance_discontinued = "technical maintenance has been officially discontinued" in page_text
    if not no_updates and not maintenance_discontinued:
        return []

    h1 = first_h1_text(soup)
    marker_title = h1 or title
    model = ""
    match = re.search(r"\|\s*([^|]+?)\s*\[EOL\]", marker_title)
    if match:
        model = normalize_text(match.group(1))
    if not model:
        match = re.search(r"\b([A-Z]{2,}\s+\d+[A-Z0-9 -]*Series)\s*\[EOL\]", marker_title)
        model = normalize_text(match.group(1) if match else "")
    if not model:
        return []

    description = html_meta_content(
        soup,
        {"name": "description"},
        {"property": "og:description"},
    )
    row: dict[str, Any] = {
        "Model": model,
        "Product Name": marker_title,
        "Description": status_page_device_type(f"{marker_title} {description}"),
        "Product Status": (
            "End-of-Life model; technical maintenance discontinued; no further "
            "software or firmware updates or maintenance will be released"
        ),
        "_source_table": f"{path.name} EOL product page policy",
        "_source_hint": "NEXCOM AIoT Mart EOL product page import",
        "_source_url": html_product_page_source_url(soup),
        "_allow_status_only": True,
        "_security_updates_ended_without_exact_date": True,
        "_review_policy": (
            "nexcom_aiot_mart_eol_no_further_software_firmware_updates_no_exact_date"
        ),
        "_review_reason": (
            "NEXCOM AIoT Mart says technical maintenance has been discontinued "
            "and no further software or firmware updates or maintenance will be "
            "released for this EOL model, but the captured product page does "
            "not publish an exact security-update end date."
        ),
        "_aliases": [model, marker_title, description],
        "_prefer_model": True,
    }
    return [row]


ACROSSER_EOL_PRODUCTS_URL = "https://www.acrosser.com/product/EOL/EOL-products.html"


def extract_acrosser_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "eol_products.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    if "EOL products" not in title:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for link in soup.find_all("a"):
        href = normalize_text(link.get("href"))
        if not href.startswith("productdetail_en.php?id="):
            continue
        model = normalize_text(link.get_text(" ", strip=True))
        if not model or model.lower() in seen:
            continue
        if not (looks_like_product_code(model) or re.search(r"\([A-Z0-9._+-]+\)", model)):
            continue
        seen.add(model.lower())
        rows.append(
            status_only_product_row(
                model=model,
                product_name=f"ACROSSER {model}",
                description=status_page_device_type(model),
                product_status="EOL products catalog",
                source_table=f"{path.name} product links",
                source_hint="ACROSSER EOL products catalog import",
                source_url=ACROSSER_EOL_PRODUCTS_URL,
                review_policy="acrosser_eol_products_catalog_status_only",
                review_reason=(
                    "ACROSSER lists this exact product in its EOL products "
                    "catalog, but the captured page does not publish an exact "
                    "support, service, vulnerability, or security-update end date."
                ),
                aliases=[model, href],
            )
        )
    return rows


CINCOZE_EOL_PRODUCTS_URL = "https://www.cincoze.com/en/supports/eol"


def cincoze_eol_device_type(category: str, model: str, details: str) -> str:
    key = normalize_header(f"{category} {model} {details}")
    if "rugged embedded" in key or "embedded computer" in key:
        return "Rugged Embedded Computer"
    if "panel pc" in key:
        return "Industrial Panel PC"
    if "monitor" in key or "tft lcd" in key:
        return "Industrial Monitor"
    if "module" in key:
        return "Embedded Module"
    if "bracket" in key or "bezel" in key:
        return "Industrial Computer Accessory"
    if "poe" in key or "lan" in key:
        return "Industrial Network Module"
    return "Rugged Embedded Computer"


def extract_cincoze_eol_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "eol.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    if "EOL" not in html_page_title(soup):
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for box_index, box in enumerate(soup.find_all(class_=lambda value: value and "tb-box" in str(value)), start=1):
        heading = box.find(["h2", "h3", "h4"])
        category = normalize_text(
            heading.get("title") if heading and heading.get("title") else (
                heading.get_text(" ", strip=True) if heading else ""
            )
        )
        table = box.find("table")
        if not table:
            continue
        matrix = html_table_matrix(table, separator="\n")
        if not matrix:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        if "model" not in headers:
            continue
        model_index = headers.index("model")
        detail_headers = [
            idx
            for idx, header in enumerate(headers)
            if idx != model_index
            and any(token in header for token in ("description", "cpu", "i o", "display", "category"))
        ]
        for table_row in matrix[1:]:
            if len(table_row) <= model_index:
                continue
            model = normalize_text(table_row[model_index])
            if not model or model.lower() in seen:
                continue
            if not re.search(r"\d", model):
                continue
            seen.add(model.lower())
            details = "; ".join(
                normalize_text(table_row[idx])
                for idx in detail_headers
                if idx < len(table_row) and normalize_text(table_row[idx])
            )
            rows.append(
                status_only_product_row(
                    model=model,
                    product_name=f"Cincoze {model}",
                    description=cincoze_eol_device_type(category, model, details),
                    product_status="EOL support page product table",
                    source_table=f"{path.name} table block {box_index}",
                    source_hint="Cincoze EOL product table import",
                    source_url=CINCOZE_EOL_PRODUCTS_URL,
                    review_policy="cincoze_eol_product_table_status_only",
                    review_reason=(
                        "Cincoze lists this exact product on its EOL support "
                        "page, but the captured page does not publish an exact "
                        "support, service, vulnerability, or security-update end date."
                    ),
                    aliases=[model, category, details],
                )
            )
    return rows


COMNET_DISCONTINUED_PRODUCTS_URL = "https://www.comnet.net/discontinued-products"


def extract_comnet_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "discontinued_products.html":
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    if "Discontinued Products" not in title:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table)
        if not matrix:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        if "product number" not in headers or "product name" not in headers:
            continue
        number_index = headers.index("product number")
        name_index = headers.index("product name")
        for table_row in matrix[1:]:
            if len(table_row) <= max(number_index, name_index):
                continue
            model = normalize_text(table_row[number_index])
            product_name = normalize_text(table_row[name_index])
            if not model or not product_name or model.lower() in seen:
                continue
            if not looks_like_product_code(model):
                continue
            seen.add(model.lower())
            rows.append(
                status_only_product_row(
                    model=model,
                    product_name=f"ComNet {model}",
                    description=status_page_device_type(f"{model} {product_name}"),
                    product_status="Discontinued products table",
                    source_table=f"{path.name} table {table_index}",
                    source_hint="ComNet discontinued products table import",
                    source_url=COMNET_DISCONTINUED_PRODUCTS_URL,
                    review_policy="comnet_discontinued_products_table_status_only",
                    review_reason=(
                        "ComNet lists this exact product in its discontinued "
                        "products table, but the captured page does not publish "
                        "an exact support, service, vulnerability, or "
                        "security-update end date."
                    ),
                    aliases=[model, product_name],
                )
            )
    return rows


IDIS_DISCONTINUED_PRODUCTS_URL = (
    "https://www.idisglobal.com/index/product_list/47/table?country=IDIS&lang=EN"
)


def extract_idis_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if "discontinued" not in path.name and not re.match(r"product_list_\d+_table\.html$", path.name):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Product Name" not in page_text or "Description" not in page_text:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        matrix = html_table_matrix(table)
        if not matrix:
            continue
        headers = [normalize_header(cell) for cell in matrix[0]]
        if "product name" not in headers or "description" not in headers:
            continue
        product_index = headers.index("product name")
        description_index = headers.index("description")
        for table_row in matrix[1:]:
            if len(table_row) <= max(product_index, description_index):
                continue
            product_cell = normalize_text(table_row[product_index])
            description = normalize_text(table_row[description_index])
            if not product_cell or not description:
                continue
            for model in split_model_group(product_cell):
                model = normalize_text(model)
                if (
                    not model
                    or normalize_header(model) in {"product name", "learn more"}
                    or not looks_like_product_code(model)
                ):
                    continue
                key = (model.lower(), description.lower())
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    status_only_product_row(
                        model=model,
                        product_name=f"IDIS {model}",
                        description=status_page_device_type(f"{model} {description}"),
                        product_status="Discontinued products table",
                        source_table=f"{path.name} table {table_index}",
                        source_hint="IDIS discontinued products table import",
                        source_url=IDIS_DISCONTINUED_PRODUCTS_URL,
                        review_policy="idis_discontinued_products_table_status_only",
                        review_reason=(
                            "IDIS lists this exact product in a discontinued "
                            "products table, but the captured page does not "
                            "publish an exact support, service, vulnerability, "
                            "or security-update end date."
                        ),
                        aliases=[model, product_cell, description],
                    )
                )
    return rows


UNIVIEW_DISCONTINUED_PRODUCTS_URL = (
    "https://www.uniview.com/Products/Discontinued_Products/"
)


def uniview_modelish_product_text(text: str, href: str) -> bool:
    text = normalize_text(text)
    href_key = normalize_header(href)
    if not text or not href or not href.startswith("/"):
        return False
    if "/products/" not in href.lower():
        return False
    if "technology" in href_key or "series" in href_key:
        return False
    if text.lower().startswith(("tri-guard", "ultra265")):
        return False
    kit_model = bool(re.match(r"^KIT\s+[A-Z0-9][A-Z0-9 &._+-]*\d", text))
    if not (looks_like_product_code(text) or kit_model):
        return False
    return len(text) <= 100


def uniview_device_description_from_href(model: str, href: str) -> str:
    key = normalize_header(f"{model} {href}")
    if "network video recorders" in key or "/nvr/" in href.lower():
        return "Network Video Recorder"
    if "dvr" in key or "xvr" in key:
        return "Video Surveillance Device"
    if "ptz" in key:
        return "PTZ IP Camera"
    if "camera" in key or "ipc" in key or "uniarch" in key:
        return "IP Camera"
    return status_page_device_type(f"{model} {href}")


def extract_uniview_discontinued_product_rows(path: Path) -> list[dict[str, Any]]:
    if "discontinued_products" not in path.name:
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    title = html_page_title(soup)
    page_text = normalize_text(soup.get_text(" ", strip=True))
    if "Discontinued" not in title and "Discontinued Products" not in page_text:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for link in soup.find_all("a"):
        text = normalize_text(link.get_text(" ", strip=True))
        href = normalize_text(link.get("href"))
        if not uniview_modelish_product_text(text, href):
            continue
        for model in split_model_group(text):
            model = normalize_text(model)
            if not model or model.lower() in seen:
                continue
            seen.add(model.lower())
            rows.append(
                status_only_product_row(
                    model=model,
                    product_name=f"Uniview {model}",
                    description=uniview_device_description_from_href(model, href),
                    product_status="Discontinued products catalog",
                    source_table=f"{path.name} discontinued product links",
                    source_hint="Uniview discontinued products catalog import",
                    source_url=UNIVIEW_DISCONTINUED_PRODUCTS_URL,
                    review_policy="uniview_discontinued_products_catalog_status_only",
                    review_reason=(
                        "Uniview lists this exact product in its discontinued "
                        "products catalog, but the captured page does not "
                        "publish an exact support, service, vulnerability, or "
                        "security-update end date."
                    ),
                    aliases=[model, text, href],
                )
            )
    return rows


def legrand_luxul_source_url(raw: dict[str, Any]) -> str:
    for key in ("computedproducturl", "clickUri", "printableUri"):
        value = normalize_text(raw.get(key))
        if not value:
            continue
        if value.startswith("/"):
            return f"https://www.legrandav.com{value}"
        if value.startswith("http"):
            return value
    return "https://www.legrandav.com/products/discontinued"


def legrand_luxul_product_rows_from_result(
    result: dict[str, Any],
    path: Path,
) -> list[dict[str, Any]]:
    raw = result.get("raw") if isinstance(result.get("raw"), dict) else {}
    status_text = normalize_text(raw.get("productz32xstatus"))
    computed_status = normalize_text(raw.get("computedproductstatus"))
    title = normalize_text(raw.get("computedproducttitle") or result.get("title"))
    if "discontinued" not in normalize_header(f"{status_text} {computed_status} {title}"):
        return []

    brand_values = raw.get("brandfacet") or []
    brand_text = " ".join(normalize_text(value) for value in brand_values)
    if brand_text and "luxul" not in normalize_header(brand_text):
        return []

    model = normalize_text(raw.get("computedproductnumber") or raw.get("computedproductmeta"))
    if not looks_like_product_code(model):
        return []

    clean_title = re.sub(r"\s+[-–]\s*DISCONTINUED\b", "", title, flags=re.I)
    clean_title = re.sub(r"\s+\bDISCONTINUED\b", "", clean_title, flags=re.I)
    clean_title = normalize_text(clean_title) or model
    source_url = legrand_luxul_source_url(raw)
    return [
        status_only_product_row(
            model=model,
            product_name=f"Luxul {model}",
            description=status_page_device_type(f"{model} {clean_title} {source_url}"),
            product_status="Discontinued product search result",
            source_table=f"{path.name} results",
            source_hint="Legrand/Luxul discontinued product search import",
            source_url=source_url,
            review_policy="legrand_luxul_discontinued_search_status_only",
            review_reason=(
                "Legrand/Luxul marks this exact product result as discontinued, "
                "but the captured search result does not publish an exact "
                "support, service, vulnerability, or security-update end date."
            ),
            aliases=[model, clean_title, title],
        )
    ]


def extract_legrand_luxul_discontinued_search_rows(path: Path) -> list[dict[str, Any]]:
    if not re.match(r"luxul_discontinued_search_page_\d+\.json$", path.name):
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows: list[dict[str, Any]] = []
    for result in payload.get("results") or []:
        if not isinstance(result, dict):
            continue
        rows.extend(legrand_luxul_product_rows_from_result(result, path))
    return rows


VERKADA_HELP_ROOT_URL = "https://help.verkada.com"


def verkada_title_models(title: str) -> list[tuple[str, str]]:
    region = ""
    region_match = re.search(r"\(([^)]+)\)", title)
    if region_match:
        region = normalize_text(region_match.group(1))
    model_text = re.sub(r"\([^)]*\)", "", title)
    models: list[tuple[str, str]] = []
    for model in re.findall(r"\b(?:ACCX-[A-Z0-9-]+|[A-Z]{1,4}\d{1,4}(?:-[A-Z0-9]+)?)\b", model_text):
        model = normalize_text(model)
        if model and (model, region) not in models:
            models.append((model, region))
    return models


def extract_verkada_end_of_sale_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "verkada_gitbook_site_index.json":
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for page in payload.get("pages") or []:
        if not isinstance(page, dict) or page.get("lang") != "en":
            continue
        breadcrumbs = [
            normalize_text(crumb.get("label"))
            for crumb in page.get("breadcrumbs") or []
            if isinstance(crumb, dict)
        ]
        if "End-of-Sale Products" not in breadcrumbs:
            continue
        title = normalize_text(page.get("title"))
        pathname = normalize_text(page.get("pathname"))
        description = normalize_text(page.get("description"))
        if title == "End-of-Sale Products" or not pathname:
            continue
        if "end of sale" not in normalize_header(f"{pathname} {description}"):
            continue
        for model, region in verkada_title_models(title):
            key = (model.lower(), region.lower())
            if key in seen:
                continue
            seen.add(key)
            model_description = description or f"End-of-Sale information for Verkada {model}"
            row = status_only_product_row(
                model=model,
                product_name=f"Verkada {model}",
                description=status_page_device_type(f"{model} {model_description}"),
                product_status="End-of-Sale product announcement",
                source_table=f"{path.name} pages",
                source_hint="Verkada end-of-sale GitBook index import",
                source_url=f"{VERKADA_HELP_ROOT_URL}{pathname}",
                review_policy="verkada_end_of_sale_product_status_only",
                review_reason=(
                    "Verkada publishes an end-of-sale announcement page for "
                    "this exact model, but the captured index does not publish "
                    "an exact support, service, vulnerability, or "
                    "security-update end date."
                ),
                aliases=[model, title, description],
            )
            if region:
                row["Region"] = region
            rows.append(row)
    return rows


NETALLY_SUPPORTED_BY_ALLYCARE_PATTERN = re.compile(
    r"supported by AllyCare until\s+"
    r"([A-Za-z]+\s+\d{1,2}(?:st|nd|rd|th)?[,]?\s+\d{4})",
    flags=re.I,
)


def netally_source_url(soup: BeautifulSoup) -> str:
    for attrs in (
        {"property": "og:url"},
        {"rel": "canonical"},
    ):
        node = soup.find("meta", attrs=attrs)
        if node and node.get("content"):
            return normalize_text(node.get("content"))
        node = soup.find("link", attrs=attrs)
        if node and node.get("href"):
            return normalize_text(node.get("href"))
    return ""


def netally_support_until(text: str) -> str:
    match = NETALLY_SUPPORTED_BY_ALLYCARE_PATTERN.search(text)
    if not match:
        return ""
    return parse_date_any(match.group(1)) or ""


def netally_device_type(model: str, description: str, title: str) -> str:
    key = normalize_header(f"{model} {description} {title}")
    if "airmagnet wifi analyzer" in key or "wifi analyzer" in key or "wi fi analyzer" in key:
        return "Wireless Network Analysis Software"
    if "spectrum xt" in key:
        return "Wireless Spectrum Analyzer"
    if "aircheck" in key or "air check" in key:
        return "Wireless Network Tester"
    if "linkrunner" in key or "link runner" in key:
        return "Network Cable Tester"
    if "multi adapter" in key:
        return "Wireless Adapter Kit"
    return "Network Test Equipment"


def netally_product_title(soup: BeautifulSoup) -> str:
    title = normalize_text(soup.title.get_text(" ", strip=True) if soup.title else "")
    title = re.sub(r"\s*\|\s*NetAlly\s*$", "", title, flags=re.I)
    return title or "NetAlly Product"


def extract_netally_legacy_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name == "link_live_enabled_features_legacy.html":
        return []
    if path.name == "linkrunner_at_1000_2000_end_of_sale.html":
        return []
    if not path.name.endswith("_legacy.html"):
        return []

    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    support_until = netally_support_until(text)
    if not support_until or "DISCONTINUED - Support only" not in text:
        return []

    title = netally_product_title(soup)
    source_url = netally_source_url(soup)
    rows: list[dict[str, Any]] = []
    for table in soup.find_all("table"):
        table_rows = html_table_matrix(table)
        if not table_rows:
            continue
        header = [normalize_header(cell) for cell in table_rows[0]]
        if len(header) < 2 or not header[0].startswith("model number"):
            continue
        for row in table_rows[1:]:
            if len(row) < 2:
                continue
            raw_model = normalize_text(row[0])
            description = normalize_text(row[1])
            if "discontinued" not in normalize_header(raw_model):
                continue
            model = normalize_text(re.split(r"\s+[–-]\s+Discontinued", raw_model, flags=re.I)[0])
            if not model:
                continue
            if "allycare support" in normalize_header(description) or re.search(
                r"-(?:1YS|3YS)$",
                model,
                flags=re.I,
            ):
                continue
            rows.append(
                {
                    "Model": model,
                    "Part Number": model,
                    "Product Name": f"NetAlly {model}",
                    "Description": netally_device_type(model, description, title),
                    "Product Status": (
                        f"DISCONTINUED - Support only; supported by AllyCare until {support_until}"
                    ),
                    "End of Support": support_until,
                    "End of Service": support_until,
                    "_source_table": f"{path.name} discontinued model table",
                    "_source_hint": "NetAlly discontinued support-only product page import",
                    "_source_url": source_url,
                    "_review_policy": "netally_discontinued_support_only_allycare_until",
                    "_aliases": [model, description, title],
                    "_prefer_model": True,
                }
            )
    return rows


CYBERDATA_EOL_COLLECTION_URL = (
    "https://www.cyberdata.net/collections/end-of-life-products"
)


def cyberdata_clean_html_text(value: Any) -> str:
    text = html_lib.unescape(normalize_text(value))
    if "<" not in text and ">" not in text:
        return normalize_text(text)
    soup = BeautifulSoup(text, "html.parser")
    return normalize_text(soup.get_text(" ", strip=True))


def cyberdata_product_sku(product: dict[str, Any]) -> str:
    variants = product.get("variants") or []
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        sku = normalize_text(variant.get("sku"))
        if sku:
            return sku
    return normalize_text(product.get("handle"))


def cyberdata_replacement_products(product: dict[str, Any]) -> str:
    text = cyberdata_clean_html_text(
        " ".join(
            normalize_text(product.get(key))
            for key in ("title", "body_html")
            if normalize_text(product.get(key))
        )
    )
    replacements: list[str] = []
    for match in re.finditer(
        r"Replacement Products?\s+(?:is|are)\s+([A-Z0-9 ,/&-]+)",
        text,
        flags=re.I,
    ):
        for code in re.findall(r"\b\d{6}[A-Z0-9 -]*\b", match.group(1), flags=re.I):
            code = normalize_text(code)
            if code and code not in replacements:
                replacements.append(code)
    for tag in product.get("tags") or []:
        match = re.match(r"related-product-(\d{6}[A-Z0-9-]*)$", str(tag), flags=re.I)
        if match:
            code = normalize_text(match.group(1))
            if code not in replacements:
                replacements.append(code)
    return "; ".join(replacements)


def cyberdata_device_type(title: str, product_type: str) -> str:
    key = normalize_header(title)
    if "switch" in key:
        return "VoIP Network Switch"
    if "intercom" in key:
        return "VoIP Intercom"
    if "speaker" in key:
        return "VoIP Speaker"
    if "amplifier" in key:
        return "Paging Amplifier"
    if "strobe" in key:
        return "Visual Notification Endpoint"
    if "ringer" in key:
        return "VoIP Ringer"
    if "horn" in key:
        return "VoIP Horn Speaker"
    if "paging" in key or "zone controller" in key:
        return "VoIP Paging Device"
    if "relay" in key or "door strike" in key or "rfid" in key:
        return "Access Control Device"
    if "clock" in key:
        return "Network Clock Accessory"
    if "hub" in key or "poweredusb" in key:
        return "USB Network Peripheral"
    if "case kit" in key or "secure case" in key or "desktop stand" in key:
        return "VoIP Endpoint Accessory"
    if normalize_header(product_type) == "retail":
        return "Retail Network Peripheral"
    return "VoIP Endpoint"


def extract_cyberdata_eol_product_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "end_of_life_products.json":
        return []
    try:
        data = load_json(path)
    except Exception:
        return []
    products = data.get("products")
    if not isinstance(products, list):
        return []

    rows: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    for product in products:
        if not isinstance(product, dict):
            continue
        tags = [normalize_text(tag).lower() for tag in product.get("tags") or []]
        if "end-of-life" not in tags:
            continue
        sku = cyberdata_product_sku(product)
        title = cyberdata_clean_html_text(product.get("title"))
        if not sku or not title:
            continue
        key = (sku, normalize_header(title))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        handle = normalize_text(product.get("handle"))
        product_type = normalize_text(product.get("product_type"))
        source_url = (
            f"https://www.cyberdata.net/products/{handle}"
            if handle
            else CYBERDATA_EOL_COLLECTION_URL
        )
        aliases = [sku, title]
        if handle and handle not in aliases:
            aliases.append(handle)
        row: dict[str, Any] = {
            "Model": sku,
            "Part Number": sku,
            "Product Name": title,
            "Description": cyberdata_device_type(title, product_type),
            "Product Status": (
                "End-of-Life product; no longer being sold but still supported; sold out"
            ),
            "Lifecycle Status Source": CYBERDATA_EOL_COLLECTION_URL,
            "_source_table": f"{path.name} products",
            "_source_hint": "CyberData End-of-Life Products collection JSON import",
            "_source_url": source_url,
            "_status_only_review": True,
            "_review_policy": "cyberdata_eol_no_longer_sold_still_supported",
            "_review_reason": (
                "CyberData's End-of-Life Products collection says listed "
                "products are no longer being sold but are still supported; "
                "the source does not publish exact support or security-update "
                "end dates."
            ),
            "_aliases": aliases,
            "_prefer_model": True,
        }
        replacement = cyberdata_replacement_products(product)
        if replacement:
            row["Replacement Products"] = replacement
        rows.append(row)
    return rows


IOGEAR_EOL_COLLECTION_URL = "https://iogear.com/collections/eol"


def iogear_product_json(data: dict[str, Any]) -> dict[str, Any]:
    product = data.get("product")
    if isinstance(product, dict):
        return product
    return data


def iogear_is_eol_product(product: dict[str, Any]) -> bool:
    tags = [
        normalize_header(tag)
        for tag in product.get("tags") or []
        if normalize_text(tag)
    ]
    return "label eol" in tags or "eol" in tags


def iogear_product_skus(product: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for variant in product.get("variants") or []:
        if not isinstance(variant, dict):
            continue
        sku = normalize_text(variant.get("sku"))
        key = normalize_alias_dedupe_key(sku)
        if not sku or not key or key in seen:
            continue
        result.append((sku, variant))
        seen.add(key)
    return result


def iogear_description_text(product: dict[str, Any]) -> str:
    description = normalize_text(product.get("description") or product.get("body_html"))
    if not description:
        return ""
    return html_lib.unescape(
        normalize_text(BeautifulSoup(description, "html.parser").get_text(" ", strip=True))
    )


def iogear_device_type(title: str, tags: list[str], description: str) -> str:
    key = normalize_header(" ".join([title, " ".join(tags), description]))
    if "secure kvm" in key:
        return "Secure KVM Switch"
    if "lcd kvm" in key or "lcd console" in key:
        return "Rackmount LCD KVM Console"
    if "kvm cable" in key or ("kvm" in key and "cable" in key):
        return "KVM Cable"
    if "kvm" in key:
        return "KVM Switch"
    if "powerline" in key or "homeplug" in key:
        return "Powerline Networking Device"
    if "wifi" in key or "wi fi" in key or "wireless range extender" in key:
        return "Wireless Networking Device"
    if "bluetooth" in key:
        return "Bluetooth Adapter"
    if "ethernet" in key and ("adapter" in key or "gateway" in key):
        return "Network Adapter"
    if "smart card" in key or "cac reader" in key:
        return "Smart Card Reader"
    if "card reader" in key:
        return "Card Reader"
    if "dock" in key or "docking station" in key:
        return "Docking Station"
    if "usb hub" in key or re.search(r"\bhub\b", key):
        return "USB Hub"
    if "matrix" in key:
        return "AV Matrix Switch"
    if "video switch" in key or "hdmi switch" in key or "displayport switch" in key:
        return "AV Switch"
    if "splitter" in key:
        return "AV Splitter"
    if "extender" in key:
        return "AV Extender"
    if "adapter" in key or "converter" in key:
        return "Video/USB Adapter"
    if "keyboard" in key and "mouse" in key:
        return "Keyboard/Mouse Peripheral"
    if "keyboard" in key:
        return "Keyboard Peripheral"
    if "mouse" in key:
        return "Mouse Peripheral"
    if "headset" in key or "microphone" in key or "speaker" in key:
        return "Audio Peripheral"
    if "cable" in key:
        return "Cable"
    if "charger" in key or "power adapter" in key:
        return "Power Accessory"
    return "IOGEAR Peripheral"


def extract_iogear_eol_product_json_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("product_"):
        return []
    try:
        product = iogear_product_json(load_json(path))
    except Exception:
        return []
    if normalize_text(product.get("vendor")).lower() != "iogear":
        return []
    if not iogear_is_eol_product(product):
        return []

    title = html_lib.unescape(normalize_text(product.get("title")))
    handle = normalize_text(product.get("handle"))
    skus = iogear_product_skus(product)
    if not title or not handle or not skus:
        return []

    tags = [normalize_text(tag) for tag in product.get("tags") or [] if normalize_text(tag)]
    description_text = iogear_description_text(product)
    source_url = f"https://iogear.com/products/{handle}"
    rows: list[dict[str, Any]] = []
    for sku, variant in skus:
        variant_title = normalize_text(variant.get("public_title") or variant.get("title"))
        product_name = title
        if variant_title and normalize_header(variant_title) != "default title":
            product_name = f"{title} ({variant_title})"

        aliases = [
            sku,
            title,
            product_name,
            handle,
            normalize_text(variant.get("barcode")),
        ]
        row = status_only_product_row(
            model=sku,
            product_name=product_name,
            description=iogear_device_type(product_name, tags, description_text),
            product_status=(
                "IOGEAR EOL-tagged product; official product page says this "
                "product is EOL and is no longer being sold"
            ),
            source_table=f"{path.name} product",
            source_hint="IOGEAR EOL-tagged product JSON import",
            source_url=source_url,
            review_policy="iogear_eol_collection_status_only",
            review_reason=(
                "IOGEAR marks this exact SKU as EOL/no longer sold, but the "
                "checked source does not publish exact support, firmware, or "
                "security-update end dates."
            ),
            aliases=aliases,
        )
        row["Part Number"] = sku
        row["SKU"] = sku
        row["Lifecycle Status Source"] = IOGEAR_EOL_COLLECTION_URL
        if description_text:
            row["Source Description"] = description_text[:500]
        rows.append(row)
    return rows


SIEMENS_RUGGEDCOM_PLM_URL = (
    "https://support.industry.siemens.com/cs/attachments/109983787/"
    "109983787_ProductLifeCycle_SINEC_NMS_DOC_V10_en.pdf"
)


def siemens_ruggedcom_product_url(mlfb: str) -> str:
    return (
        "https://mall.industry.siemens.com/mall/en/WW/Catalog/Product/?mlfb="
        f"{mlfb}"
    )


def siemens_ruggedcom_date(value: Any) -> str | None:
    text = normalize_text(value)
    if "T" in text:
        text = text.split("T", 1)[0]
    return parse_date_any(text)


def siemens_ruggedcom_milestone_dates(lifecycle: dict[str, Any]) -> dict[str, str]:
    dates: dict[str, str] = {}
    for milestone in lifecycle.get("mileStones") or []:
        if not isinstance(milestone, dict):
            continue
        code = normalize_text(milestone.get("code") or milestone.get("id"))
        parsed = siemens_ruggedcom_date(milestone.get("date"))
        if code and parsed:
            dates[code] = parsed
    current = lifecycle.get("currentMilestone")
    if isinstance(current, dict):
        code = normalize_text(current.get("code") or current.get("id"))
        parsed = siemens_ruggedcom_date(current.get("date"))
        if code and parsed:
            dates.setdefault(code, parsed)
    return dates


def siemens_ruggedcom_device_type(
    short_text: str,
    description: str,
    *,
    is_software: bool,
) -> str:
    text = normalize_header(f"{short_text} {description}")
    if is_software or "software" in text or "license" in text:
        return "RUGGEDCOM software"
    if any(token in text for token in ("firewall", "vpn", "security appliance")):
        return "Industrial security appliance"
    if "router" in text and "switch" in text:
        return "Industrial switch/router"
    if "switch" in text:
        return "Industrial Ethernet switch"
    if "serial to ethernet" in text or "serial-to-ethernet" in description.lower():
        return "Serial-to-Ethernet server"
    if "sfp" in text or "transceiver" in text:
        return "RUGGEDCOM network transceiver module"
    if "arrestor" in text or "accessory" in text:
        return "RUGGEDCOM network accessory"
    return "RUGGEDCOM industrial network device"


def siemens_ruggedcom_successor_text(lifecycle: dict[str, Any]) -> str:
    successor = lifecycle.get("successor") or lifecycle.get("substitute")
    if not isinstance(successor, dict):
        return normalize_text(lifecycle.get("successorHint"))
    parts = [
        normalize_text(successor.get("articleNumber")),
        normalize_text(successor.get("description")),
    ]
    return " / ".join(part for part in parts if part)


def extract_siemens_ruggedcom_lifecycle_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.endswith("_products_and_prices.json"):
        return []
    data = load_json(path)
    products = data.get("products")
    if not isinstance(products, list):
        return []

    rows: list[dict[str, Any]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        info = product.get("productInformation")
        if not isinstance(info, dict):
            continue
        lifecycle = info.get("lifeCycle")
        if not isinstance(lifecycle, dict):
            continue
        milestone_dates = siemens_ruggedcom_milestone_dates(lifecycle)
        current = lifecycle.get("currentMilestone")
        current_code = ""
        if isinstance(current, dict):
            current_code = normalize_text(current.get("code") or current.get("id"))
        if not current_code:
            current_code = normalize_text(lifecycle.get("plmEffectiveLabel"))

        identifiers = info.get("productIdentifiers") or {}
        article_number = normalize_text(identifiers.get("articleNumber"))
        mlfb = normalize_text(identifiers.get("mlfb")) or normalize_text(product.get("mlfb"))
        model = normalize_text(info.get("materialShortText")) or mlfb or article_number
        description = normalize_text(info.get("description"))
        if not (model and (article_number or mlfb)):
            continue

        row: dict[str, Any] = {
            "Model": model,
            "Part Number": article_number or mlfb,
            "Product Name": model,
            "Description": siemens_ruggedcom_device_type(
                model,
                description,
                is_software=bool(info.get("isSoftware")),
            ),
            "Product Status": "",
            "Lifecycle Status Source": SIEMENS_RUGGEDCOM_PLM_URL,
            "_source_table": f"{path.name} products",
            "_source_hint": "Siemens Ruggedcom Industry Mall PLM JSON import",
            "_source_url": siemens_ruggedcom_product_url(mlfb or article_number),
            "_review_policy": "siemens_ruggedcom_plm_milestone_mapping",
            "_aliases": [
                model,
                article_number,
                mlfb,
                normalize_text(product.get("originalArticleNumber")),
            ],
            "_prefer_model": True,
        }
        replacement = siemens_ruggedcom_successor_text(lifecycle)
        if replacement:
            row["Replacement Products"] = replacement
        if milestone_dates.get("P.M400"):
            row["Announcement Date"] = milestone_dates["P.M400"]

        if (
            current_code in {"P.M500", "P.M490"}
            or lifecycle.get("plmEffectiveLabel") == "lblPI_PMDMilestone500"
        ):
            eol = milestone_dates.get("P.M490") or siemens_ruggedcom_date(
                lifecycle.get("plmEffectiveDate")
            )
            if not eol:
                continue
            row["End of Life"] = eol
            row["End of Support"] = eol
            row["Product Status"] = (
                "Siemens PLM product end of life; product no longer available "
                "and support discontinued"
            )
        elif current_code == "P.M410" or lifecycle.get("phasedOut"):
            cancellation = (
                milestone_dates.get("P.M410")
                or siemens_ruggedcom_date(lifecycle.get("phasedOutSinceDate"))
                or siemens_ruggedcom_date(lifecycle.get("plmEffectiveDate"))
            )
            if not cancellation:
                continue
            row["End of Sale"] = cancellation
            row["Last Sale"] = cancellation
            row["Product Status"] = (
                "Siemens PLM product cancellation; product can only be ordered "
                "as a spare part"
            )
        else:
            continue

        rows.append(row)
    return rows


def extract_vendor_json_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug == "acti":
        return extract_acti_eol_json_rows(path)
    if vendor_slug == "avm_fritzbox":
        return extract_avm_fritzbox_status_rows(path)
    if vendor_slug == "cyberdata":
        return extract_cyberdata_eol_product_rows(path)
    if vendor_slug == "hp_printers_official":
        return extract_hp_designjet_eosl_json_rows(path)
    if vendor_slug == "iogear":
        return extract_iogear_eol_product_json_rows(path)
    if vendor_slug == "legrand_luxul":
        return extract_legrand_luxul_discontinued_search_rows(path)
    if vendor_slug == "netapp":
        return extract_netapp_software_version_support_rows(path)
    if vendor_slug == "pepperl_fuchs":
        return extract_pepperl_fuchs_archive_rows(path)
    if vendor_slug == "qnap":
        return extract_qnap_product_status_api_rows(path)
    if vendor_slug == "rockwell_automation":
        return extract_rockwell_stratix_lifecycle_rows(path)
    if vendor_slug == "siemens_ruggedcom":
        return extract_siemens_ruggedcom_lifecycle_rows(path)
    if vendor_slug == "thecus_nas":
        return extract_thecus_nas_archive_rows(path)
    if vendor_slug == "verkada":
        return extract_verkada_end_of_sale_rows(path)
    return []


def extract_pdf_text(path: Path, *, raw: bool = False) -> str:
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        return ""
    source_path = path
    temp_pdf = None
    try:
        if path.read_bytes()[:2] == b"\x1f\x8b":
            temp_pdf = tempfile.NamedTemporaryFile(suffix=".pdf")
            temp_pdf.write(gzip.open(path, "rb").read())
            temp_pdf.flush()
            source_path = Path(temp_pdf.name)
    except Exception:
        return ""
    args = [pdftotext, "-raw" if raw else "-layout", str(source_path), "-"]
    try:
        completed = subprocess.run(
            args,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return ""
    finally:
        if temp_pdf is not None:
            temp_pdf.close()
    return completed.stdout


def pdf_lifecycle_date(text: str, labels: tuple[str, ...]) -> str | None:
    date_pattern = (
        r"(?:\d{1,2}/\d{1,2}/\d{2,4}|"
        r"[A-Za-z]{3,9}[-\s]+\d{1,2},?\s+\d{4}|"
        r"[A-Za-z]{3,9}-\d{1,2}-\d{4})"
    )
    lines = text.splitlines()
    for label in labels:
        normalized_label = normalize_header(label)
        for index, line in enumerate(lines):
            if not normalize_header(line).startswith(normalized_label):
                continue
            window = " ".join(lines[index:index + 8])
            match = re.search(date_pattern, window, flags=re.I)
            if match:
                parsed = parse_date_any(match.group(0), dayfirst=False)
                if parsed:
                    return parsed
    return None


def calix_document_date(text: str) -> str | None:
    match = re.search(
        r"\bDATE:\s*([A-Za-z]{3,9}-\d{1,2}-\d{4}|\d{1,2}/\d{1,2}/\d{2,4})",
        text,
        flags=re.I,
    )
    if match:
        return parse_date_any(match.group(1))
    return None


def parse_calix_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if "CUSTOMER ADVISORY" not in text or "Calix" not in text:
        return []
    affected_text = re.split(
        r"\n\s*REPLACEMENT PRODUCT DETAILS\b",
        text,
        maxsplit=1,
        flags=re.I,
    )[0]
    dates = {
        "Announcement Date": pdf_lifecycle_date(
            text,
            (
                "Product End of Sale announcement date",
                "End of life announcement date",
            ),
        ) or calix_document_date(text),
        "End of Sale": pdf_lifecycle_date(
            text,
            ("End of Sale date",),
        ),
        "End of Support": pdf_lifecycle_date(
            text,
            ("End of Support date",),
        ),
    }
    extracted = []
    for raw_line in affected_text.splitlines():
        match = re.match(r"^\s*(\d{3}-\d{5})\s{2,}(.+?)\s{2,}(.+?)\s*$", raw_line)
        if not match:
            continue
        part_number, part_name, description = (normalize_text(item) for item in match.groups())
        if normalize_header(part_name) in {"part name", "current part name"}:
            continue
        if not any(char.isalpha() for char in part_name + description):
            continue
        row: dict[str, Any] = {
            "Part Number": part_number,
            "Product Name": part_name,
            "Description": description,
            "Product Status": "customer advisory bulletin",
            "_source_table": f"{source_name} affected part table",
            "_source_hint": "Calix customer advisory bulletin PDF import",
        }
        for header, value in dates.items():
            if value:
                row[header] = value
        if any(header in row for header in ("End of Sale", "End of Support", "Announcement Date")):
            extracted.append(row)
    return extracted


def parse_aruba_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if "HPE ARUBA HARDWARE END OF SALE" not in text:
        return []
    extracted = []
    for raw_line in text.splitlines():
        if not re.match(r"^\s*[A-Z]{1,3}\d{2,5}[A-Z]\s{2,}", raw_line):
            continue
        date_matches = list(re.finditer(r"\d{1,2}/\d{1,2}/\d{4}", raw_line))
        if len(date_matches) < 2:
            continue
        sku = normalize_text(raw_line[: date_matches[0].start()]).split(" ", 1)[0]
        before_dates = raw_line[: date_matches[0].start()]
        columns = [normalize_text(part) for part in re.split(r"\s{2,}", before_dates.strip()) if normalize_text(part)]
        if len(columns) < 3:
            continue
        product_family = columns[1]
        description = " ".join(columns[2:])
        announcement = parse_date_any(date_matches[0].group(0))
        end_of_sale = parse_date_any(date_matches[1].group(0))
        after_dates = raw_line[date_matches[-1].end() :]
        replacement = ""
        replacement_description = ""
        after_parts = [
            normalize_text(part)
            for part in re.split(r"\s{2,}", after_dates.strip())
            if normalize_text(part)
        ]
        if after_parts:
            replacement = after_parts[0]
            replacement_description = " ".join(after_parts[1:])
        if not sku or not end_of_sale:
            continue
        row = {
            "Part Number": sku,
            "Product Name": description or sku,
            "Description": product_family,
            "Announcement Date": announcement,
            "End of Sale": end_of_sale,
            "Replacement Products": " / ".join(
                part
                for part in (replacement, replacement_description)
                if part and normalize_header(part) not in {"n a", "na"}
            ),
            "Product Status": "end-of-sale",
            "_source_table": f"{source_name} hardware end-of-sale PDF table",
            "_source_hint": "Aruba HPE hardware end-of-sale PDF import",
        }
        extracted.append({k: v for k, v in row.items() if v})
    return extracted


def parse_westermo_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if "Westermo" not in text or "Discontinuation Date" not in text:
        return []
    extracted = []
    for raw_line in text.splitlines():
        if not re.match(r"^\s*\d{4}-\d{4}\s{2,}", raw_line):
            continue
        date_match = re.search(r"[A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}", raw_line)
        if not date_match:
            continue
        before_date = raw_line[: date_match.start()]
        columns = [normalize_text(part) for part in re.split(r"\s{2,}", before_date.strip()) if normalize_text(part)]
        if len(columns) < 2:
            continue
        part_number, description = columns[0], columns[1]
        discontinuation = parse_date_any(date_match.group(0))
        after = raw_line[date_match.end() :]
        after_parts = [
            normalize_text(part).rstrip("*")
            for part in re.split(r"\s{2,}", after.strip())
            if normalize_text(part)
        ]
        replacement = " / ".join(after_parts)
        extracted.append(
            {
                "Part Number": part_number,
                "Product Name": description,
                "Description": description,
                "End of Sale": discontinuation,
                "Replacement Products": replacement,
                "Product Status": "discontinued",
                "_source_table": f"{source_name} discontinuation PDF table",
                "_source_hint": "Westermo life-cycle notification PDF import",
                "_force_lifecycle_review": True,
                "_review_policy": "discontinued_not_security_eol",
            }
        )
    return extracted


def parse_avigilon_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if "Avigilon" not in text or "Product End of Life" not in text:
        return []
    support_end = None
    support_match = re.search(
        r"continue to support .*? until\s+([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        normalize_text(text),
        flags=re.I,
    )
    if support_match:
        support_end = parse_date_any(support_match.group(1))
    issue_date = None
    issue_match = re.search(
        r"Date of Issue:\s*([A-Za-z]{3,9}\.?\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    if issue_match:
        issue_date = parse_date_any(issue_match.group(1))

    sku_pattern = (
        r"([0-9.]+[A-Z]-H5A-FE-[A-Z0-9-]+(?:-\s*IR)?)"
        r".*?"
        r"([0-9.]+[A-Z]-H6A-FE-[A-Z0-9-]+(?:-\s*IR)?)"
    )
    extracted: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        normalized_line = re.sub(r"-\s+IR\b", "-IR", raw_line)
        match = re.search(sku_pattern, normalized_line)
        if not match:
            continue
        sku = normalize_text(match.group(1).replace("- ", "-"))
        replacement = normalize_text(match.group(2).replace("- ", "-"))
        row: dict[str, Any] = {
            "Model": sku,
            "Part Number": sku,
            "Product Name": f"Avigilon Unity H5A Fisheye {sku}",
            "Description": "H5A Fisheye camera",
            "Product Status": "Product End of Life (EOL); discontinued",
            "Replacement Products": replacement,
            "_source_table": f"{source_name} discontinued product table",
            "_source_hint": "Avigilon Unity H5A Fisheye EOL notice PDF import",
        }
        if issue_date:
            row["Announcement Date"] = issue_date
        if support_end:
            row["End of Support"] = support_end
        extracted.append(row)
    return extracted


def parse_celona_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Celona" not in normalized or "End of Support" not in normalized:
        return []
    if "Product:" not in text:
        return []

    product_match = re.search(
        r"(?:^|\n)\s*(?:[-*\u2022]\s*)?Product:\s*(.+)",
        text,
        flags=re.I,
    )
    if not product_match:
        return []
    product_name = normalize_text(product_match.group(1))
    replacement_match = re.search(
        r"(?:[-*\u2022]\s*)?(?:Recommended\s+)?Replacement:\s*(.+)",
        text,
        flags=re.I,
    )
    replacement = normalize_text(replacement_match.group(1)) if replacement_match else ""

    announcement = pdf_lifecycle_date(text, ("EoL Announcement",))
    end_sale = pdf_lifecycle_date(text, ("End-of-Sale", "End of Sale"))
    support_end = pdf_lifecycle_date(text, ("End of Support",))
    if not support_end:
        return []

    model_match = re.search(r"\b(AP\d{2}-\d{2})\b", product_name)
    if model_match:
        model = model_match.group(1)
        description = normalize_text(
            re.sub(r"[-\u2010-\u2015]\s*" + re.escape(model) + r"\b", "", product_name)
        )
    elif "Edge Enterprise Appliance" in product_name:
        model = "Edge Enterprise Appliance (1st Gen)"
        description = "Private wireless edge appliance"
    else:
        model = product_name
        description = "Private wireless product"

    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": product_name,
        "Description": description or product_name,
        "Product Status": "End-of-Life announcement; End of Support (EoST) listed",
        "End of Support": support_end,
        "End of Vulnerability Support": support_end,
        "Replacement Products": replacement,
        "_source_table": f"{source_name} product lifecycle announcement",
        "_source_hint": "Celona product lifecycle EoL announcement PDF import",
        "_prefer_model": True,
    }
    if announcement:
        row["Announcement Date"] = announcement
    if end_sale:
        row["End of Sale"] = end_sale
    return [row]


def parse_alcatel_lucent_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "OmniSwitch" not in normalized or "End-of-Sales product life" not in normalized:
        return []
    match = re.search(
        r"effective\s+([A-Za-z]+\s+\d{1,2},\s+\d{4}),\s+and\s+"
        r"([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        normalized,
        flags=re.I,
    )
    if not match:
        return []
    first_date = parse_date_any(match.group(1))
    second_date = parse_date_any(match.group(2))
    if not first_date or not second_date:
        return []

    rows = []
    for model, end_sale in (
        ("OmniSwitch 6850", first_date),
        ("OmniSwitch 6850E", second_date),
    ):
        rows.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": f"{model} switch family",
                "Description": "Stackable LAN switch family",
                "Product Status": "End-of-Sales product life cycle",
                "End of Sale": end_sale,
                "Replacement Products": "Stackable LAN OmniSwitch 6860 product family",
                "_source_table": f"{source_name} end-of-life notice",
                "_source_hint": "Alcatel-Lucent Enterprise OmniSwitch End-of-Sales PDF import",
                "_prefer_model": True,
            }
        )
    return rows


AVAYA_ORDER_CODE_RE = re.compile(r"\b[A-Z]{2}[A-Z0-9]{6,9}-[A-Z0-9]{2,5}\b")


def avaya_pdf_schedule_date(text: str, labels: tuple[str, ...]) -> str | None:
    date_pattern = (
        r"(?:\d{1,2}/\d{1,2}/\d{2,4}|"
        r"[A-Za-z]{3,9}[-\s]+\d{1,2},?\s+\d{4}|"
        r"[A-Za-z]{3,9}-\d{1,2}-\d{4})"
    )
    for label in labels:
        normalized_label = normalize_header(label)
        for line in text.splitlines():
            if not normalize_header(line).startswith(normalized_label):
                continue
            match = re.search(date_pattern, line, flags=re.I)
            if not match:
                return None
            return parse_date_any(match.group(0), dayfirst=False)
    return None


def avaya_model_from_description(description: str) -> str:
    for pattern in (
        r"\bERS\s*([0-9]{4}[A-Z0-9+-]*)(?=\s|$)",
        r"\bEthernet Routing Switch\s+([0-9]{4}[A-Z0-9+-]*)(?=\s|$)",
    ):
        match = re.search(pattern, description, flags=re.I)
        if match:
            return f"ERS {match.group(1)}"
    return ""


def avaya_discontinued_order_codes(text: str) -> list[tuple[str, str]]:
    try:
        section = re.split(r"\n\s*Schedule\b", text, maxsplit=1, flags=re.I)[0]
        section = re.split(
            r"\n\s*Discontinued Order Codes\b",
            section,
            maxsplit=1,
            flags=re.I,
        )[1]
    except IndexError:
        return []

    ignored_headers = {
        "code",
        "description",
        "discontinued order codes",
        "material offer",
        "material offer code",
        "order code",
    }
    items: list[tuple[str, list[str]]] = []
    current_code = ""
    current_parts: list[str] = []
    for raw_line in section.splitlines():
        line = normalize_text(raw_line)
        if not line:
            continue
        normalized = normalize_header(line)
        if normalized in ignored_headers or normalized.startswith("all rights reserved"):
            continue
        if normalized.startswith("trademarks") or normalized.startswith("respective owners"):
            continue
        match = AVAYA_ORDER_CODE_RE.search(line)
        if match:
            if current_code:
                items.append((current_code, current_parts))
            current_code = match.group(0)
            current_parts = [normalize_text(line[: match.start()] + " " + line[match.end() :])]
            continue
        if current_code:
            current_parts.append(line)
    if current_code:
        items.append((current_code, current_parts))

    result = []
    for code, description_parts in items:
        description = normalize_text(" ".join(part for part in description_parts if part))
        if not re.match(
            r"^(?:Federal TAA\.\s*)?(?:ERS|Ethernet Routing Switch)\b",
            description,
            flags=re.I,
        ):
            continue
        result.append((code, description))
    return result


def parse_avaya_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if "End of Sale Notice" not in text or "Avaya" not in text:
        return []
    order_codes = avaya_discontinued_order_codes(text)
    if not order_codes:
        return []

    announcement = avaya_pdf_schedule_date(text, ("Notification Date", "Revised Date", "Date"))
    end_sale = avaya_pdf_schedule_date(text, ("End of Sale Date",))
    software_eoms = avaya_pdf_schedule_date(text, ("End of Manufacturer Support for SOFTWARE",))
    hardware_eoms = avaya_pdf_schedule_date(text, ("End of Manufacturer Support for HARDWARE",))
    services_end = avaya_pdf_schedule_date(text, ("Targeted End of Services Support",))

    rows = []
    for order_code, description in order_codes:
        model = avaya_model_from_description(description)
        if not model:
            continue
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": order_code,
            "Product Name": f"Avaya {model}",
            "Description": description,
            "Product Status": "End of Sale notice",
            "_source_table": f"{source_name} discontinued order codes",
            "_source_hint": "Avaya Ethernet Routing Switch end-of-sale notice PDF import",
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if end_sale:
            row["End of Sale"] = end_sale
        if software_eoms:
            row["End of Vulnerability Support"] = software_eoms
            row["Product Status"] = "End of Sale notice; End of Manufacturer Support for Software listed"
        if hardware_eoms:
            row["End of Hardware Support"] = hardware_eoms
        if services_end:
            row["End of Service"] = services_end
        if not software_eoms and (hardware_eoms or services_end):
            row["_force_lifecycle_review"] = True
            row["_review_policy"] = "avaya_hardware_or_targeted_service_date_not_security_eol"
            row["_review_reason"] = (
                "Avaya source gives hardware or targeted services support dates, "
                "but no exact software/security-update end date for this product."
            )
        rows.append(row)
    return rows


GEOVISION_PRODUCT_RE = re.compile(
    r"\b(?:"
    r"GV[_-]DSP[_-]LPR[_-]V[23]|"
    r"GV[_-]IPCAMD[_-]GV[_-][A-Z0-9]+|"
    r"GV[_-]GM8186[_-]VS14|"
    r"GV[-_]VS14[_-]VS14|"
    r"GV[_-]VS(?:03|2410|28XX|216XX)|"
    r"GV\s+VS04[AH]|"
    r"GV-VS1[12]|"
    r"GVLX\s+4\s+V[23]"
    r")\b"
)


def geovision_device_description(model: str) -> str:
    normalized = normalize_header(model)
    if "ipcamd" in normalized:
        return "IP camera"
    if "vs" in normalized:
        return "Video server"
    if "gvlx" in normalized:
        return "DVR"
    if "lpr" in normalized:
        return "License plate recognition device"
    return "IP video device"


def parse_geovision_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "GeoVision Security Advisory" not in normalized or "reached their end of life" not in normalized:
        return []
    release_date = None
    release_match = re.search(
        r"Release Date:\s*([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    if release_match:
        release_date = parse_date_any(release_match.group(1))

    english_text = re.split(
        r"\n\s*\u5947\u5076\u79d1\u6280\u5b89\u5168\u6027\u901a\u544a",
        text,
        maxsplit=1,
    )[0]
    models = [
        normalize_text(match.group(0))
        for match in GEOVISION_PRODUCT_RE.finditer(english_text)
    ]
    rows = []
    for model in dict.fromkeys(models):
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"GeoVision {model}",
            "Description": geovision_device_description(model),
            "Product Status": "EOL; no longer maintained",
            "_source_table": f"{source_name} affected product list",
            "_source_hint": "GeoVision EOL IP device security advisory review import",
            "_status_only_review": True,
            "_review_policy": "geovision_eol_no_longer_maintained_no_exact_date",
            "_review_reason": (
                "Source says the affected devices are no longer maintained and "
                "have reached EOL, but it does not provide an exact support or "
                "security-update end date."
            ),
            "_prefer_model": True,
        }
        if release_date:
            row["Announcement Date"] = release_date
        rows.append(row)
    return rows


def parse_advantech_ntron_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    announcement = None
    phase_out = None
    announcement_match = re.search(
        r"Announcement\s+Announcement of this document\s+(\d{4}/\d{1,2}/\d{1,2})",
        text,
        flags=re.I,
    )
    if announcement_match:
        announcement = parse_date_any(announcement_match.group(1))
    phase_out_match = re.search(
        r"Phase-out\s+The product is officially phased out\.\s+(\d{4}/\d{1,2}/\d{1,2})",
        text,
        flags=re.I,
    )
    if phase_out_match:
        phase_out = parse_date_any(phase_out_match.group(1))

    rows: list[dict[str, Any]] = []
    in_table = False
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = normalize_text(raw_line)
        if "Product Part Numbers Affected by This Announcement" in line:
            in_table = True
            continue
        if in_table and "Reason for the Change" in line:
            break
        if not in_table or not line:
            continue
        match = re.match(
            r"^(BB-[A-Z0-9-]+)\s+([A-Z0-9][A-Z0-9-]+)\s+Available Now\b",
            line,
        )
        if not match:
            continue
        model, replacement = match.groups()
        if model in seen:
            continue
        seen.add(model)
        row = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Advantech {model}",
            "Description": "Industrial Ethernet switch or media converter",
            "Product Status": "End of Life / phase-out notice",
            "Replacement Products": replacement,
            "_source_table": f"{source_name} product part numbers affected",
            "_source_hint": "Advantech IIoT product EOL phase-out notice",
            "_status_only_review": True,
            "_review_policy": "advantech_phase_out_not_security_eol",
            "_review_reason": (
                "Advantech announces EOL/phase-out and replacement products, "
                "but the captured source does not provide an exact support or "
                "security-update end date."
            ),
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement"] = announcement
        if phase_out:
            row["_phase_out_date"] = phase_out
        rows.append(row)
    return rows


def parse_pilz_pnozmulti_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if (
        "PNOZmulti generation change" not in normalized
        or not re.search(r"phasing out(?:\s+and|,)\s+discontinuation", normalized, flags=re.I)
        or "Last Order" not in normalized
    ):
        return []

    last_order_match = re.search(r"\bLast Order:\s*(\d{1,2}\.\d{1,2}\.\d{4})", text, flags=re.I)
    if not last_order_match:
        return []
    last_order = parse_date_any(last_order_match.group(1))
    if not last_order:
        return []

    last_delivery = None
    last_delivery_match = re.search(
        r"\bLast Delivery:\s*(\d{1,2}\.\d{1,2}\.\d{4})",
        text,
        flags=re.I,
    )
    if last_delivery_match:
        last_delivery = parse_date_any(last_delivery_match.group(1))

    description_suffix = (
        f"; last delivery {last_delivery}"
        if last_delivery
        else ""
    )
    common = {
        "Product Status": "Phasing out and discontinuation",
        "End of Sale": last_order,
        "_source_table": f"{source_name} PNOZmulti generation change notice",
        "_source_hint": "Pilz PNOZmulti generation-change discontinuation PDF import",
        "_status_only_review": True,
        "_review_policy": "pilz_last_order_not_security_eol",
        "_review_reason": (
            "Pilz source gives phasing-out, discontinuation, last-order, and "
            "last-delivery information, but it does not provide an exact "
            "support or security-update end date."
        ),
        "_prefer_model": True,
    }

    rows: list[dict[str, Any]] = [
        {
            **common,
            "Model": "PNOZmulti Classic",
            "Part Number": "773100-773830",
            "Product Name": "Pilz PNOZmulti Classic",
            "Description": (
                "PNOZmulti Classic configurable safe small controllers incl. "
                "expansions and fieldbus modules; item number range "
                "773100 - 773830 + clamps"
                f"{description_suffix}"
            ),
            "Replacement Products": "PNOZmulti 2; PNOZ m B0; PNOZ m B1",
            "_aliases": [
                "PNOZmulti Classic System",
                "PNOZ m0p",
                "PNOZ m1p",
                "PNOZ m1p ETH",
                "PNOZ m2p",
                "PNOZ m3p",
                "773100",
                "773103",
                "773104",
                "773105",
                "773110",
                "773120",
                "773123",
                "773125",
                "773126",
            ],
        },
        {
            **common,
            "Model": "PNOZmulti Mini",
            "Part Number": "772000-772036",
            "Product Name": "Pilz PNOZmulti Mini",
            "Description": (
                "PNOZmulti Mini configurable safe compact controllers incl. "
                "extensions; item number range 772000 - 772036"
                f"{description_suffix}"
            ),
            "Replacement Products": "PNOZmulti 2; PNOZ m B0.1; PNOZ m B0",
            "_aliases": [
                "PNOZ mm0p",
                "PNOZ mm0.1p",
                "PNOZ mm0.2p",
                "PNOZ mm0p-T",
                "772000",
                "772001",
                "772002",
                "772010",
            ],
        },
    ]

    exact_products = [
        (
            "PNOZ m0p",
            "773110",
            ["PNOZmulti Classic", "773110"],
            "PNOZmulti Classic configurable safe small controller base unit",
            "PNOZmulti 2; PNOZ m C0; PNOZ m B0.1; PNOZ m B0; PNOZ m B1",
        ),
        (
            "PNOZ m1p",
            "773100",
            ["PNOZmulti Classic", "773103", "773104", "773105", "PNOZ m1p ETH"],
            "PNOZmulti Classic configurable safe small controller base unit",
            "PNOZmulti 2; PNOZ m C0; PNOZ m B0.1; PNOZ m B0; PNOZ m B1",
        ),
        (
            "PNOZ m2p",
            "773120",
            ["PNOZmulti Classic", "773123"],
            "PNOZmulti Classic configurable safe small controller base unit",
            "PNOZmulti 2; PNOZ m C0; PNOZ m B0.1; PNOZ m B0; PNOZ m B1",
        ),
        (
            "PNOZ m3p",
            "773125",
            ["PNOZmulti Classic", "773126"],
            "PNOZmulti Classic configurable safe small controller base unit",
            "PNOZmulti 2; PNOZ m C0; PNOZ m B0.1; PNOZ m B0; PNOZ m B1",
        ),
        (
            "PNOZ mm0p",
            "772000",
            ["PNOZmulti Mini"],
            "PNOZmulti Mini configurable safe compact controller base unit",
            "PNOZmulti 2; PNOZ m B0.1; PNOZ m B0",
        ),
        (
            "PNOZ mm0.1p",
            "772001",
            ["PNOZmulti Mini"],
            "PNOZmulti Mini configurable safe compact controller base unit",
            "PNOZmulti 2; PNOZ m B0.1; PNOZ m B0",
        ),
        (
            "PNOZ mm0.2p",
            "772002",
            ["PNOZmulti Mini"],
            "PNOZmulti Mini configurable safe compact controller base unit",
            "PNOZmulti 2; PNOZ m B0.1; PNOZ m B0",
        ),
        (
            "PNOZ mm0p-T",
            "772010",
            ["PNOZmulti Mini", "coated version"],
            "PNOZmulti Mini coated configurable safe compact controller base unit",
            "PNOZmulti 2 software migration possible",
        ),
    ]
    for model, part_number, aliases, description, replacement in exact_products:
        if model not in text and part_number not in text:
            continue
        rows.append(
            {
                **common,
                "Model": model,
                "Part Number": part_number,
                "Product Name": f"Pilz {model}",
                "Description": f"{description}{description_suffix}",
                "Replacement Products": replacement,
                "_aliases": [part_number, f"Pilz {model}", *aliases],
            }
        )

    return rows


def broadcom_brocade_pdf_date(text: str, pattern: str) -> str | None:
    match = re.search(
        pattern + r"\s+([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    if not match:
        return None
    return parse_date_any(match.group(1))


def parse_broadcom_brocade_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Product EOL Notice" not in normalized or "Brocade" not in normalized:
        return []
    if "Brocade Part Number" not in normalized:
        return []

    family_match = re.search(r"Brocade\S*\s+([A-Z]?\d{3,4})\s+Switch", text, flags=re.I)
    if not family_match:
        return []
    family_model = family_match.group(1).upper()
    family_name = f"Brocade {family_model} Switch"

    announcement = broadcom_brocade_pdf_date(
        text,
        r"End-of-Life(?:\s+\(EOL\))?\s+Notification\s+Date",
    )
    last_order = broadcom_brocade_pdf_date(
        text,
        r"Last\s+Time\s+Order.*?Due\s+Date",
    )
    last_ship = broadcom_brocade_pdf_date(
        text,
        r"Last\s+Customer\s+Ship(?:\s+\(LCS\))?\s+Date",
    )
    support_end = broadcom_brocade_pdf_date(
        text,
        r"End-of-Support(?:\s+\(EOS\))?\s+Date",
    )
    end_sale = last_order or last_ship
    if not support_end:
        return []

    try:
        table_text = re.split(r"\n\s*Brocade Part Number\b", text, maxsplit=1)[1]
    except IndexError:
        return []
    table_text = re.split(r"\n\s*Revision History\b", table_text, maxsplit=1)[0]

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in table_text.splitlines():
        line = normalize_text(raw_line)
        if not re.match(r"^(?:BR|XBR)-[A-Z0-9-]+\b", line):
            continue
        columns = [
            normalize_text(part)
            for part in re.split(r"\s{2,}", raw_line.strip())
            if normalize_text(part)
        ]
        if len(columns) < 2:
            continue
        part_number = columns[0]
        if part_number in seen:
            continue
        seen.add(part_number)
        description = columns[1]
        replacement = columns[2] if len(columns) >= 3 else ""
        if normalize_header(replacement) in {"n a", "na"}:
            replacement = ""
        device_type = (
            "Fibre Channel switch FRU"
            if part_number.startswith("XBR-")
            else "Fibre Channel switch"
        )
        row: dict[str, Any] = {
            "Model": part_number,
            "Part Number": part_number,
            "Product Name": f"{family_name} {part_number}",
            "Description": f"{device_type}; {description}",
            "Product Status": "End-of-Life notice; support continues until End-of-Support",
            "End of Support": support_end,
            "Replacement Products": replacement,
            "_source_table": f"{source_name} Brocade part number table",
            "_source_hint": "Broadcom Brocade product EOL notice PDF import",
            "_aliases": [family_name, family_model, part_number],
        }
        if announcement:
            row["Announcement Date"] = announcement
        if end_sale:
            row["End of Sale"] = end_sale
        if last_ship:
            row["Last Sale"] = last_ship
        rows.append({key: value for key, value in row.items() if value})
    return rows


def hirschmann_belden_milestone_date(text: str, label: str) -> str | None:
    target = normalize_header(label)
    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    for index, line in enumerate(lines):
        if normalize_header(line).startswith(target):
            parsed = first_parsed_date(line)
            if parsed:
                return parsed
            parsed = first_parsed_date(" ".join(lines[index:index + 4]))
            if parsed:
                return parsed
    return None


def parse_hirschmann_belden_pdn_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Product Discontinuation Announcement" not in normalized:
        return []
    if "MACH102 Product Family" not in normalized:
        return []
    if "Discontinuation Milestones" not in normalized:
        return []

    announcement = hirschmann_belden_milestone_date(
        text,
        "Discontinuation Announcement Date",
    )
    last_order = hirschmann_belden_milestone_date(text, "Last Order Date")
    last_delivery = hirschmann_belden_milestone_date(text, "Last Delivery Date")
    last_service = hirschmann_belden_milestone_date(text, "Last Service Date")
    if not last_order or not last_service:
        return []

    replacement = ""
    replacement_match = re.search(r"\b(942298xxx)\s+GRS103\b", normalized)
    if replacement_match:
        replacement = f"GRS103 family ({replacement_match.group(1)})"

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = normalize_text(raw_line)
        match = re.match(r"^(943969\d{3})\s+(MACH102-[A-Z0-9-]+)\b", line)
        if not match:
            continue
        part_number, model = match.groups()
        if part_number in seen:
            continue
        seen.add(part_number)
        description_parts = [
            "Industrial Ethernet switch",
            "MACH102 product family",
            "Classic Software platform",
        ]
        if last_delivery:
            description_parts.append(f"last delivery date {last_delivery}")
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": part_number,
            "Product Name": f"Hirschmann {model}",
            "Description": "; ".join(description_parts),
            "Product Status": "Discontinued product; Last Service Date published",
            "End of Sale": last_order,
            "End of Support": last_service,
            "Replacement Products": replacement,
            "_source_table": f"{source_name} MACH102 discontinued products table",
            "_source_hint": "Belden Hirschmann MACH102 product discontinuation notice import",
            "_aliases": [
                model,
                part_number,
                f"Hirschmann {model}",
                f"Belden Hirschmann {model}",
                "MACH102 Product Family",
            ],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        rows.append({key: value for key, value in row.items() if value})
    return rows


def nvidia_notice_date(text: str, *, prefer_new: bool = False) -> str | None:
    labels = ("New Notice Date", "Notice Date") if prefer_new else ("Notice Date",)
    for label in labels:
        match = re.search(
            rf"\b{re.escape(label)}\s*:?\s+"
            r"([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
            text,
            flags=re.I,
        )
        if match:
            parsed = parse_date_any(match.group(1))
            if parsed:
                return parsed
    return None


def parse_nvidia_mellanox_switchx_eol_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "MLNX-15-4122" not in normalized:
        return []
    if "SwitchX integrated circuit devices" not in normalized:
        return []

    announcement = nvidia_notice_date(text, prefer_new=True)
    last_order = pdf_lifecycle_date(text, ("Last Time Buy",))
    last_ship = pdf_lifecycle_date(text, ("Last Ship Date",))
    service_end = pdf_lifecycle_date(text, ("End of Service",))
    if not last_order or not service_end:
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        match = re.match(
            r"\s*(MT\d{5}A1-[A-Z0-9-]+)\s+"
            r"(MT\d{5}A2-[A-Z0-9-]+)\b",
            raw_line,
        )
        if not match:
            continue
        part_number, replacement = match.groups()
        if part_number in seen:
            continue
        seen.add(part_number)
        row: dict[str, Any] = {
            "Model": part_number,
            "Part Number": part_number,
            "Product Name": f"Mellanox SwitchX {part_number}",
            "Description": (
                "SwitchX InfiniBand, Ethernet, and VPI integrated circuit device"
            ),
            "Product Status": (
                "End of Life; End of Service contract renewal date published"
            ),
            "End of Sale": last_order,
            "End of Support": service_end,
            "Replacement Products": replacement,
            "_source_table": f"{source_name} SwitchX EOL product OPN table",
            "_source_hint": "NVIDIA Mellanox SwitchX EOL notification PDF import",
            "_aliases": [part_number, f"Mellanox {part_number}"],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if last_ship:
            row["Last Sale"] = last_ship
        rows.append(row)
    return rows


def parse_nvidia_mellanox_switchx2_gateway_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "LCR-000844" not in normalized:
        return []
    if "Mellanox SwitchX-2 InfiniBand to Ethernet Gateway" not in normalized:
        return []

    announcement = nvidia_notice_date(text)
    last_order = pdf_lifecycle_date(text, ("Last Time Buy",))
    last_ship = pdf_lifecycle_date(text, ("Last Ship Date",))
    if not last_order:
        return []

    product_rows = [
        (
            "MSX6710G-FS2F2",
            "Mellanox SwitchX-2 InfiniBand to Ethernet gateway, 36 QSFP+ ports, 2 AC power supplies, x86 dual core, standard depth, P2C airflow, rail kit",
        ),
        (
            "MSX6710G-FS2R2",
            "Mellanox SwitchX-2 InfiniBand to Ethernet gateway, 36 QSFP+ ports, 2 AC power supplies, x86 dual core, standard depth, C2P airflow, rail kit",
        ),
    ]
    rows: list[dict[str, Any]] = []
    for part_number, description in product_rows:
        if part_number not in text:
            continue
        row: dict[str, Any] = {
            "Model": part_number,
            "Part Number": part_number,
            "Product Name": f"Mellanox SwitchX-2 Gateway {part_number}",
            "Description": (
                f"{description}; last supported firmware fw-SX-rel-9_4_5070; "
                "last supported software 3.6.8010"
            ),
            "Product Status": (
                "End of Life notice; last supported firmware/software versions listed"
            ),
            "End of Sale": last_order,
            "Replacement Products": "MGA100-HS2",
            "_source_table": f"{source_name} SwitchX-2 gateway EOL product OPN table",
            "_source_hint": (
                "NVIDIA Mellanox SwitchX-2 InfiniBand to Ethernet Gateway EOL notice PDF import"
            ),
            "_aliases": [
                part_number,
                f"Mellanox {part_number}",
                f"SwitchX-2 Gateway {part_number}",
            ],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if last_ship:
            row["Last Sale"] = last_ship
        rows.append(row)
    return rows


def parse_nvidia_mellanox_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    rows = parse_nvidia_mellanox_switchx_eol_rows_from_text(text, source_name)
    rows.extend(parse_nvidia_mellanox_switchx2_gateway_rows_from_text(text, source_name))
    return rows


def parse_hikvision_discontinuation_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Product Discontinuation Notification" not in normalized or "Hikvision" not in normalized:
        return []
    if "at end-of life" not in normalized and "Discontinued" not in normalized:
        return []

    notice_date = None
    date_match = re.search(
        r"\bDate:\s*([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        text,
        flags=re.I,
    )
    if date_match:
        notice_date = parse_date_any(date_match.group(1))

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = normalize_text(raw_line)
        match = re.match(
            r"^(DS-[A-Z0-9]+)\s+(.+?)\s+\$[\d,]+\s+(DS-[A-Z0-9]+)\s+(.+?)\s+\$[\d,]+",
            line,
        )
        if not match:
            continue
        model, description, replacement, replacement_description = match.groups()
        if model in seen:
            continue
        seen.add(model)
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Hikvision {model} Network Switch",
            "Description": f"Ethernet PoE network switch; {normalize_text(description)}",
            "Product Status": "End-of-life; discontinued; warranty support continues under policy",
            "Replacement Products": " / ".join(
                part for part in (replacement, normalize_text(replacement_description)) if part
            ),
            "_source_table": f"{source_name} discontinued model table",
            "_source_hint": "Hikvision product discontinuation notification PDF import",
            "_status_only_review": True,
            "_review_policy": "hikvision_eol_warranty_support_no_exact_security_date",
            "_review_reason": (
                "Hikvision source says the product is end-of-life and discontinued, "
                "but it also says qualified products continue under warranty policy "
                "and does not provide an exact support or security-update end date."
            ),
            "_aliases": [model, "DS-3D2216P Network Switch"],
        }
        if notice_date:
            row["Announcement Date"] = notice_date
            row["End of Sale"] = notice_date
        rows.append(row)
    return rows


def helmholz_milestone_date(text: str, milestone: str) -> str | None:
    normalized = normalize_text(text)
    match = re.search(
        rf"\b{re.escape(milestone)}\*?\s+.*?(\d{{1,2}}\.\d{{1,2}}\.\d{{4}})",
        normalized,
        flags=re.I,
    )
    if not match:
        return None
    return parse_date_any(match.group(1))


def parse_helmholz_myrex24_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Notification of discontinued product" not in normalized or "myREX24 V1" not in normalized:
        return []
    if "EOL-SWS" not in normalized or "security" not in normalized.lower():
        return []

    announcement = helmholz_milestone_date(text, "EOL-NOT")
    last_order = helmholz_milestone_date(text, "EOL-ORD")
    software_security_end = helmholz_milestone_date(text, "EOL-SWS")
    service_shutdown = helmholz_milestone_date(text, "EOL-EOS")
    product_support_end = helmholz_milestone_date(text, "EOL-PS")
    if not software_security_end:
        return []

    support_note = (
        f"; product support ended {product_support_end}"
        if product_support_end
        else ""
    )
    shutdown_note = (
        f"; service shutdown {service_shutdown}"
        if service_shutdown
        else ""
    )
    row: dict[str, Any] = {
        "Model": "myREX24 V1 Portal",
        "Part Number": "myREX24 V1",
        "Product Name": "Helmholz myREX24 V1 Portal",
        "Description": (
            "Remote service portal; software and security updates ended "
            f"{software_security_end}{support_note}{shutdown_note}"
        ),
        "Product Status": (
            "Discontinued product; software and security updates ended; "
            "service shutdown scheduled"
        ),
        "End of Vulnerability Support": software_security_end,
        "_source_table": f"{source_name} myREX24 V1 lifecycle milestone table",
        "_source_hint": "Helmholz myREX24 V1 EOL document PDF import",
        "_aliases": [
            "myREX24 V1",
            "myREX24 V1 Portal",
            "myREX24 V1 Server",
            "myREX24.net",
            "web2go.myrex24.net",
            "vpn2.myREX24.net",
        ],
        "_prefer_model": True,
    }
    if announcement:
        row["Announcement Date"] = announcement
    if last_order:
        row["End of Sale"] = last_order
    if service_shutdown:
        row["End of Service"] = service_shutdown
    return [row]


def weidmueller_device_description(model: str) -> str:
    normalized = normalize_header(model)
    if normalized.startswith("ie sr"):
        return "Industrial Ethernet security router"
    if normalized.startswith("ie sw"):
        return "Industrial Ethernet switch"
    return "Industrial Ethernet product"


def parse_weidmueller_datasheet_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Weidm" not in normalized or "Delivery status Discontinued" not in normalized:
        return []
    order_match = re.search(r"\bOrder No\.\s+(\d{6,})\b", normalized)
    type_match = re.search(r"\bType\s+([A-Z0-9][A-Z0-9/-]+)\b", normalized)
    available_match = re.search(r"\bAvailable until\s+(\d{4}-\d{2}-\d{2})", normalized)
    replacement_match = re.search(
        r"\bAlternative product\s+([A-Z0-9][A-Z0-9/-]+)\b",
        normalized,
    )
    if not order_match or not type_match:
        return []
    model = type_match.group(1)
    available_until = parse_date_any(available_match.group(1)) if available_match else None
    replacement = replacement_match.group(1) if replacement_match else ""
    description = weidmueller_device_description(model)
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": order_match.group(1),
        "Product Name": f"Weidmueller {model}",
        "Description": description,
        "Product Status": "Delivery status discontinued",
        "Replacement Products": replacement,
        "_source_table": f"{source_name} general ordering data",
        "_source_hint": "Weidmueller discontinued product datasheet PDF import",
        "_force_lifecycle_review": True,
        "_review_policy": "weidmueller_discontinued_available_until_not_security_eol",
        "_review_reason": (
            "Weidmueller datasheet marks this product discontinued and gives "
            "an availability end date, but it does not provide an exact support "
            "or security-update end date."
        ),
        "_aliases": [model, order_match.group(1)],
        "_prefer_model": True,
    }
    if available_until:
        row["End of Sale"] = available_until
    return [{key: value for key, value in row.items() if value}]


def parse_eltako_safe_iv_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "PROFESSIONAL SMART HOME CONTROLLER SAFE IV" not in normalized:
        return []
    if "Discontinued on" not in normalized:
        return []

    replacements = "MiniSafe2; MiniSafe2-REG; WP2"
    rows: list[dict[str, Any]] = []
    for model, color in (
        ("Safe IV-rw", "pure white"),
        ("Safe IV-sz", "black"),
    ):
        pattern = rf"\b{re.escape(model)}\b.*?Discontinued on\s+(\d{{1,2}}\.\d{{1,2}}\.\d{{4}})"
        match = re.search(pattern, normalized, flags=re.I)
        if not match:
            continue
        discontinued = parse_date_any(match.group(1))
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Eltako Safe IV {color}",
            "Description": f"Smart Home controller Safe IV with GFVS 4.0 software, {color}",
            "Product Status": "Discontinued",
            "Replacement Products": replacements,
            "_source_table": f"{source_name} Safe IV discontinued products",
            "_source_hint": "Eltako Safe IV discontinued datasheet PDF import",
            "_force_lifecycle_review": True,
            "_review_policy": "eltako_discontinued_not_security_eol",
            "_review_reason": (
                "Eltako datasheet marks this Safe IV controller discontinued "
                "and lists alternatives, but it does not provide an exact "
                "support or security-update end date."
            ),
            "_aliases": [model, "Safe IV", "Eltako Safe IV", "GFVS Safe IV"],
            "_prefer_model": True,
        }
        if discontinued:
            row["End of Sale"] = discontinued
        rows.append(row)
    return rows


def atx_milestone_date(text: str, label: str) -> str | None:
    target = normalize_header(label)
    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    for index, line in enumerate(lines):
        header = normalize_header(line)
        if header == target:
            parsed = first_parsed_date(line)
            if parsed:
                return parsed
            for candidate in lines[index + 1:index + 8]:
                parsed = parse_date_any(candidate)
                if parsed:
                    return parsed
        elif header.startswith(f"{target} "):
            parsed = first_parsed_date(line)
            if parsed:
                return parsed
    return None


def parse_atx_digistream_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if "DigiStream Product Line" not in text and "DigiStream product line" not in text:
        return []
    if "End-of-Software Maintenance" not in text:
        return []

    announcement = atx_milestone_date(text, "End-of-Life Announcement")
    end_sale = atx_milestone_date(text, "End-of-Sale")
    software_end = atx_milestone_date(text, "End-of-Software Maintenance")
    support_end = atx_milestone_date(text, "End-of-Support")
    if not software_end:
        return []

    product_match = re.search(
        r"End-of-Life Products\s+ATX Part Number\s+Description(?P<body>.*?)Table 2:",
        text,
        flags=re.S,
    )
    if not product_match:
        return []

    product_lines = [
        normalize_text(line)
        for line in product_match.group("body").splitlines()
        if normalize_text(line)
    ]
    products: list[tuple[str, str]] = []
    current_part = ""
    description_parts: list[str] = []
    for line in product_lines:
        inline_match = re.match(r"^((?:DS|DSL)[A-Z0-9-]+)\s+(.+)$", line)
        if inline_match:
            if current_part:
                products.append((current_part, " ".join(description_parts)))
            current_part = inline_match.group(1)
            description_parts = [inline_match.group(2)]
        elif re.match(r"^(?:DS|DSL)[A-Z0-9-]+$", line):
            if current_part:
                products.append((current_part, " ".join(description_parts)))
            current_part = line
            description_parts = []
        elif current_part:
            description_parts.append(line)
    if current_part:
        products.append((current_part, " ".join(description_parts)))

    rows: list[dict[str, Any]] = []
    for part_number, description in products:
        row: dict[str, Any] = {
            "Model": part_number,
            "Part Number": part_number,
            "Product Name": f"ATX DigiStream {part_number}",
            "Description": "; ".join(
                part
                for part in (
                    "DigiStream content streaming product",
                    description,
                    (
                        f"Technical support and warranty or non-warranty repair ended {support_end}"
                        if support_end
                        else ""
                    ),
                )
                if part
            ),
            "Product Status": "End-of-Life; firmware/software maintenance ended",
            "End of Vulnerability Support": software_end,
            "_source_table": f"{source_name} DigiStream end-of-life products",
            "_source_hint": "ATX DigiStream end-of-sale and end-of-life notice import",
            "_aliases": [part_number, f"DigiStream {part_number}"],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if end_sale:
            row["End of Sale"] = end_sale
        rows.append(row)
    return rows


def mobotix_product_discontinuation_row(
    *,
    source_name: str,
    part_number: str,
    model_name: str,
    description: str,
    replacement: str = "",
    end_sale: str = "",
    aliases: list[str] | None = None,
) -> dict[str, Any]:
    product_name = model_name if model_name.startswith("MOBOTIX ") else f"MOBOTIX {model_name}"
    row: dict[str, Any] = {
        "Model": model_name,
        "Part Number": part_number,
        "Product Name": product_name,
        "Description": description,
        "Product Status": "Product discontinuation (EoL); no longer available",
        "Replacement Products": replacement,
        "_source_table": f"{source_name} product discontinuations",
        "_source_hint": "MOBOTIX Product News product discontinuation PDF import",
        "_status_only_review": True,
        "_force_lifecycle_review": True,
        "_review_policy": "mobotix_product_discontinuation_not_security_eol",
        "_review_reason": (
            "MOBOTIX Product News marks this product as EoL, discontinued, or "
            "no longer available, but the source does not provide an exact "
            "support or security-update end date."
        ),
        "_aliases": [part_number, model_name, *(aliases or [])],
    }
    if end_sale:
        row["End of Sale"] = end_sale
    return {key: value for key, value in row.items() if value}


def parse_mobotix_product_news_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "MOBOTIX" not in normalized or "Product discontinuations" not in normalized:
        return []

    rows: list[dict[str, Any]] = []

    discontinued_2026 = [
        (
            "Mx-M73TA-B640R050-EN54-V2",
            "M73A Thermal Camera TR(B), VGA, R050 (90 degrees) - EN54 Bundle V2",
            "EN54-V2 thermal camera bundle with M73A body and VGA thermal module",
            "Mx-M73TA-C640R050-EN54-V3",
            "",
        ),
        (
            "Mx-M73TA-B640R050-EN54",
            "M73A Thermal Camera TR(B), VGA, R050 (90 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with M73A body and VGA thermal module",
            "Mx-M73TA-C640R050-EN54-V3",
            "",
        ),
        (
            "Mx-M73TA-B640R150-EN54",
            "M73A Thermal Camera TR(B), VGA, R150 (32 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with M73A body and VGA thermal module",
            "Mx-M73TA-B640R150-EN54-V2",
            "",
        ),
        (
            "Mx-M73TA-B336R100-EN54",
            "M73A Thermal Camera TR(B), CIF, R100 (45 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with M73A body and CIF thermal module",
            "Mx-M73TA-B336R100-EN54-V2",
            "",
        ),
        (
            "Mx-M73TA-B336R150-EN54",
            "M73A Thermal Camera TR(B), CIF, R150 (25 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with M73A body and CIF thermal module",
            "Mx-M73TA-B336R150-EN54-V2",
            "",
        ),
        (
            "Mx-S74TA-B640R050-EN54-V2",
            "S74A Thermal Camera TR(B), VGA, R050 (90 degrees) - EM73N54 Bundle V2",
            "EN54-V2 thermal camera bundle with S74A body and VGA thermal module",
            "Mx-M73TA-C640R050-EN54-V3",
            "",
        ),
        (
            "Mx-S74TA-B640R050-EN54",
            "S74A Thermal Camera TR(B), VGA, R050 (90 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with S74A body and VGA thermal module",
            "Mx-M73TA-C640R050-EN54-V3",
            "",
        ),
        (
            "Mx-S74TA-B640R150-EN54",
            "S74A Thermal Camera TR(B), VGA, R150 (32 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with S74A body and VGA thermal module",
            "Mx-S74TA-B640R150-EN54-V2",
            "",
        ),
        (
            "Mx-S74TA-B336R100-EN54",
            "S74A Thermal Camera TR(B), CIF, R100 (45 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with S74A body and CIF thermal module",
            "Mx-S74TA-B336R100-EN54-V2",
            "",
        ),
        (
            "Mx-S74TA-B336R150-EN54",
            "S74A Thermal Camera TR(B), CIF, R150 (25 degrees) - EN54 Bundle",
            "EN54 thermal camera bundle with S74A body and CIF thermal module",
            "Mx-S74TA-B336R150-EN54-V2",
            "",
        ),
        (
            "Mx-p71TB-320T040",
            "p71TB Thermal ECO 320 - T040",
            "p71TB 4K indoor thermal camera with ECO 320-T040 thermal module",
            "Mx-p71TB-320T080",
            "",
        ),
        (
            "Mx-O-M73TB-640R050",
            "Thermal module 640-R050 for M73 (B model)",
            "VGA thermal radiometry module for M73",
            "Mx-O-M73TC-640R050",
            "",
        ),
        (
            "Mx-O-M7SB-640RP050",
            "S7x PTMount-Thermal 640-R050 (B model)",
            "PTMount thermal module for S7x with 2 m connection cable",
            "Mx-O-M7SB-640RP150; M73 with Mx-O-M73TC-640R050",
            "",
        ),
        (
            "Mx-O-M7SB-640RS050",
            "S7x Thermal Module 640-R050 (B model)",
            "Thermal module for S7x camera systems",
            "Mx-O-M7SB-640RS150; M73 with Mx-O-M73TC-640R050",
            "",
        ),
        (
            "Mx-VB3A-2-IR-VA",
            "MOBOTIX MOVE VandalBullet VB3-2-IR-VA",
            "MOBOTIX MOVE Vandal Bullet network camera with video analytics",
            "Mx-BC2A-2-IR; Mx-VB2A-5-IR-VA; Mx-VB1A-8-IR-VA",
            "",
        ),
        (
            "Mx-S-NVR1B-8-POE",
            "MOBOTIX MOVE NVR Network Video Recorder 8 channels",
            "MOBOTIX MOVE network video recorder with 8 PoE camera channels",
            "Mx-S-NVR1B-16-POE; Mx-S-NVR1A-64-POE24",
            "",
        ),
        (
            "MX-SM-OPT-POL",
            "Polarization filter for sensor modules",
            "Polarization filter for MOBOTIX sensor modules",
            "",
            "",
        ),
        (
            "Mx-c26B-6D016",
            "c26B Complete camera 6MP, B016, Day",
            "Hemispheric IP indoor camera for ceiling mounting",
            "MOBOTIX c71",
            "2026-05-15",
        ),
        (
            "Mx-c26B-AU-6D016",
            "c26B Complete Camera 6MP, B016, Day, Audio Package",
            "Hemispheric IP indoor camera for ceiling mounting with audio package",
            "MOBOTIX c71",
            "2026-05-15",
        ),
        (
            "Mx-O-SMA-S-6D016",
            "Sensor module 6MP, B016 (day), white, for M16/S16",
            "Day sensor module for M16 and S16 camera systems",
            "MOBOTIX M73/S74",
            "2026-05-15",
        ),
        (
            "Mx-O-SMA-S-6N016",
            "Sensor module 6MP, B016 (night), white, for M16/S16",
            "Night sensor module for M16 and S16 camera systems",
            "MOBOTIX M73/S74",
            "2026-05-15",
        ),
    ]
    if "MOBOTIX NEWS" in normalized and "February 2026" in normalized:
        for part_number, model_name, description, replacement, end_sale in discontinued_2026:
            if part_number not in text:
                continue
            rows.append(
                mobotix_product_discontinuation_row(
                    source_name=source_name,
                    part_number=part_number,
                    model_name=model_name,
                    description=description,
                    replacement=replacement,
                    end_sale=end_sale,
                )
            )

    discontinued_2023 = [
        (
            "MX-OPT-BPA1-EXT",
            "MX-BPA box",
            "MOBOTIX accessory module; MxBus power supply box",
        ),
        (
            "MX-OPT-Input1-EXT",
            "MX input box",
            "MOBOTIX accessory module; weatherproof input box",
        ),
        (
            "MX-OPT-Output1-EXT",
            "MX output box",
            "MOBOTIX accessory module; weatherproof output box",
        ),
        (
            "MX-PROX-BOX",
            "MX proximity box",
            "MOBOTIX accessory module; weatherproof proximity sensor box",
        ),
        (
            "MX-OPT-DIGI-INT",
            "MxDigitizer for S1x",
            "MOBOTIX accessory module; interface box for analog video sources",
        ),
    ]
    if "PRODUCTS END OF LIFE (EOL)" in normalized and "AS OF DECEMBER 1, 2023" in normalized:
        for part_number, model_name, description in discontinued_2023:
            if part_number not in text:
                continue
            rows.append(
                mobotix_product_discontinuation_row(
                    source_name=source_name,
                    part_number=part_number,
                    model_name=model_name,
                    description=description,
                    end_sale="2023-12-01",
                )
            )

    return rows


def parse_numeric_month_year_end(value: str) -> str | None:
    match = re.fullmatch(r"(\d{1,2})/(\d{4})", normalize_text(value))
    if not match:
        return None
    month = int(match.group(1))
    year = int(match.group(2))
    if month < 1 or month > 12:
        return None
    day = calendar.monthrange(year, month)[1]
    return date(year, month, day).isoformat()


def bosch_ip_video_platform_description(platform: str, eom: str | None) -> str:
    product_type = "IP video firmware software platform"
    if eom:
        return (
            f"{product_type}; maintenance ended {eom}; extended support "
            "provided security fixes only until EOS/EOP"
        )
    return f"{product_type}; extended support provided security fixes only until EOS/EOP"


def parse_bosch_ip_video_firmware_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "IP Video Firmware Info Brief" not in normalized:
        return []
    if "Extended firmware support for EOL platforms" not in normalized:
        return []
    if "EOS/EOP" not in normalized or "End of service / end of provisioning" not in normalized:
        return []

    rows: list[dict[str, Any]] = []
    platform_re = re.compile(
        r"^\s*(CPP(?:-ENC|5|4|3\s+cameras|3\s+encoders))\s+"
        r"(\d{2}/\d{4})\s+(\d{2}/\d{4})\s+(\d{2}/\d{4})\s+"
        r"([0-9.]+)\s+([A-Z]+)\s+([A-Za-z]+)\b",
        flags=re.I,
    )
    seen: set[str] = set()
    for raw_line in text.splitlines():
        match = platform_re.match(raw_line)
        if not match:
            continue
        platform = normalize_text(match.group(1))
        eof = parse_numeric_month_year_end(match.group(2))
        eom = parse_numeric_month_year_end(match.group(3))
        eos_eop = parse_numeric_month_year_end(match.group(4))
        firmware_version = normalize_text(match.group(5))
        status = normalize_text(match.group(6)).upper()
        availability = normalize_text(match.group(7)).lower()
        if not eos_eop or platform in seen:
            continue
        seen.add(platform)
        description = bosch_ip_video_platform_description(platform, eom)
        if eof:
            description = f"{description}; end of feature development {eof}"
        row: dict[str, Any] = {
            "Model": platform,
            "Part Number": platform,
            "Product Name": f"Bosch {platform} IP Video firmware platform",
            "Description": (
                f"{description}; firmware version {firmware_version}; "
                f"status {status}; availability {availability}"
            ),
            "Product Status": (
                "End of service / end of provisioning; no firmware fixes or "
                "updates after EOS"
            ),
            "End of Support": eos_eop,
            "End of Vulnerability Support": eos_eop,
            "_source_table": f"{source_name} recent firmware platform lifecycle table",
            "_source_hint": "Bosch IP Video firmware lifecycle platform PDF import",
            "_aliases": [
                platform,
                f"Bosch {platform}",
                f"{platform} firmware",
                f"Bosch IP Video {platform}",
            ],
            "_prefer_model": True,
        }
        rows.append(row)
    return rows


def parse_silver_peak_edgeconnect_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "EdgeConnect Product Lifecycle Policy" not in normalized:
        return []
    if "End of Software Support (EoSS)" not in normalized:
        return []
    if "The EoSS is a date-based milestone" not in normalized:
        return []

    rows: list[dict[str, Any]] = []
    source_hint = "HPE Aruba Networking EdgeConnect lifecycle policy PDF import"

    if (
        "The 4GB version of EC-XS was declared as End of Sale (EoS) on December 31,2016"
        in normalized
        and "EOST for ECOS 9.4 will be December 31, 2028" in normalized
    ):
        for part_number in ("200889", "200900"):
            rows.append(
                {
                    "Model": "EC-XS 4GB",
                    "Part Number": part_number,
                    "Product Name": f"EdgeConnect EC-XS 4GB PN {part_number}",
                    "Description": "SD-WAN gateway appliance",
                    "Product Status": (
                        "End of Sale; ECOS 9.4 is the last compatible software "
                        "release; ECOS 9.4 EOST is 2028-12-31"
                    ),
                    "End of Sale": "2016-12-31",
                    "End of Support": "2028-12-31",
                    "_source_table": f"{source_name} last compatible software release example",
                    "_source_hint": source_hint,
                    "_aliases": [
                        "EC-XS 4GB",
                        "EdgeConnect EC-XS 4GB",
                        f"PN {part_number}",
                        part_number,
                    ],
                    "_prefer_model": True,
                }
            )

    if (
        "EC-US end of sale (EoS) Jan 31, 2025" in normalized
        and "EC-US end of software support Jan 31, 2032" in normalized
    ):
        rows.append(
            {
                "Model": "EC-US",
                "Part Number": "201106",
                "Product Name": "EdgeConnect EC-US",
                "Description": "SD-WAN gateway appliance",
                "Product Status": (
                    "End of Sale; end of software support scheduled; EoS "
                    "announcement July 2024; last hardware maintenance renewal "
                    "2029-01-31; hardware maintenance EoSL 2030-01-31"
                ),
                "End of Sale": "2025-01-31",
                "End of Support": "2032-01-31",
                "_source_table": f"{source_name} EdgeConnect hardware lifecycle examples",
                "_source_hint": source_hint,
                "_aliases": ["EC-US", "EdgeConnect EC-US", "PN 201106", "201106"],
                "_prefer_model": True,
            }
        )

    if (
        "EC-XL-H end of sale (EoS) Mar 31, 2026" in normalized
        and "EC-XL-H end of software support Mar 31, 2031" in normalized
    ):
        rows.append(
            {
                "Model": "EC-XL-H",
                "Part Number": "EC-XL-H",
                "Product Name": "EdgeConnect EC-XL-H",
                "Description": "SD-WAN gateway appliance",
                "Product Status": (
                    "End of Sale; end of software support scheduled; EoS "
                    "announcement June 2025; last hardware maintenance renewal "
                    "2030-03-31; hardware maintenance EoSL 2031-03-31"
                ),
                "End of Sale": "2026-03-31",
                "End of Support": "2031-03-31",
                "_source_table": f"{source_name} EdgeConnect hardware lifecycle examples",
                "_source_hint": source_hint,
                "_aliases": ["EC-XL-H", "EdgeConnect EC-XL-H"],
                "_prefer_model": True,
            }
        )

    return rows


GENEXIS_PSTI_PDF_URL = (
    "https://genexis.eu/wp-content/uploads/2025/10/UK-Product-Support-PSTI.pdf"
)
GENEXIS_MONTH_YEAR_RE = re.compile(
    r"\b("
    r"January|February|March|April|May|June|July|August|September|October|"
    r"November|December"
    r")\s+\d{4}\b"
)


def parse_genexis_psti_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Genexis UK Product Support" not in normalized:
        return []
    if "Product Security and Telecommunications Infrastructure (PSTI)" not in normalized:
        return []
    if "Within this period, your device will receive security fixes when needed" not in normalized:
        return []
    if "End of Support Life dates stated below only apply to products sold in the UK" not in normalized:
        return []

    rows: list[dict[str, Any]] = []
    seen_models: set[str] = set()
    for raw_line in text.splitlines():
        line = normalize_text(raw_line)
        dates = GENEXIS_MONTH_YEAR_RE.findall(line)
        if len(dates) < 2:
            continue
        matches = list(GENEXIS_MONTH_YEAR_RE.finditer(line))
        market_introduction = matches[0].group(0)
        support_life = matches[1].group(0)
        model = normalize_text(line[: matches[0].start()])
        if not model or normalize_header(model).startswith("product name"):
            continue
        support_end = parse_date_any(support_life)
        if not support_end:
            continue
        if model in seen_models:
            continue
        seen_models.add(model)
        rows.append(
            {
                "Model": model,
                "Part Number": model,
                "Product Name": model,
                "Description": "Fiber CPE",
                "Region": "UK",
                "Product Status": (
                    "End of Support Life published; security fixes provided "
                    "until End of Support Life when needed; market "
                    f"introduction {market_introduction}; UK PSTI support period"
                ),
                "End of Support": support_end,
                "End of Vulnerability Support": support_end,
                "_source_table": f"{source_name} UK product support table",
                "_source_hint": "Genexis UK PSTI product support PDF import",
                "_source_url": GENEXIS_PSTI_PDF_URL,
                "_aliases": [model, f"Genexis {model}"],
                "_prefer_model": True,
            }
        )
    return rows


WINMATE_PCN_URL = "https://www.winmate.com/en/NewsAndEvents/PCNNews"
WINMATE_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October|"
    "November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
)
WINMATE_MODEL_TOKEN_RE = re.compile(
    r"(?<![A-Z0-9])"
    r"(?=[A-Z0-9][A-Z0-9./()_-]{2,}[A-Z0-9)]\b)"
    r"(?=[A-Z0-9./()_-]*[A-Z])"
    r"(?=[A-Z0-9./()_-]*\d)"
    r"[A-Z0-9][A-Z0-9./()_-]*[A-Z0-9)]"
    r"(?![A-Z0-9])"
)


def winmate_normalize_date_text(value: str) -> str:
    text = normalize_text(value)
    text = re.sub(r"[\u2022\u00b7]+", " ", text)
    text = re.sub(r"\bAril\b", "April", text, flags=re.I)
    text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
    text = re.sub(r"\b([A-Za-z]+)\s*\.", r"\1 ", text)
    text = re.sub(r"\s*/\s*", "/", text)
    text = re.sub(r"\s*,\s*", ", ", text)
    text = re.sub(r"(\d+)\s+(st|nd|rd|th)\b", r"\1\2", text, flags=re.I)
    return normalize_text(text)


def winmate_first_date(value: str) -> str | None:
    text = winmate_normalize_date_text(value)
    patterns = (
        r"\b\d{4}/\d{1,2}/\d{1,2}\b",
        rf"\b(?:{WINMATE_MONTHS})\s*,?\s+\d{{1,2}}(?:st|nd|rd|th)?\s*,?\s+\d{{4}}\b",
        rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{WINMATE_MONTHS})\s+\d{{4}}\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            candidate = winmate_normalize_date_text(match.group(0))
            candidate = re.sub(
                rf"^({WINMATE_MONTHS})\s+(\d{{1,2}}(?:st|nd|rd|th)?)\s+(\d{{4}})$",
                r"\1 \2, \3",
                candidate,
                flags=re.I,
            )
            parsed = parse_date_any(candidate)
            if parsed:
                return parsed
    return None


def winmate_pdf_date_by_labels(text: str, labels: tuple[str, ...]) -> str | None:
    normalized_labels = tuple(normalize_header(label) for label in labels)
    lines = text.splitlines()
    for label in normalized_labels:
        for index, line in enumerate(lines):
            normalized_line = normalize_header(line)
            if label not in normalized_line:
                continue
            window = " ".join(lines[index:index + 3])
            parsed = winmate_first_date(window)
            if parsed:
                return parsed
    return None


def winmate_clean_model_token(value: str) -> str:
    token = normalize_text(value).strip(".,;:[]{}")
    token = token.replace("\u2010", "-").replace("\u2011", "-")
    token = token.replace("\u2012", "-").replace("\u2013", "-").replace("\u2014", "-")
    token = token.strip(".,;:")
    if not token or len(token) < 4:
        return ""
    if token.endswith("-") or token.startswith("-"):
        return ""
    normalized = normalize_header(token)
    if normalized in {
        "model name",
        "product line",
        "page 1",
        "page 2",
        "pcn a",
        "winmate",
    }:
        return ""
    if any(marker in token.upper() for marker in ("XXX", "XXXXX", "X=", "~")):
        return ""
    if token.upper().endswith("-WINDOWS"):
        return ""
    if re.fullmatch(r"PCN[-A-Z0-9]+", token, flags=re.I):
        return ""
    if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
        return ""
    return token


def winmate_line_model_tokens(line: str) -> list[tuple[int, str]]:
    tokens: list[tuple[int, str]] = []
    seen: set[str] = set()
    for match in WINMATE_MODEL_TOKEN_RE.finditer(line.upper()):
        if match.end() < len(line) and line[match.end()] == "-":
            continue
        token = winmate_clean_model_token(match.group(0))
        if not token:
            continue
        key = normalize_alias_dedupe_key(token)
        if key in seen:
            continue
        seen.add(key)
        tokens.append((match.start(), token))
    return tokens


def winmate_product_sections(text: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    starts = (
        r"Impacted Product List\s*:",
        r"IMPACT PRODUCT LIST\s*:",
        r"Affected Product List\s*:",
        r"Applies for\s*:",
    )
    stop_pattern = re.compile(
        r"\n\s*(?:"
        r"BIOS change|Board changes|Change Effective Date|Original\s+New|"
        r"RELEASE DATE|Will be effective|Implementation date|ISSUED BY|"
        r"APPROVE:|Impacts:|If you have any further questions"
        r")\b",
        flags=re.I,
    )
    for start_pattern in starts:
        for match in re.finditer(start_pattern, text, flags=re.I):
            tail = text[match.end():]
            stop = stop_pattern.search(tail)
            section = tail[: stop.start()] if stop else tail
            if section.strip():
                sections.append((match.group(0), section))
    return sections


def winmate_discontinue_boundary(section: str) -> int | None:
    pairs: list[tuple[int, int]] = []
    for line in section.splitlines():
        tokens = winmate_line_model_tokens(line)
        if len(tokens) < 2:
            continue
        first, second = tokens[0][0], tokens[1][0]
        if first < second:
            pairs.append((first, second))
    if not pairs:
        return None
    midpoint_sum = sum((first + second) // 2 for first, second in pairs)
    return midpoint_sum // len(pairs)


def winmate_section_models(section: str) -> dict[str, str]:
    normalized_section = normalize_header(section)
    paired_table = (
        "alternative product" in normalized_section
        or ("applies for" in normalized_section and "replacement" in normalized_section)
        or "replacement changes" in normalized_section
    )
    boundary = winmate_discontinue_boundary(section) if paired_table else None
    models: dict[str, str] = {}
    for raw_line in section.splitlines():
        line = raw_line.rstrip()
        normalized_line = normalize_header(line)
        if not normalized_line:
            continue
        if any(
            header in normalized_line
            for header in (
                "product line",
                "model name",
                "discontinue product",
                "alternative product",
                "replacement",
                "changes",
                "page ",
            )
        ):
            continue
        tokens = winmate_line_model_tokens(line)
        if not tokens:
            continue
        if paired_table:
            if boundary is not None and tokens[0][0] >= boundary:
                continue
            model = tokens[0][1]
            replacements = [
                token
                for _, token in tokens[1:]
                if normalize_alias_dedupe_key(token) != normalize_alias_dedupe_key(model)
            ]
            models.setdefault(model, "; ".join(replacements))
            continue
        for _, model in tokens:
            models.setdefault(model, "")
    return models


def winmate_prose_models(text: str) -> dict[str, str]:
    models: dict[str, str] = {}
    for pattern in (
        r"following models\s+(.+?)\s+will be removed",
        r"product series,\s*(.+?)\s+will be removed",
    ):
        for match in re.finditer(pattern, normalize_text(text), flags=re.I):
            for _, model in winmate_line_model_tokens(match.group(1)):
                models.setdefault(model, "")
    return models


def parse_winmate_pcn_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    normalized_header_text = normalize_header(normalized)
    if "product change notification" not in normalized_header_text:
        return []
    if "winmate" not in normalized_header_text:
        return []
    if not any(
        phrase in normalized_header_text
        for phrase in (
            "product discontinuation",
            "product discontinued",
            "product end of life",
            "end of life notice",
            "eol",
            "remove from website",
            "removed from winmate standard product line",
        )
    ):
        return []

    announcement = winmate_pdf_date_by_labels(
        text,
        (
            "PCN Release Date",
            "Release Date",
            "Date of Publication",
        ),
    )
    end_sale = winmate_pdf_date_by_labels(
        text,
        (
            "Last Time Buy Date",
            "Change Effective Date",
            "Last Product Discontinuance Order Date",
            "Will be effective from",
            "Implementation date",
        ),
    )
    if not end_sale:
        return []

    model_replacements: dict[str, str] = {}
    for _, section in winmate_product_sections(text):
        for model, replacement in winmate_section_models(section).items():
            model_replacements.setdefault(model, replacement)
    for model, replacement in winmate_prose_models(text).items():
        model_replacements.setdefault(model, replacement)
    if not model_replacements:
        return []

    rows: list[dict[str, Any]] = []
    for model, replacement in model_replacements.items():
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Winmate {model}",
            "Description": "Winmate industrial computing product",
            "Product Status": (
                "Product change notification; end-of-sale or last-time-buy "
                "date listed for affected product; support/security-update "
                "end not stated"
            ),
            "End of Sale": end_sale,
            "_source_table": f"{source_name} product change notification",
            "_source_hint": "Winmate product change notification PDF import",
            "_source_url": WINMATE_PCN_URL,
            "_review_policy": "winmate_discontinuation_not_security_eol",
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if replacement:
            row["Replacement Products"] = replacement
        rows.append(row)
    return rows


MIMOSA_EOF_PDF_SOURCE_URLS = {
    "2025_A5c_EOL.pdf": "https://www2.mimosa.co/a5c-eol",
    "2025_A5x_EOL.pdf": "https://www2.mimosa.co/a5x-eol",
    "2025_B11_EOL.pdf": "https://www2.mimosa.co/b11-eol",
    "2025_B24_EOL.pdf": "https://www2.mimosa.co/b24-eol",
    "2025_B5x_EOL.pdf": "https://www2.mimosa.co/b5x-eol",
    "2025_C5c_EOL.pdf": "https://www2.mimosa.co/c5c-eol",
    "2025_C5x_EOL.pdf": "https://www2.mimosa.co/c5x-eol",
}


def mimosa_extract_milestone_date(text: str, milestone: str) -> str:
    pattern = (
        rf"{re.escape(milestone)}\s+.*?"
        r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sept|Sep|Oct|Nov|Dec)"
        r"[a-z]*\s+\d{1,2},\s+\d{4})"
    )
    match = re.search(pattern, text, flags=re.I | re.S)
    if not match:
        return ""
    return parse_date_any(match.group(1)) or ""


def parse_mimosa_eol_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if (
        "Mimosa" not in normalized
        or "End-of-Life Announcement" not in normalized
        or ("Product Key Milestones" not in normalized and "Key Milestones" not in normalized)
    ):
        return []
    product_match = re.search(r"Product:\s*(.+?)(?:\n\s*|Model Number)", text, flags=re.I | re.S)
    model_match = re.search(
        r"Model Number\(s\):\s*(.+?)(?:\n\s*As we continue|\n\s*Product Key Milestones)",
        text,
        flags=re.I | re.S,
    )
    if not product_match or not model_match:
        return []
    product = normalize_text(product_match.group(1))
    model_text = normalize_text(model_match.group(1))
    primary_models = []
    aliases = [product, model_text]
    for part in re.split(r"\s*,\s*", model_text):
        item = normalize_text(part)
        if not item:
            continue
        aliases.append(item)
        model = normalize_text(item.split("|", 1)[0])
        part_number = normalize_text(item.split("|", 1)[1]) if "|" in item else model
        if model:
            primary_models.append((model, part_number))
    if not primary_models:
        return []

    announcement = mimosa_extract_milestone_date(text, "End-of-Life Announcement")
    software_maintenance = mimosa_extract_milestone_date(text, "End of Software Maintenance")
    end_of_sale = mimosa_extract_milestone_date(text, "End-of-Sale Date")
    replacement = ""
    replacement_section = re.search(
        r"Recommended Replacement:(.+?)(?:Support Commitments:|Document Revision History)",
        text,
        flags=re.I | re.S,
    )
    if replacement_section:
        replacement_part = ""
        replacement_name = ""
        raw_lines = [line for line in replacement_section.group(1).splitlines() if normalize_text(line)]
        lines = [normalize_text(line) for line in raw_lines]
        for index, raw_line in enumerate(raw_lines):
            part_match = re.search(r"\bPN:\s*([0-9-]+)\b", raw_line, flags=re.I)
            if not part_match:
                continue
            replacement_part = part_match.group(1)
            same_line = re.search(
                r"\bPN:\s*[0-9-]+\s{2,}(.+?)(?:\s{2,}|$)",
                raw_line,
                flags=re.I,
            )
            if same_line:
                replacement_name = normalize_text(same_line.group(1))
            if not replacement_name:
                for candidate in lines[index + 1 :]:
                    if normalize_header(candidate) in {"part number", "product"}:
                        continue
                    replacement_name = candidate
                    break
            break
        replacement = " / ".join(part for part in (replacement_part, replacement_name) if part)

    rows: list[dict[str, Any]] = []
    source_url = MIMOSA_EOF_PDF_SOURCE_URLS.get(source_name, "https://mimosa.co/legal/eol")
    for model, part_number in primary_models:
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": part_number,
            "Product Name": product or f"Mimosa {model}",
            "Description": "Mimosa 5 Series wireless product EOL announcement",
            "Product Status": (
                "End-of-Life process; software maintenance and bug fixes ended; "
                "support based on warranty terms"
            ),
            "_source_table": f"{source_name} product key milestones",
            "_source_hint": "Mimosa 2025 product EOL PDF import",
            "_source_url": source_url,
            "_aliases": aliases,
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if software_maintenance:
            row["Security Updates End"] = software_maintenance
        if end_of_sale:
            row["End of Sale"] = end_of_sale
        if replacement:
            row["Replacement Products"] = replacement
        rows.append(row)
    return rows


LIGOWAVE_EOL_POLICY_URL = "https://www.ligowave.com/end-of-life-policy"
LIGOWAVE_DATE_RE = re.compile(
    r"\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},\s+\d{4}\b",
    flags=re.I,
)


def ligowave_device_type(model: str) -> str:
    key = normalize_header(model)
    if "wnms" in key or "wireless network management" in key:
        return "Wireless network management software"
    if "ligomux" in key or "ligo mux" in key:
        return "Wireless backhaul multiplexer"
    if "ligoptp" in key or "ligo ptp" in key:
        return "Wireless point-to-point bridge"
    if "ligodlb" in key or "ligo dlb" in key:
        return "Wireless CPE"
    if re.search(r"\bnft\b", key):
        return "Wireless access point"
    if "apc" in key:
        return "Wireless broadband device series"
    return "Wireless network device"


def ligowave_title_from_text(normalized_text: str) -> str:
    match = re.match(
        r"(.+?)\s+Product\s+End\s+of\s+Life\s+Announcement\b",
        normalized_text,
        flags=re.I,
    )
    if not match:
        return ""
    return normalize_text(match.group(1))


def ligowave_timeline_dates(
    timeline_text: str,
) -> tuple[str | None, str | None, str | None, str | None]:
    dates = [
        parse_date_any(normalize_text(match.group(0)))
        for match in LIGOWAVE_DATE_RE.finditer(timeline_text)
    ]
    header = normalize_header(timeline_text)
    if "end of software maintenance" in header and len(dates) >= 4:
        return dates[0], dates[1], dates[2], dates[3]
    if "last date of support" in header and len(dates) >= 2:
        valid_dates = [date_value for date_value in dates if date_value]
        if len(valid_dates) >= 2:
            return valid_dates[-2], None, None, valid_dates[-1]
    return None, None, None, None


def parse_ligowave_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if not source_name.lower().startswith("eol_") or not source_name.lower().endswith(".pdf"):
        return []
    normalized = normalize_text(text)
    header = normalize_header(normalized)
    if (
        "product end of life announcement" not in header
        or "end of life timeline" not in header
    ):
        return []
    if "product change announcement" in header:
        return []

    model = ligowave_title_from_text(normalized)
    if not model:
        return []
    timeline = normalized.split("End of Life Timeline", 1)[-1]
    for marker in ("Alternative Products", "Inquiries"):
        if marker in timeline:
            timeline = timeline.split(marker, 1)[0]
    announcement, end_of_sale, software_maintenance, support_end = ligowave_timeline_dates(
        timeline
    )
    if not announcement or not support_end:
        return []

    status_parts = [
        "LigoWave Product End of Life Announcement",
        f"announcement date {announcement}",
    ]
    if end_of_sale:
        status_parts.append(f"end of sale date {end_of_sale}")
    if software_maintenance:
        status_parts.append(f"software maintenance end date {software_maintenance}")
    status_parts.append(f"last date of support {support_end}")

    aliases = [model]
    acronym_match = re.search(r"\(([A-Z0-9]+)\)", model)
    if acronym_match:
        aliases.append(acronym_match.group(1))
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": f"LigoWave {model}",
        "Description": ligowave_device_type(model),
        "Product Status": "; ".join(status_parts),
        "Announcement Date": announcement,
        "End of Support": support_end,
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} End of Life Timeline",
        "_source_hint": "LigoWave Product End of Life Announcement PDF import",
        "_source_url": LIGOWAVE_EOL_POLICY_URL,
        "_review_policy": "ligowave_last_date_of_support_and_software_maintenance",
        "_aliases": aliases,
        "_prefer_model": True,
    }
    if end_of_sale:
        row["End of Sale"] = end_of_sale
    if software_maintenance:
        row["Vendor Software Maintenance End"] = software_maintenance
    return [row]


SILICOM_MONTHS = (
    "January|February|March|April|May|June|July|August|September|"
    "October|November|December"
)
SILICOM_DATE_RE = re.compile(
    rf"\b(?:{SILICOM_MONTHS})\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}\b|"
    rf"\b\d{{1,2}}\s+(?:{SILICOM_MONTHS})\s+\d{{4}}\b|"
    r"\b\d{1,2}[./]\d{1,2}[./]\d{2,4}\b",
    flags=re.I,
)
SILICOM_MODEL_TOKEN_RE = re.compile(
    r"(?<![A-Z0-9])"
    r"(?:"
    r"BDS#[A-Z0-9][A-Z0-9._/-]*|"
    r"(?:PE|PEG|PEX|PXG|PXSC|PESC|PES|M[124]E|MEG|IBS|OE|NA)"
    r"[A-Z0-9][A-Z0-9()._/-]*|"
    r"(?:80300|80500)-\d{4}-G\d{2}"
    r")"
    r"(?![A-Z0-9])",
    flags=re.I,
)
SILICOM_BROAD_MODELS = {
    "PESC61",
    "PESC62",
    "PESC63",
}


def silicom_parse_date(value: Any) -> str | None:
    text = normalize_text(value)
    text = re.sub(r"\b(\d{1,2})(?:st|nd|rd|th)\b", r"\1", text, flags=re.I)
    text = re.sub(r"\b(\d{1,2})th\b", r"\1", text, flags=re.I)
    dayfirst = bool(re.fullmatch(r"\d{1,2}[.]\d{1,2}[.]\d{2,4}", text))
    if re.fullmatch(r"\d{1,2}/\d{1,2}/\d{2,4}", text):
        first = int(text.split("/", 1)[0])
        dayfirst = first > 12
    return parse_date_any(text, dayfirst=dayfirst)


def silicom_first_date(value: str) -> str | None:
    for match in SILICOM_DATE_RE.finditer(value):
        parsed = silicom_parse_date(match.group(0))
        if parsed:
            return parsed
    return None


def silicom_add_years(value: str, years: int) -> str | None:
    parsed = parse_date_any(value)
    if not parsed:
        return None
    year, month, day = (int(part) for part in parsed.split("-"))
    target_year = year + years
    day = min(day, calendar.monthrange(target_year, month)[1])
    return date(target_year, month, day).isoformat()


def silicom_first_date_after(patterns: tuple[str, ...], text: str) -> str | None:
    normalized = normalize_text(text)
    for pattern in patterns:
        for match in re.finditer(pattern, normalized, flags=re.I):
            parsed = silicom_first_date(match.group(0))
            if parsed:
                return parsed
    return None


def silicom_lifecycle_dates(text: str) -> dict[str, str | None]:
    normalized = normalize_text(text)
    end_sale = silicom_first_date_after(
        (
            r"Last Time Buy[^.]*?accepted\s+until\s+[^.]+",
            r"purchase orders[^.]*?accepted\s+until\s+[^.]+",
            r"purchase orders[^.]*?accepted\s+through\s+[^.]+",
            r"last purchase order and ship date[^.]*?(?:was|is)\s+[^.]+",
        ),
        normalized,
    )
    support_end = silicom_first_date_after(
        (
            r"support\s+till\s+[^.]+",
            r"provide support[^.]*?\s+until\s+[^.]+",
        ),
        normalized,
    )
    if not support_end:
        support_base = silicom_first_date_after(
            (
                r"support[^.]*?three\s+\(3\)\s+years[^.]*?\s+on\s+[^.]+",
                r"support[^.]*?full three\s+years[^.]*?\s+on\s+[^.]+",
            ),
            normalized,
        )
        if support_base:
            support_end = silicom_add_years(support_base, 3)

    last_ship = silicom_first_date_after(
        (
            r"Last Time Ship[^.]*?(?:until|at)\s+[^.]+",
            r"Last Ship Date\s+is\s*:?\s+[^.]+",
            r"Last ship date\s+is\s*:?\s+[^.]+",
        ),
        normalized,
    )
    announcement = None
    for line in text.splitlines()[:18]:
        parsed = silicom_first_date(line)
        if parsed:
            announcement = parsed
            break
    return {
        "announcement": announcement,
        "end_sale": end_sale,
        "support_end": support_end,
        "last_ship": last_ship,
    }


def silicom_clean_model_candidate(value: str) -> str:
    text = normalize_text(value)
    text = text.replace("\\-", "-")
    text = text.strip(" .,:;[]{}")
    text = text.upper()
    if not text or len(text) < 4:
        return ""
    if text.startswith("-") or text.endswith("-"):
        return ""
    if text in SILICOM_BROAD_MODELS:
        return ""
    if any(marker in text for marker in ("*", "/", "(", ")")):
        return ""
    if re.search(r"(?:^|-|_)X{2,}(?:$|-|_)", text):
        return ""
    if not (re.search(r"[A-Z]", text) and re.search(r"\d", text)):
        return ""
    if re.fullmatch(r"\d{4,}", text) and not text.startswith(("80300-", "80500-")):
        return ""
    if normalize_header(text) in {
        "product",
        "replacement",
        "description",
        "support",
    }:
        return ""
    return text


def silicom_model_tokens(line: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    seen: set[str] = set()
    for pos, _, model in silicom_model_like_matches(line):
        if not model:
            continue
        key = normalize_alias_dedupe_key(model)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append((pos, model))
    return result


def silicom_model_like_matches(line: str) -> list[tuple[int, str, str]]:
    matches: list[tuple[int, str, str]] = []
    for match in SILICOM_MODEL_TOKEN_RE.finditer(line):
        raw = match.group(0)
        matches.append((match.start(), raw, silicom_clean_model_candidate(raw)))
    return matches


def silicom_add_model(
    models: dict[str, dict[str, str]],
    model: str,
    *,
    row_end_sale: str | None = None,
) -> None:
    key = normalize_alias_dedupe_key(model)
    if not key:
        return
    entry = models.setdefault(key, {"model": model})
    if row_end_sale and "row_end_sale" not in entry:
        entry["row_end_sale"] = row_end_sale


def silicom_title_models(text: str) -> dict[str, dict[str, str]]:
    models: dict[str, dict[str, str]] = {}
    normalized = normalize_text(text)
    match = re.search(
        r"End of Life Notification(?:\s+for)?\s*:\s*(.+?)(?:\s+Dear\s+|"
        r"\s+(?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{1,2}|\s+\d{1,2}[./]\d{1,2}[./]\d{2,4})",
        normalized,
        flags=re.I,
    )
    if not match:
        return models
    title = normalize_text(match.group(1))
    if "based on" in normalize_header(title) or "minnowboard" in normalize_header(title):
        return models
    for part in re.split(r"\s*,\s*", title):
        for _, model in silicom_model_tokens(part):
            silicom_add_model(models, model)
    return models


def silicom_prose_models(text: str) -> dict[str, dict[str, str]]:
    models: dict[str, dict[str, str]] = {}
    normalized = normalize_text(text)
    section_patterns = (
        r"following products?\s*:\s*(.+?)(?:\s+The reason|\s+Due to|\s+Purchase orders|\s+Last ship|\s+As the leading)",
        r"Product Series that will be discontinued\s*:\s*(.+?)(?:\s+The reason|\s+Purchase orders|\s+Last ship|\s+As the leading)",
        r"discontinu(?:e|ing)\s+the production of\s+(.+?)(?:\s+The reason|\s+Due to|\s+Purchase orders|\s+Last ship|\s+PNs as|\.)",
    )
    for pattern in section_patterns:
        for match in re.finditer(pattern, normalized, flags=re.I):
            section = match.group(1)
            if "all products using" in normalize_header(section):
                continue
            for _, model in silicom_model_tokens(section):
                silicom_add_model(models, model)
    return models


def silicom_table_models(text: str) -> dict[str, dict[str, str]]:
    models: dict[str, dict[str, str]] = {}
    in_table = False
    table_header_re = re.compile(
        r"\b(?:End of Life product|Product\s+Recommended replacement PN|"
        r"Product\s+Replacement|Part Number\s+Replacement Part Number|"
        r"Current\s+Replacement|EOL PN\s+Recommended replacement PN)\b",
        flags=re.I,
    )
    stop_re = re.compile(
        r"\b(?:Full Warranty and Support|The new products|For immediate product "
        r"demand|Silicom will continue|Please contact|Thank you|As the leading)\b",
        flags=re.I,
    )
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        normalized = normalize_text(line)
        header = normalize_header(normalized)
        if table_header_re.search(normalized):
            in_table = True
            continue
        if in_table and stop_re.search(normalized):
            in_table = False
        if not in_table or not normalized:
            continue
        if any(word in header for word in ("description", "replacement", "representative")) and not silicom_model_tokens(line):
            continue
        all_matches = silicom_model_like_matches(line)
        tokens = [(pos, model) for pos, _, model in all_matches if model]
        if not tokens:
            continue
        row_end_sale = silicom_first_date(line)
        first_pos, first_model = tokens[0]
        if any(pos < first_pos and not model for pos, _, model in all_matches):
            continue
        if first_pos <= 45:
            silicom_add_model(models, first_model, row_end_sale=row_end_sale)
    return models


def silicom_device_type(model: str) -> str:
    header = normalize_header(model)
    if re.match(r"^(?:80300|80500)-", model):
        return "Single-board computer"
    if header.startswith("na"):
        return "Network appliance"
    if header.startswith("ib"):
        return "Bypass switch"
    if header.startswith("oe"):
        return "OCP mezzanine network adapter"
    if header.startswith(("pxsc", "pes")):
        return "Security protocol processor adapter"
    if header.startswith(("m1e", "m2e", "m4e", "meg")):
        return "Ethernet adapter module"
    return "Ethernet server adapter"


def silicom_row(
    *,
    model: str,
    source_name: str,
    dates: dict[str, str | None],
    row_end_sale: str | None = None,
) -> dict[str, Any]:
    end_sale = row_end_sale or dates.get("end_sale")
    support_end = dates.get("support_end")
    status_parts = ["Silicom Product End of Life notification"]
    if dates.get("announcement"):
        status_parts.append(f"announcement date {dates['announcement']}")
    if end_sale:
        status_parts.append(f"last-time-buy or product discontinuance date {end_sale}")
    if dates.get("last_ship"):
        status_parts.append(f"last ship date {dates['last_ship']}")
    if support_end:
        status_parts.append(f"support end date {support_end}")

    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": f"Silicom {model}",
        "Description": silicom_device_type(model),
        "Product Status": "; ".join(status_parts),
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} Silicom EOL notice",
        "_source_hint": "Silicom Product End of Life notification PDF import",
        "_review_policy": "silicom_eol_notice_explicit_or_derived_support_end",
        "_aliases": [model, f"Silicom {model}"],
        "_prefer_model": True,
    }
    if dates.get("announcement"):
        row["Announcement Date"] = dates["announcement"]
    if end_sale:
        row["End of Sale"] = end_sale
    if dates.get("last_ship"):
        row["Last Ship Date"] = dates["last_ship"]
    if support_end:
        row["End of Support"] = support_end
    else:
        row["_force_lifecycle_review"] = True
        row["_status_only_review"] = True
        row["_review_policy"] = "silicom_eol_notice_sale_or_status_only"
        row["_review_reason"] = (
            "The Silicom notice identifies this exact product as EOL or "
            "discontinued, but it does not publish an exact support, service, "
            "firmware, vulnerability, or security-update end date."
        )
    return row


def parse_silicom_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    header = normalize_header(normalized)
    if "silicom" not in header or "end of life" not in header:
        return []
    if "discontinu" not in header and "product discontinuance date" not in header:
        return []

    dates = silicom_lifecycle_dates(text)
    model_entries: dict[str, dict[str, str]] = {}
    for extractor in (silicom_table_models, silicom_prose_models, silicom_title_models):
        for key, entry in extractor(text).items():
            model_entries.setdefault(key, entry)
            if entry.get("row_end_sale") and "row_end_sale" not in model_entries[key]:
                model_entries[key]["row_end_sale"] = entry["row_end_sale"]

    rows: list[dict[str, Any]] = []
    for key in sorted(model_entries):
        entry = model_entries[key]
        rows.append(
            silicom_row(
                model=entry["model"],
                source_name=source_name,
                dates=dates,
                row_end_sale=entry.get("row_end_sale"),
            )
        )
    return rows


EATON_DATE_RE = re.compile(
    r"\b(?:January|February|March|April|May|June|Jun|July|August|"
    r"September|October|November|December)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b|"
    r"\b\d{1,2}(?:st|nd|rd|th)?\s+"
    r"(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December),?\s+\d{4}\b|"
    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b|"
    r"\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)/\d{4}\b",
    flags=re.I,
)
EATON_SKU_RE = re.compile(
    r"(?<![A-Z0-9])(?=[A-Z0-9-]*[A-Z])(?=[A-Z0-9-]*\d)"
    r"[A-Z0-9][A-Z0-9-]{2,}(?![A-Z0-9])|(?<![A-Z0-9])\d{7}(?![A-Z0-9])",
    flags=re.I,
)
EATON_SOURCE_RE = re.compile(
    r"^(?:dit_eol_notice_|network_m3_anz_eol_sales_bulletin\.pdf)",
    flags=re.I,
)


def eaton_parse_date(value: str) -> str | None:
    text = normalize_text(value)
    text = re.sub(r"\bJun\.\s+", "June ", text, flags=re.I)
    return parse_date_any(text)


def eaton_first_date(value: str) -> str | None:
    for match in EATON_DATE_RE.finditer(value):
        parsed = eaton_parse_date(match.group(0))
        if parsed:
            return parsed
    return None


def eaton_notice_date(lines: list[str]) -> str | None:
    for line in lines[:25]:
        parsed = eaton_first_date(line)
        if parsed:
            return parsed
    return None


def eaton_notice_dates(text: str, source_name: str) -> dict[str, str | None]:
    normalized = normalize_text(text)
    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    announcement = eaton_notice_date(lines)
    end_of_life = None
    end_of_sale = None
    end_of_support = None

    for pattern in (
        r"End-of-Life Effective Date\s+\*+\s*[^*]+\*+",
        r"scheduled transition to EOL(?:\s+by)?\s+[^.]+",
        r"EOL Date\s*:\s*[^.]+",
        r"effective\s+[^.]+",
    ):
        for match in re.finditer(pattern, normalized, flags=re.I):
            if "effective immediately" in normalize_header(match.group(0)):
                continue
            parsed = eaton_first_date(match.group(0))
            if parsed:
                end_of_life = parsed
                break
        if end_of_life:
            break

    calendar_year = re.search(r"end of calendar year\s+(\d{4})", normalized, flags=re.I)
    if not end_of_life and calendar_year:
        end_of_life = f"{calendar_year.group(1)}-12-31"
    by_year = re.search(r"by the end of\s+(\d{4})", normalized, flags=re.I)
    if not end_of_life and by_year:
        end_of_life = f"{by_year.group(1)}-12-31"

    for pattern in (
        r"Orders placed[^.]*?prior to\s+[^.]+",
        r"last time buys should be placed by\s+[^.]+",
        r"accept new orders through\s+[^.]+",
    ):
        parsed = eaton_first_date(
            next((m.group(0) for m in re.finditer(pattern, normalized, flags=re.I)), "")
        )
        if parsed:
            end_of_sale = parsed
            break

    if "Power Alert Local" in normalized and "no longer receive updates, patches, or technical support" in normalized:
        end_of_support = end_of_life or eaton_first_date(normalized)

    return {
        "announcement": announcement,
        "end_of_life": end_of_life,
        "end_of_sale": end_of_sale,
        "end_of_support": end_of_support,
    }


def eaton_clean_model_candidate(value: str) -> str:
    text = normalize_text(value).strip(" .,:;[]{}()*")
    text = text.upper()
    if not text or len(text) < 3:
        return ""
    if any(marker in text for marker in ("XXX", "XXXX", "XXXXX", "*")):
        return ""
    if text in {"EOL", "UPS", "PDU", "NONE", "NA", "N/A", "MODEL", "CATALOG", "NUMBER"}:
        return ""
    if re.fullmatch(r"\d+(?:V|VA|W|KW|KVA|VDC)", text):
        return ""
    if re.fullmatch(r"(?:IEC|NEMA)?L?\d{2,4}(?:-\d{1,3})?(?:P|R)?", text):
        return ""
    if re.fullmatch(r"\d{4,6}", text):
        return ""
    if not re.search(r"[A-Z]", text):
        return ""
    if not (re.search(r"\d", text) or text in {"WEBCARDLXE", "POWER ALERT LOCAL"}):
        return ""
    return text


def eaton_model_like_matches(line: str) -> list[tuple[int, str, str]]:
    matches: list[tuple[int, str, str]] = []
    for match in EATON_SKU_RE.finditer(line):
        raw = match.group(0)
        matches.append((match.start(), raw, eaton_clean_model_candidate(raw)))
    return matches


def eaton_add_model(
    models: dict[str, dict[str, str]],
    model: str,
    *,
    replacement: str = "",
) -> None:
    key = normalize_alias_dedupe_key(model)
    if not key:
        return
    entry = models.setdefault(key, {"model": model})
    if replacement and "replacement" not in entry:
        entry["replacement"] = replacement


def eaton_replacement_from_line(line: str, model: str) -> str:
    tail = normalize_text(line)
    if model and tail.upper().startswith(model):
        tail = normalize_text(tail[len(model):])
    matches = [m for _, _, m in eaton_model_like_matches(tail) if m and m != model]
    return matches[0] if matches else ""


def eaton_table_models(text: str) -> dict[str, dict[str, str]]:
    models: dict[str, dict[str, str]] = {}
    in_table = False
    model_column_pos: int | None = None
    table_header_re = re.compile(
        r"\b(?:EOL Part Number|EOL Catalog|Catalog Number\s+kVA|"
        r"Discontinued models impacted|Eaton Tripp Lite\s+Replacement|"
        r"Eaton Tripp Lite\s+EOL Model)\b",
        flags=re.I,
    )
    stop_re = re.compile(
        r"\b(?:TIME SCHEDULE|ISSUED BY|CONTACT INFORMATION|For more information|"
        r"Next Steps|Thank you|Page \d+ of \d+|Model\s+)\b",
        flags=re.I,
    )
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        normalized = normalize_text(line)
        header = normalize_header(normalized)
        if table_header_re.search(normalized):
            in_table = True
            model_column_pos = None
            continue
        if in_table and stop_re.search(normalized):
            in_table = False
        if not in_table or not normalized:
            continue
        if any(word in header for word in ("description", "replacement", "catalog number")) and not eaton_model_like_matches(line):
            continue
        all_matches = eaton_model_like_matches(line)
        tokens = [(pos, model) for pos, _, model in all_matches if model]
        if not tokens:
            continue
        first_pos, first_model = tokens[0]
        if any(pos < first_pos and not model for pos, _, model in all_matches):
            continue
        if model_column_pos is None:
            if first_pos > 25:
                continue
            model_column_pos = first_pos
        if first_pos <= model_column_pos + 3:
            eaton_add_model(
                models,
                first_model,
                replacement=eaton_replacement_from_line(line, first_model),
            )
    return models


def eaton_prose_models(text: str) -> dict[str, dict[str, str]]:
    models: dict[str, dict[str, str]] = {}
    normalized = normalize_text(text)
    header = normalize_header(normalized)
    if "power alert local" in header and "end of life" in header:
        eaton_add_model(models, "Power Alert Local")
    if "network m2" in header and "network m3" in header and "end" in header:
        eaton_add_model(models, "NETWORK-M2", replacement="NETWORK-M3")
    if "modbus ms" in header and "end of life" in header:
        eaton_add_model(models, "MODBUS-MS", replacement="INDGW-M2")
    relay = re.search(r"X-Slot Relay Card\s+\(PN\s+(\d{7})\)", normalized, flags=re.I)
    if relay:
        eaton_add_model(models, relay.group(1), replacement="103003055")
    for match in re.finditer(r"EOL Product\s+(.+?)(?:\s+Affected Regions|\s+EOL Notice|\s+EOL Owner|\s+AFFECTED)", normalized, flags=re.I):
        section = match.group(1)
        if "product line" in normalize_header(section):
            continue
        for _, _, model in eaton_model_like_matches(section):
            if model:
                eaton_add_model(models, model)
    return models


def eaton_device_type(model: str, source_name: str) -> str:
    header = normalize_header(f"{model} {source_name}")
    if "power alert" in header:
        return "UPS monitoring and management software"
    if "webcard" in header or "network" in header or "modbus" in header or model.isdigit():
        return "UPS network management card"
    if "pdu" in header or model.startswith(("EBA", "EMA", "EVM")):
        return "Rack power distribution unit"
    if model.startswith(("P00", "P01", "P02", "P03", "P05")):
        return "Power cord or power accessory"
    if model.startswith("SRCOOL"):
        return "Portable cooling unit"
    return "UPS or distributed IT power hardware"


def eaton_row(
    *,
    model: str,
    replacement: str,
    source_name: str,
    dates: dict[str, str | None],
) -> dict[str, Any]:
    support_end = dates.get("end_of_support")
    status_parts = ["Eaton Distributed IT end-of-life notice"]
    if dates.get("announcement"):
        status_parts.append(f"announcement date {dates['announcement']}")
    if dates.get("end_of_sale"):
        status_parts.append(f"order cutoff or last-time-buy date {dates['end_of_sale']}")
    if dates.get("end_of_life"):
        status_parts.append(f"vendor EOL effective date {dates['end_of_life']}")
    if support_end:
        status_parts.append(f"updates, patches, and technical support end {support_end}")

    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": f"Eaton {model}",
        "Description": eaton_device_type(model, source_name),
        "Product Status": "; ".join(status_parts),
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} Eaton DIT EOL notice",
        "_source_hint": "Eaton Distributed IT EOL notice PDF import",
        "_review_policy": "eaton_dit_eol_notice_status_only",
        "_aliases": [model, f"Eaton {model}", f"Tripp Lite {model}"],
        "_prefer_model": True,
    }
    if replacement:
        row["Replacement Products"] = replacement
    if dates.get("announcement"):
        row["Announcement Date"] = dates["announcement"]
    if dates.get("end_of_sale"):
        row["End of Sale"] = dates["end_of_sale"]
    if dates.get("end_of_life"):
        row["End of Life"] = dates["end_of_life"]
    if support_end:
        row["End of Support"] = support_end
        row["Security Updates End"] = support_end
        row["_end_of_security_updates_override"] = support_end
        row["_review_policy"] = "eaton_explicit_no_updates_patches_or_support"
    else:
        row["_force_lifecycle_review"] = True
        row["_status_only_review"] = True
        row["_review_reason"] = (
            "The Eaton notice publishes EOL, order, or replacement lifecycle "
            "evidence, but it does not explicitly state an exact support, "
            "service, firmware, vulnerability, or security-update end date."
        )
    return row


def parse_eaton_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if not EATON_SOURCE_RE.match(source_name):
        return []
    normalized = normalize_text(text)
    header = normalize_header(normalized)
    if "eaton" not in header or "end" not in header:
        return []
    if "internal use only" in header or "tentative eol date" in header:
        return []
    if source_name.startswith("dit_eol_notice_03") and len(normalized) < 100:
        return []

    dates = eaton_notice_dates(text, source_name)
    models: dict[str, dict[str, str]] = {}
    for extractor in (eaton_table_models, eaton_prose_models):
        for key, entry in extractor(text).items():
            models.setdefault(key, entry)
            if entry.get("replacement") and "replacement" not in models[key]:
                models[key]["replacement"] = entry["replacement"]
    rows: list[dict[str, Any]] = []
    for key in sorted(models):
        entry = models[key]
        rows.append(
            eaton_row(
                model=entry["model"],
                replacement=entry.get("replacement", ""),
                source_name=source_name,
                dates=dates,
            )
        )
    return rows


AUDIOCODES_DATE_RE = re.compile(
    r"\b(?:January|February|Febuary|March|April|May|June|July|August|"
    r"September|Sept|October|November|December)\s+\d{1,2},?\s+\d{4}\b|"
    r"\b(?:January|February|Febuary|March|April|May|June|July|August|"
    r"September|Sept|October|November|December)[,\s]+\d{4}\b|"
    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",
    flags=re.I,
)
AUDIOCODES_BULLET_RE = re.compile(r"^[\s\u2022\u25aa\u25ab\u25cf\u25e6\uf0a7\uf06e\-]+")
AUDIOCODES_CODE_RE = re.compile(
    r"^(?=.*[A-Z])(?=.*(?:\d|/|-))[A-Z0-9][A-Z0-9./_-]{2,}(?:-[A-Z0-9./_-]+)*$"
)
AUDIOCODES_NOTICE_SOURCE_RE = re.compile(
    r"^\d{4}-product-notice-.*\.pdf$",
    flags=re.I,
)


def audiocodes_parse_date(value: Any) -> str | None:
    text = normalize_text(value)
    text = re.sub(r"\bFebuary\b", "February", text, flags=re.I)
    text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
    text = re.sub(r"\b([A-Za-z]+),\s+(\d{4})\b", r"\1 \2", text)
    return parse_date_any(text)


def audiocodes_first_date(value: Any) -> str | None:
    text = normalize_text(value)
    for match in AUDIOCODES_DATE_RE.finditer(text):
        parsed = audiocodes_parse_date(match.group(0))
        if parsed:
            return parsed
    return None


def audiocodes_date_after_label(lines: list[str], labels: tuple[str, ...]) -> str | None:
    normalized_labels = [normalize_header(label) for label in labels]
    for index, line in enumerate(lines):
        header = normalize_header(line)
        if not any(label in header for label in normalized_labels):
            continue
        window = " ".join(lines[index : index + 4])
        parsed = audiocodes_first_date(window)
        if parsed:
            return parsed
    return None


def audiocodes_sentence_date(text: str, phrases: tuple[str, ...]) -> str | None:
    normalized_phrases = [normalize_header(phrase) for phrase in phrases]
    for sentence in re.split(r"(?<=[.!?])\s+", normalize_text(text)):
        header = normalize_header(sentence)
        if not any(phrase in header for phrase in normalized_phrases):
            continue
        parsed = audiocodes_first_date(sentence)
        if parsed:
            return parsed
    return None


def audiocodes_notice_title(lines: list[str]) -> str:
    title_parts: list[str] = []
    for index, line in enumerate(lines[:18]):
        header = normalize_header(line)
        if not line or "product notice" in header or header.startswith("notice "):
            continue
        if "end of " not in header and "end of" not in header.replace("end of", "end of"):
            continue
        title_parts.append(line)
        for follow in lines[index + 1 : index + 4]:
            follow_header = normalize_header(follow)
            if (
                not follow
                or "product notice" in follow_header
                or follow_header.startswith("this product notice")
                or follow_header.startswith("notice ")
            ):
                continue
            if (
                line.rstrip().lower().endswith(("for", "of", "and"))
                or len(follow) <= 80
            ):
                title_parts.append(follow)
            break
        break
    return normalize_text(" ".join(title_parts))


def audiocodes_notice_kind(text: str, title: str) -> set[str]:
    header = normalize_header(f"{title} {text[:1200]}")
    kinds: set[str] = set()
    if "end of service" in header:
        kinds.add("service")
    if "end of support" in header:
        kinds.add("support")
    if "end of product sales" in header or "end of product sale" in header:
        kinds.add("sale")
    if "end of sale" in header or "end of sales" in header:
        kinds.add("sale")
    if "end of life" in header:
        kinds.add("life")
    return kinds


def audiocodes_dates(text: str, lines: list[str], kinds: set[str]) -> dict[str, str | None]:
    dates: dict[str, str | None] = {
        "Announcement Date": audiocodes_date_after_label(
            lines,
            (
                "Announcement Date",
                "Notice Date",
                "End of Product Sale notification date",
                "End-of-Product-Sale notification date",
            ),
        ),
        "End of Sale": None,
        "End of Life": None,
        "End of Support": None,
        "End of Service": None,
    }

    sale = audiocodes_date_after_label(
        lines,
        (
            "End of Product Sale and Last-Time Buy",
            "End-of-Product-Sale and Last-Time Buy",
            "End of Product Sale date",
            "End-of-Product-Sales",
            "End of Sale",
            "End-of-Sale",
            "Last Time Buy",
            "Last-Time Buy",
            "LTB date",
        ),
    )
    if sale:
        dates["End of Sale"] = sale

    support = (
        audiocodes_date_after_label(
            lines,
            (
                "End of Support",
                "End-of-Support",
                "End of Software Support Date",
                "Software Support services",
            ),
        )
        or audiocodes_sentence_date(
            text,
            (
                "software support services",
                "support services",
                "support status",
            ),
        )
    )
    service = (
        audiocodes_date_after_label(lines, ("End of Service", "End-of-Service"))
        or audiocodes_sentence_date(text, ("end of service", "end-of-service"))
    )
    effective = audiocodes_date_after_label(
        lines,
        ("Effective Date", "Notice Effective Date", "Affective Date"),
    )
    if "support" in kinds and not support:
        support = effective or audiocodes_sentence_date(
            text,
            ("end of support", "end-of-support"),
        )
    if "service" in kinds and not service:
        service = effective
    if "sale" in kinds and not dates["End of Sale"]:
        dates["End of Sale"] = effective
    if "life" in kinds:
        dates["End of Life"] = effective or dates["End of Sale"]

    dates["End of Support"] = support
    dates["End of Service"] = service
    return dates


def audiocodes_clean_product_line(line: str) -> str:
    text = normalize_text(line)
    text = text.replace("\uf0a7", " ").replace("\uf06e", " ")
    text = AUDIOCODES_BULLET_RE.sub("", text)
    text = re.sub(r"^l\s+(?=[A-Z0-9])", "", text)
    return normalize_text(text).strip(" .;")


def audiocodes_is_broad_product(value: str) -> bool:
    header = normalize_header(value)
    return (
        not header
        or header in {
            "affected products",
            "affected product family",
            "affected part numbers",
            "affected part numbers cpn",
            "cpn description",
            "product migration",
            "replacement products",
        }
        or header.startswith("all ")
        or "all variants" in header
        or "all software and hardware" in header
        or "all voca cic" in header
        or "all software" in header
        or "product family" in header
        or "the following" in header
        or "this eol applies" in header
        or "this end of" in header
        or "version 7 0 ga supports" in header
        or "deadline for" in header
        or "orders for" in header
        or "audio codes fax server cpns" in header
        or "audiocodes fax server cpns" in header
        or "audio codes auto attendant ivr cpns" in header
        or "audiocodes auto attendant ivr cpns" in header
    )


def audiocodes_is_exact_product(value: str) -> bool:
    text = normalize_text(value).strip(" .;")
    if audiocodes_is_broad_product(text):
        return False
    if AUDIOCODES_CODE_RE.match(text):
        return True
    header = normalize_header(text)
    if len(text) > 120:
        return False
    exact_needles = (
        "mediant ",
        "mediapack ",
        "mp ",
        "mp-",
        "rxv",
        "smarttap",
        "smartworks",
        "businessplus",
        "auto attendant",
        "auto-attendant",
        "fax server",
        "device manager",
        "media transcoding cluster",
        "ovoc on dedicated hardware server",
        "sbc and media gateway software",
        "gateway and sbc software",
        "sip software version",
        "sbc software version",
        "software version",
        "webrtc",
        "csp",
        "csps",
        "tx100",
        "rts box",
        "dp3209",
        "ipm 260",
        "tp 260",
        "voca cic non managed",
    )
    if any(needle in header for needle in exact_needles):
        return True
    return bool(re.search(r"\b(?:IP|UC|TEAMS|M1K|M1KB|MP|SW)[A-Z0-9./_-]{2,}\b", text))


def audiocodes_split_product_candidates(line: str) -> list[tuple[str, str]]:
    clean = audiocodes_clean_product_line(line)
    if not clean or audiocodes_is_broad_product(clean):
        return []

    if "," in clean:
        parts = [audiocodes_clean_product_line(part) for part in clean.split(",")]
        if all(part and audiocodes_is_exact_product(part) for part in parts):
            return [(part, "") for part in parts]

    paren = re.match(r"^([A-Z0-9][A-Z0-9./_-]{2,})\s+\((.+)\)$", clean)
    if paren and audiocodes_is_exact_product(paren.group(1)):
        return [(paren.group(1), normalize_text(paren.group(2)))]

    table = re.match(r"^([A-Z0-9][A-Z0-9./_-]{2,})\s{1,}(.+)$", clean)
    if table and AUDIOCODES_CODE_RE.match(table.group(1)):
        if re.match(r"^MP-\d+$", table.group(1)) and re.match(
            r"^(?:with|fxs|fxo|bri|gateway|e-sbc|sba|msbr)\b",
            table.group(2),
            flags=re.I,
        ):
            return [(clean, "")]
        return [(table.group(1), normalize_text(table.group(2)))]

    if audiocodes_is_exact_product(clean):
        return [(clean, "")]
    return []


def audiocodes_affected_products(text: str) -> list[tuple[str, str]]:
    raw_lines = text.splitlines()
    lines = [normalize_text(line) for line in raw_lines]
    products: list[tuple[str, str]] = []
    seen: set[str] = set()
    in_section = False
    for line in lines:
        header = normalize_header(line)
        if header in {
            "affected products",
            "affected part numbers",
            "affected part numbers cpn",
            "affected part numbers cpn cpn",
        }:
            in_section = True
            continue
        if in_section and (
            header.startswith("product migration")
            or header.startswith("announcement date")
            or header.startswith("notice details")
            or header.startswith("related software")
            or header.startswith("software support")
            or header.startswith("if you have")
            or header.startswith("audiocodes inc")
            or header.startswith("audio codes inc")
            or header.startswith("life cycle milestones")
            or header.startswith("effective date")
            or header.startswith("last time buy")
        ):
            in_section = False
        if not in_section:
            continue
        for product, description in audiocodes_split_product_candidates(line):
            key = normalize_alias_dedupe_key(product)
            if not key or key in seen:
                continue
            seen.add(key)
            products.append((product, description))
    return products


def audiocodes_model_from_title(title: str, text: str) -> str:
    candidates = [title]
    reached = re.search(
        r"AudioCodes\s+that\s+(.+?)\s+has\s+reached\s+End-of-(?:Support|Life|Service)",
        normalize_text(text),
        flags=re.I,
    )
    if reached:
        candidates.append(reached.group(1))
    for candidate in candidates:
        model = normalize_text(candidate)
        model = re.sub(
            r"^End[- ]of[- ](?:Support|Service|Life|Sale)(?:\s+\([A-Z]+\))?"
            r"(?:\s+Announcement)?\s+(?:for|of)?\s*",
            "",
            model,
            flags=re.I,
        )
        model = re.sub(r"^AudioCodes\s+", "", model, flags=re.I)
        model = model.strip(" .:-")
        if audiocodes_is_exact_product(model):
            return model
    return ""


def audiocodes_is_software_release_notice(title: str, text: str) -> bool:
    header = normalize_header(f"{title} {text[:700]}")
    return (
        "software version" in header
        or "software versions" in header
        or "smarttap 360 version" in header
        or "smarttap software version" in header
        or "smartworks version" in header
    )


def audiocodes_device_type(model: str, description: str = "") -> str:
    header = normalize_header(f"{model} {description}")
    if any(token in header for token in ("ip phone", "teams c", "rxv", "meeting")):
        return "IP phone or meeting space device"
    if any(token in header for token in ("mediant", "mediapack", "media gateway", "sbc", "mp 1", "mp 2", "mp-")):
        return "VoIP gateway or session border controller"
    if any(token in header for token in ("module", "m1kb vm", "m1k msbr")):
        return "Gateway module or accessory"
    if any(
        token in header
        for token in (
            "software",
            "smarttap",
            "smartworks",
            "businessplus",
            "auto attendant",
            "fax server",
            "device manager",
            "voca",
            "ovoc",
            "webrtc",
        )
    ):
        return "AudioCodes software or application"
    return "AudioCodes network communications product"


def audiocodes_row(
    *,
    model: str,
    description: str,
    title: str,
    source_name: str,
    dates: dict[str, str | None],
    kinds: set[str],
) -> dict[str, Any]:
    product_name = f"AudioCodes {model}"
    status_parts = [title or "AudioCodes product notice"]
    for label in (
        "Announcement Date",
        "End of Sale",
        "End of Life",
        "End of Support",
        "End of Service",
    ):
        if dates.get(label):
            status_parts.append(f"{label.lower()} {dates[label]}")
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": product_name,
        "Description": audiocodes_device_type(model, description),
        "Product Status": "; ".join(status_parts),
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} AudioCodes product notice",
        "_source_hint": "AudioCodes product notice PDF import",
        "_review_policy": "audiocodes_product_notice_term_mapping",
        "_aliases": [model, product_name, description],
        "_prefer_model": True,
        "_suppress_description_aliases": True,
    }
    if description:
        row["Description"] = description
        row["_aliases"].append(f"AudioCodes {description}")
    for label, value in dates.items():
        if value:
            row[label] = value
    if not (dates.get("End of Support") or dates.get("End of Service")):
        row["_force_lifecycle_review"] = True
        row["_review_reason"] = (
            "The AudioCodes notice publishes sale/lifecycle evidence, but does "
            "not explicitly state an exact support, service, firmware, "
            "vulnerability, or security-update end date for this product row."
        )
    elif dates.get("End of Service"):
        row["_review_policy"] = "audiocodes_explicit_end_of_service_notice"
    elif dates.get("End of Support"):
        row["_review_policy"] = "audiocodes_explicit_end_of_support_notice"
    return row


def parse_audiocodes_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    source_key = source_name.lower()
    if source_key == "audiocodes_devices_end_of_sale_eos_policy_for_meeting_space_devices_and_ip_phones.pdf":
        return []
    if not AUDIOCODES_NOTICE_SOURCE_RE.match(source_name):
        return []
    normalized = normalize_text(text)
    if "AudioCodes" not in normalized or "Product Notice" not in normalized:
        return []

    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    title = audiocodes_notice_title(lines)
    kinds = audiocodes_notice_kind(normalized, title)
    if not kinds:
        return []
    dates = audiocodes_dates(normalized, lines, kinds)
    if not any(value for key, value in dates.items() if key != "Announcement Date"):
        return []

    product_rows = []
    if not audiocodes_is_software_release_notice(title, normalized):
        product_rows = audiocodes_affected_products(text)
    if not product_rows:
        title_model = audiocodes_model_from_title(title, normalized)
        if title_model:
            product_rows = [(title_model, "")]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for model, description in product_rows:
        if audiocodes_is_broad_product(model):
            continue
        key = normalize_alias_dedupe_key(model)
        if not key or key in seen:
            continue
        seen.add(key)
        rows.append(
            audiocodes_row(
                model=model,
                description=description,
                title=title,
                source_name=source_name,
                dates=dates,
                kinds=kinds,
            )
        )
    return rows


RIBBON_DATE_RE = re.compile(
    r"\b(?:January|February|March|April|May|June|July|August|"
    r"September|Sept|October|November|December|Jan|Feb|Mar|Apr|Jun|"
    r"Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b|"
    r"\b\d{1,2}(?:st|nd|rd|th)?\s+"
    r"(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\.?,?\s+\d{4}\b|"
    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",
    flags=re.I,
)
RIBBON_CODE_RE = re.compile(
    r"^(?=.{3,80}$)(?=.*[A-Z])(?=.*(?:[A-Z]{2,}|\d))"
    r"[A-Z0-9][A-Z0-9._/+]{1,}(?:-[A-Z0-9._/+]+)+$|"
    r"^(?=.{4,30}$)(?=.*[A-Z])(?=.*\d)[A-Z]{2,}[A-Z0-9._/+]*$|"
    r"^\d{3,}-\d{4,}-\d{2,}$",
    flags=re.I,
)


def ribbon_parse_date(value: Any) -> str | None:
    text = normalize_text(value)
    text = re.sub(r"\b(\d{1,2})(?:st|nd|rd|th)\b", r"\1", text, flags=re.I)
    text = re.sub(r"\bSept\b", "Sep", text, flags=re.I)
    return parse_date_any(text)


def ribbon_first_date(value: Any) -> str | None:
    text = normalize_text(value)
    for match in RIBBON_DATE_RE.finditer(text):
        parsed = ribbon_parse_date(match.group(0))
        if parsed:
            return parsed
    return None


def ribbon_date_after_label(lines: list[str], labels: tuple[str, ...]) -> str | None:
    normalized_labels = [normalize_header(label) for label in labels]
    for index, line in enumerate(lines):
        header = normalize_header(line)
        if not any(label in header for label in normalized_labels):
            continue
        window = " ".join(lines[index : index + 6])
        parsed = ribbon_first_date(window)
        if parsed:
            return parsed
    return None


def ribbon_notice_title(lines: list[str]) -> str:
    title_parts: list[str] = []
    for index, line in enumerate(lines[:35]):
        header = normalize_header(line)
        if not header or header.startswith(("product and services", "sonus product")):
            continue
        if header.startswith(("external announcement", "issued", "confidential")):
            continue
        if not any(
            phrase in header
            for phrase in (
                "end of product",
                "end of support",
                "end of service",
                "end of life",
                "eops",
                "eol",
            )
        ):
            continue
        title_parts.append(line)
        for follow in lines[index + 1 : index + 5]:
            follow_header = normalize_header(follow)
            if (
                not follow_header
                or follow_header.startswith(("ribbon communications", "sonus networks"))
                or follow_header.startswith(("summary", "product life cycle"))
            ):
                break
            if len(follow) <= 90:
                title_parts.append(follow)
        break
    return normalize_text(" ".join(title_parts))


def ribbon_lifecycle_dates(text: str) -> dict[str, str | None]:
    normalized = normalize_text(text)
    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    announcement = ribbon_date_after_label(
        lines,
        (
            "End of Product Sale Announcement",
            "End of Product Sale Notification",
            "End of Life Announcement",
            "End of Product Support Announcement",
            "Date on which Ribbon has announced EoPS",
            "Date on which Sonus has announced EOPS",
        ),
    )
    if not announcement:
        for line in lines[:16]:
            header = normalize_header(line)
            if header.startswith("issued"):
                announcement = ribbon_first_date(line)
                break

    end_sale = ribbon_date_after_label(
        lines,
        (
            "End of Product Availability",
            "Last Order Date",
            "End of Product Sale: The product is no longer",
            "Last date that an order may be placed",
        ),
    )
    if not end_sale:
        end_sale = ribbon_date_after_label(lines, ("Last Quote Date",))
    last_ship = ribbon_date_after_label(
        lines,
        (
            "Last Ship Date",
            "Manufacturer's Discontinuance",
            "Manufacturers Discontinuance",
            "End of Product Delivery",
            "Manufacturing Discontinuation",
        ),
    )
    support = ribbon_date_after_label(
        lines,
        (
            "End of R&D Support",
            "End of RD Support",
            "End of Product Support",
            "End of Support Life",
            "End of Support",
            "End of RMA Support",
            "End of Service Life",
            "Release 24.xx End of Support",
            "Release 23.xx End of Support",
            "Release 22.xx End of Support",
        ),
    )
    if not support:
        for pattern in (
            r"Sonus\s+will\s+support\s+(?:them|[^.]+?)\s+until\s+[^.]+",
            r"Ribbon\s+will\s+support\s+(?:them|[^.]+?)\s+until\s+[^.]+",
            r"supported\s+by\s+Sonus\s+until\s+[^.]+",
            r"supported\s+by\s+Ribbon\s+until\s+[^.]+",
        ):
            match = re.search(pattern, normalized, flags=re.I)
            if match:
                support = ribbon_first_date(match.group(0))
                if support:
                    break
    end_life = ribbon_date_after_label(
        lines,
        (
            "EOL Date",
            "End of Life Date",
        ),
    )
    return {
        "Announcement Date": announcement,
        "End of Sale": end_sale,
        "Last Ship Date": last_ship,
        "End of Life": end_life,
        "End of Support": support,
    }


def ribbon_clean_product(value: str) -> str:
    text = normalize_text(value)
    text = re.sub(r"^[\u2022\-\*\s]+", "", text)
    text = text.strip(" .,:;[]{}")
    if not text:
        return ""
    header = normalize_header(text)
    if header in {
        "n a",
        "na",
        "none",
        "product code",
        "product codes",
        "eops product code",
        "existing sku",
        "old product code",
        "replacement",
        "replacement product code",
        "replacement service product code",
        "description",
        "software release",
        "software releases no longer available",
    }:
        return ""
    if any(
        phrase in header
        for phrase in (
            "new product code",
            "new firmware code",
            "replacement software release",
            "suggested replacement",
            "ribbon confidential",
            "confidential and proprietary",
            "copyright",
            "for more information",
            "please contact",
        )
    ):
        return ""
    return text


def ribbon_product_code_from_field(value: str) -> str:
    text = ribbon_clean_product(value)
    if not text:
        return ""
    if RIBBON_CODE_RE.match(text):
        return text
    if re.fullmatch(
        r"(?:RAMP\s+Software\s+Releases?|SBC\s+Core\s+Release|SBC\s+Edge\s+Release)"
        r"\s+[A-Z0-9./ xX_-]+(?:\s+\([^)]+\))?",
        text,
        flags=re.I,
    ):
        return normalize_text(text)
    return ""


def ribbon_first_table_field(line: str) -> tuple[str, str]:
    stripped = line.strip()
    if not stripped:
        return "", ""
    parts = re.split(r"\s{2,}", stripped, maxsplit=1)
    field = parts[0]
    description = parts[1] if len(parts) > 1 else ""
    return field, normalize_text(description)


def ribbon_add_product(
    products: dict[str, dict[str, str]],
    product: str,
    *,
    description: str = "",
) -> None:
    product = ribbon_clean_product(product)
    if not product:
        return
    key = normalize_alias_dedupe_key(product)
    if not key:
        return
    entry = products.setdefault(key, {"model": product})
    if description and "description" not in entry:
        entry["description"] = normalize_text(description)


def ribbon_table_products(text: str) -> dict[str, dict[str, str]]:
    products: dict[str, dict[str, str]] = {}
    in_product_table = False
    in_old_code_block = False
    previous_key = ""
    start_re = re.compile(
        r"\b(?:PRODUCT CODES(?: NO LONGER AVAILABLE(?: AFTER LAST QUOTE DATE)?| AFFECTED| Impacted)?|"
        r"Product Codes No Longer Available|product codes that will no longer be available|"
        r"SOFTWARE RELEASES NO LONGER AVAILABLE)\b",
        flags=re.I,
    )
    stop_re = re.compile(
        r"\b(?:PRODUCT LIFE CYCLE DATES|Sonus Product Life Cycle Dates|"
        r"FREQUENTLY ASKED QUESTIONS|Major System|RIBBON CONFIDENTIAL|"
        r"Sonus Confidential|Table Notes|Table notes|replacement products|"
        r"List Price|Price Change|Contributors)\b",
        flags=re.I,
    )
    old_stop_re = re.compile(
        r"\b(?:OLD FIRMWARE CODE|NEW CLEI CODE|ASSOCIATED PRODUCTS|DRAWING NUMBER)\b",
        flags=re.I,
    )

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        normalized = normalize_text(line)
        header = normalize_header(normalized)
        if not normalized:
            continue
        if header.startswith("suggested replacement"):
            in_product_table = False
            previous_key = ""
            continue
        if "old product code" in header:
            in_old_code_block = True
            in_product_table = False
            tail = re.sub(r"^.*?\bOLD PRODUCT CODE\b", "", normalized, flags=re.I).strip()
            code = ribbon_product_code_from_field(tail)
            if code:
                ribbon_add_product(products, code)
                previous_key = normalize_alias_dedupe_key(code)
            continue
        if in_old_code_block and old_stop_re.search(normalized):
            in_old_code_block = False
            previous_key = ""
        if in_old_code_block:
            code = ribbon_product_code_from_field(normalized)
            if code:
                ribbon_add_product(products, code)
                previous_key = normalize_alias_dedupe_key(code)
            continue

        if start_re.search(normalized):
            in_product_table = True
            previous_key = ""
            continue
        if in_product_table and stop_re.search(normalized):
            in_product_table = False
            previous_key = ""
        if not in_product_table:
            continue
        if any(word in header for word in ("replacement", "description", "product code")):
            continue

        field, description = ribbon_first_table_field(line)
        code = ribbon_product_code_from_field(field)
        if code:
            desc_field, _ = ribbon_first_table_field(description)
            desc_code = ribbon_product_code_from_field(desc_field or description)
            if desc_code:
                ribbon_add_product(products, desc_code)
                description = ""
            ribbon_add_product(products, code, description=description)
            previous_key = normalize_alias_dedupe_key(code)
            continue
        if previous_key and len(normalized) <= 120:
            entry = products.get(previous_key)
            if entry and entry.get("description"):
                entry["description"] = normalize_text(f"{entry['description']} {normalized}")
    return products


def ribbon_clean_title_product(value: str) -> str:
    text = normalize_text(value)
    text = re.split(
        r"\b(?:This bulletin|Key Takeaway|BULLETIN ID|ISSUED:|PRODUCT LIFE CYCLE)\b",
        text,
        maxsplit=1,
        flags=re.I,
    )[0]
    text = re.sub(r"^the\s+", "", text, flags=re.I)
    text = text.strip(" .,:;-")
    if len(text) > 120:
        return ""
    header = normalize_header(text)
    if not header or header in {"release", "software", "product", "notification", "notice"}:
        return ""
    if re.fullmatch(r"release\s+\d+(?:\.\d+)?", header):
        return ""
    if any(
        phrase in header
        for phrase in (
            "key takeaway",
            "date on which",
            "customer",
            "replacement",
            "current or upcoming",
            "prior releases",
        )
    ):
        return ""
    return text


def ribbon_title_products(text: str, title: str, source_name: str = "") -> dict[str, dict[str, str]]:
    products: dict[str, dict[str, str]] = {}
    normalized = normalize_text(text)
    candidates: list[str] = []
    major = re.search(r"\bMajor System\s+(.+?)(?:\s+Sub System|\s+Hardware\b)", normalized, flags=re.I)
    if major:
        candidates.append(major.group(1))
    for pattern in (
        r"(.+?)\s+End of Product Sale\b",
        r"(.+?)\s+End of Product Support\b",
        r"(.+?)\s+End of Support\b",
        r"(.+?)\s+End of Life\b",
        r"(.+?)\s+EoPS\b",
        r"(.+?)\s+EOL\b",
        r"End of Product Sale(?:, End of R&D Support)?(?: is Announced)? for\s+(.+)",
        r"End of Product Support Notice for\s+(.+)",
        r"End of Product Sale Notification for\s+(.+)",
        r"End of Product Sale\s*(?:-|\u2013)\s*(.+)",
        r"EOPS for\s+(.+?)\s+is not available",
    ):
        match = re.search(pattern, title, flags=re.I)
        if match:
            candidates.append(match.group(1))
    for pattern in (
        r"(EdgeView\s+Release\s+[0-9][0-9.xX._-]*)",
        r"(PSX\s+SW\s+Release\s+[0-9][0-9.xX._-]*)",
        r"(PSX\s+Release\s+[0-9][0-9.xX._-]*)",
        r"(RAMP\s+Software\s+Releases?\s+[0-9][0-9.xX]+)",
        r"(SBC\s+Core\s+Release\s+[Rr]?[0-9][0-9.xX._-]*(?:\s+\([^)]+\))?)",
        r"(SBC\s+Edge\s+Release\s+[Rr]?[0-9][0-9.xX._-]*)",
        r"(SBC\s+1000\s+SBC\s+2000(?:\s+SBC\s+SWe\s+Lite)?\s+Release\s+[0-9][0-9.xX._-]*)",
        r"(SBC\s+5xxx\s+software\s+release\s+[0-9][0-9.xX._-]*)",
        r"(Ribbon'?s?\s+VNFM)",
        r"(VNFM\s+SW\s+Release\s+[0-9][0-9.xX._-]*)",
        r"(Virtual Network Function Manager\s+\(VNFM\))",
        r"(Virtual\s+EdgeProtect)",
        r"(VX900C)",
        r"(Q21\s+SBC)",
        r"(HP\s+DL380p?\s+G8)",
        r"(Network\s+Wide\s+Licensing)",
        r"(Multi\s+Application\s+Rack\s+Mounted\s+Server\s+\(MA-RMS\))",
        r"(Federal Edge\s+2000)",
        r"(Session Border Controller\s+2000)",
    ):
        for match in re.finditer(
            pattern,
            f"{title} {source_name.replace('_', ' ')} {normalized[:1800]}",
            flags=re.I,
        ):
            candidates.append(match.group(1))

    for candidate in candidates:
        model = ribbon_clean_title_product(candidate)
        model = re.sub(r"^Ribbon'?s?\s+", "Ribbon ", model, flags=re.I)
        model = re.sub(r"\s+", " ", model).strip(" .,:;-")
        header = normalize_header(model)
        if not model or len(model) > 120:
            continue
        if "replacement" in header or "portfolio" in header:
            continue
        ribbon_add_product(products, model)
    return products


def ribbon_device_type(model: str, description: str = "") -> str:
    header = normalize_header(f"{model} {description}")
    if any(token in header for token in ("release", "software", "vnfm", "license", "licensing", "swe")):
        return "Ribbon software release or license"
    if any(token in header for token in ("service", "rma", "repair", "support")):
        return "Ribbon service SKU"
    if any(token in header for token in ("sbc", "session border", "edge", "gateway", "gsx", "sgx", "vx", "tenor")):
        return "Session border controller or VoIP gateway"
    if any(token in header for token in ("server", "raid", "chassis", "adapter", "module", "power", "psu")):
        return "Ribbon hardware module or appliance"
    return "Ribbon communications product"


def ribbon_row(
    *,
    model: str,
    description: str,
    title: str,
    source_name: str,
    dates: dict[str, str | None],
    support_ends_updates: bool = False,
) -> dict[str, Any]:
    support_end = dates.get("End of Support")
    status_parts = [title or "Ribbon lifecycle bulletin"]
    for label in (
        "Announcement Date",
        "End of Sale",
        "Last Ship Date",
        "End of Life",
        "End of Support",
    ):
        if dates.get(label):
            status_parts.append(f"{label.lower()} {dates[label]}")
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": f"Ribbon {model}",
        "Description": description or ribbon_device_type(model),
        "Product Status": "; ".join(status_parts),
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} Ribbon lifecycle bulletin",
        "_source_hint": "Ribbon/Sonus lifecycle bulletin PDF import",
        "_review_policy": "ribbon_lifecycle_bulletin_term_mapping",
        "_aliases": [model, f"Ribbon {model}", f"Sonus {model}"],
        "_prefer_model": True,
        "_suppress_description_aliases": True,
    }
    for label, value in dates.items():
        if value:
            row[label] = value
    if support_end:
        row["_review_policy"] = "ribbon_explicit_support_or_rnd_support_end"
        if support_ends_updates:
            row["Security Updates End"] = support_end
            row["_end_of_security_updates_override"] = support_end
    else:
        row["_force_lifecycle_review"] = True
        row["_review_reason"] = (
            "The Ribbon/Sonus bulletin publishes sale or lifecycle evidence, "
            "but it does not explicitly state an exact support, service, "
            "firmware, vulnerability, or security-update end date for this "
            "product row."
        )
    return row


def parse_ribbon_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    source_key = source_name.lower()
    if source_key in {"sonus-end-of-product-sale-policy-050717.pdf"}:
        return []
    normalized = normalize_text(text)
    header = normalize_header(normalized[:3000])
    if "ribbon" not in header and "sonus" not in header:
        return []
    if not any(
        phrase in header
        for phrase in (
            "end of product sale",
            "end of support",
            "end of service",
            "end of life",
            "eops",
            "eol",
        )
    ):
        return []

    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    title = ribbon_notice_title(lines)
    dates = ribbon_lifecycle_dates(text)
    if not any(value for key, value in dates.items() if key != "Announcement Date"):
        return []

    products = ribbon_table_products(text)
    if not products:
        products = ribbon_title_products(text, title, source_name)

    support_ends_updates = bool(
        re.search(
            r"\b(?:End of R&D Support|no longer receive software fixes|"
            r"without software updates/patches|without software patches|"
            r"no new software updates|security updates)\b",
            normalized,
            flags=re.I,
        )
    )

    rows: list[dict[str, Any]] = []
    for key in sorted(products):
        entry = products[key]
        rows.append(
            ribbon_row(
                model=entry["model"],
                description=entry.get("description", ""),
                title=title,
                source_name=source_name,
                dates=dates,
                support_ends_updates=support_ends_updates,
            )
        )
    return rows


VERTIV_AVOCENT_SOURCE_URLS = {
    "eol_notice_045_avocent_dsview_45_product_end_of_sale_av_49568.pdf": (
        "https://www.vertiv.com/48ec30/globalassets/products/monitoring-control-and-management/"
        "software/avocent-dsview-management-software/"
        "vertiv-avocent-dsview-4.5-management-software-product-end-of-sale-eos-av-49568-.pdf"
    ),
    "eol_notice_046_avocent_universal_management_gateway_6000_eol.pdf": (
        "https://www.vertiv.com/4911b1/globalassets/products/monitoring-control-and-management/"
        "ip-kvm/avocent-universal-management-gateway-6000-end-of-life.pdf"
    ),
    "eol_notice_047_avocent_acs6000_console_servers_eol.pdf": (
        "https://www.vertiv.com/globalassets/products/monitoring-control-and-management/"
        "serial-consoles-and-gateways/vertiv-acs6000-eol-en-na-kl-2018-0330_228058_0.pdf"
    ),
    "eol_notice_048_avocent_hmx_1000_2000_and_amx_high_performance_kvm_eol.pdf": (
        "https://www.vertiv.com/globalassets/products/monitoring-control-and-management/"
        "it-management/bulletin-end-of-life-avocent-hmx-10002000-and-amx-high-performance-kvm-.pdf"
    ),
    "eol_notice_049_avocent_rmk_81_hmx_rack_mount_eol.pdf": (
        "https://www.vertiv.com/globalassets/shared/"
        "avocent-rmk-81-rmk-for-hmx-5000-6000-end-of-life-.pdf"
    ),
}


def vertiv_avocent_row(
    *,
    model: str,
    product_name: str,
    description: str,
    product_status: str,
    source_name: str,
    source_url: str,
    aliases: list[str],
    replacement: str = "",
    announcement: str | None = None,
    end_of_sale: str | None = None,
    end_of_life: str | None = None,
    end_of_service: str | None = None,
    security_updates_end: str | None = None,
    force_review: bool = False,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": product_name,
        "Description": description,
        "Product Status": product_status,
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} Avocent lifecycle notice",
        "_source_hint": "Vertiv Avocent lifecycle PDF import",
        "_source_url": source_url,
        "_review_policy": (
            "vertiv_avocent_explicit_security_or_service_milestones"
            if security_updates_end or end_of_service
            else "vertiv_avocent_product_eol_extended_warranty_review"
        ),
        "_aliases": aliases,
        "_prefer_model": True,
    }
    if replacement:
        row["Replacement Products"] = replacement
    if announcement:
        row["Announcement Date"] = announcement
    if end_of_sale:
        row["End of Sale"] = end_of_sale
    if end_of_life:
        row["End of Life"] = end_of_life
    if end_of_service:
        row["End of Service"] = end_of_service
    if security_updates_end:
        row["Security Updates End"] = security_updates_end
        row["_end_of_security_updates_override"] = security_updates_end
    if force_review:
        row["_force_lifecycle_review"] = True
        row["_review_reason"] = (
            "The Vertiv notice publishes product EOL or extended-warranty "
            "milestones, but does not explicitly state that firmware, "
            "vulnerability, or security updates ended for this exact SKU."
        )
    return row


def parse_vertiv_avocent_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if source_name == "eol_notice_042_avocent_acs_6000_product_eol.pdf":
        return []
    source_url = VERTIV_AVOCENT_SOURCE_URLS.get(source_name)
    if not source_url:
        return []

    rows: list[dict[str, Any]] = []
    if source_name == "eol_notice_045_avocent_dsview_45_product_end_of_sale_av_49568.pdf":
        if "end of security updates" not in normalize_header(normalized):
            return []
        models = list(dict.fromkeys(re.findall(r"\bDSV4\.5-[A-Z0-9]+\b", text)))
        for model in models:
            rows.append(
                vertiv_avocent_row(
                    model=model,
                    product_name=f"Vertiv Avocent DSView 4.5 {model}",
                    description="Avocent DSView management software license",
                    product_status=(
                        "Avocent DSView 4.5 end-of-sale notice; final software "
                        "release and end of security updates December 2026; "
                        "full end-of-life technical support February 1, 2030"
                    ),
                    source_name=source_name,
                    source_url=source_url,
                    aliases=[model, "Avocent DSView 4.5", "DSView 4.5"],
                    replacement="Vertiv Avocent DSView Solution Management Software",
                    end_of_sale="2025-02-01",
                    security_updates_end="2026-12-31",
                    end_of_life="2030-02-01",
                )
            )
        return rows

    if source_name == "eol_notice_046_avocent_universal_management_gateway_6000_eol.pdf":
        if "UMG6000-400" not in normalized:
            return []
        return [
            vertiv_avocent_row(
                model="UMG6000-400",
                product_name="Vertiv Avocent Universal Management Gateway 6000",
                description="Universal management gateway appliance",
                product_status=(
                    "Avocent Universal Management Gateway 6000 product EOL; "
                    "end-of-sale December 31, 2017; product end of life "
                    "December 31, 2022"
                ),
                source_name=source_name,
                source_url=source_url,
                aliases=["UMG6000-400", "UMG6000", "Avocent UMG6000"],
                replacement="UMG4000-400",
                announcement="2017-10-31",
                end_of_sale="2017-12-31",
                end_of_life="2022-12-31",
                force_review=True,
            )
        ]

    if source_name == "eol_notice_047_avocent_acs6000_console_servers_eol.pdf":
        models = list(
            dict.fromkeys(
                re.findall(r"\bACS\d{4}[A-Z]+-G2(?:-G01)?\b", text)
            )
        )
        for model in models:
            rows.append(
                vertiv_avocent_row(
                    model=model,
                    product_name=f"Vertiv Avocent ACS6000 {model}",
                    description="Serial console server",
                    product_status=(
                        "Avocent ACS6000 product EOL; EOL announcement "
                        "March 30, 2018; end-of-sale July 31, 2018; "
                        "product end of life July 31, 2023"
                    ),
                    source_name=source_name,
                    source_url=source_url,
                    aliases=[model, "Avocent ACS6000", "ACS6000"],
                    replacement="Avocent ACS8000 / ACS800 family",
                    announcement="2018-03-30",
                    end_of_sale="2018-07-31",
                    end_of_life="2023-07-31",
                    force_review=True,
                )
            )
        return rows

    if source_name == "eol_notice_048_avocent_hmx_1000_2000_and_amx_high_performance_kvm_eol.pdf":
        impacted = normalized.split("Impacted SKU(s):", 1)[-1].split("For questions", 1)[0]
        models = list(
            dict.fromkeys(
                re.findall(
                    r"\b(?:MXR\d{4}-\d{3}|MXT\d{4}-[A-Z]+|DMK-\d+|"
                    r"PSC\d+|CBL\d+|RMK-\d+)\b",
                    impacted,
                )
            )
        )
        for model in models:
            rows.append(
                vertiv_avocent_row(
                    model=model,
                    product_name=f"Vertiv Avocent High-Performance KVM {model}",
                    description="High-performance KVM device or accessory",
                    product_status=(
                        "Avocent high-performance KVM product EOL; "
                        "end-of-sale December 31, 2022; end of service life "
                        "December 31, 2027"
                    ),
                    source_name=source_name,
                    source_url=source_url,
                    aliases=[model, "Avocent Matrix High-Performance KVM"],
                    announcement="2022-11-25",
                    end_of_sale="2022-12-31",
                    end_of_service="2027-12-31",
                )
            )
        return rows

    if source_name == "eol_notice_049_avocent_rmk_81_hmx_rack_mount_eol.pdf":
        if "RMK-81" not in normalized:
            return []
        return [
            vertiv_avocent_row(
                model="RMK-81",
                product_name="Vertiv Avocent RMK-81 rack mount kit",
                description="KVM rack mount kit",
                product_status=(
                    "Avocent RMK-81 product EOL; end-of-sale and product "
                    "end of life May 2017"
                ),
                source_name=source_name,
                source_url=source_url,
                aliases=["RMK-81", "Avocent RMK-81"],
                replacement="RMK-97",
                announcement="2017-05-31",
                end_of_sale="2017-05-31",
                end_of_life="2017-05-31",
                force_review=True,
            )
        ]

    return []


VERTIV_GEIST_SOURCE_RE = re.compile(
    r"^eol_notice_\d{3}_product_end_of_(?:life|support)_announcement",
    flags=re.I,
)
VERTIV_PART_TOKEN_RE = re.compile(
    r"^(?=.{3,20}$)(?=.*\d)[A-Z]{0,4}[A-Z0-9]{3,10}[A-Z]{0,3}$",
    flags=re.I,
)
VERTIV_MODEL_TOKEN_RE = re.compile(
    r"^(?=.{6,80}$)(?=.*[A-Z])(?=.*\d)[A-Z0-9][A-Z0-9-]*$",
    flags=re.I,
)


def vertiv_first_date(value: Any) -> str | None:
    return ribbon_first_date(value)


def vertiv_geist_dates(text: str) -> dict[str, str | None]:
    normalized = normalize_text(text)
    lines = [normalize_text(line) for line in text.splitlines() if normalize_text(line)]
    announcement = None
    for line in lines[:24]:
        if normalize_header(line).startswith("announcement"):
            announcement = vertiv_first_date(line)
            break
    if not announcement:
        for line in lines[:16]:
            announcement = vertiv_first_date(line)
            if announcement:
                break

    end_sale = None
    end_life = None
    end_service = None
    for pattern in (
        r"End of Sale\s*(?:\(and EOL\))?\s*:\s*[^.\n]+",
        r"Last day to accept orders\s*[-:]\s*[^.\n]+",
        r"last day orders will be accepted is\s+[^.]+",
        r"Effective\s+[^.]+?\s+[^.]*?no longer be available for sale",
    ):
        match = re.search(pattern, normalized, flags=re.I)
        if match:
            end_sale = vertiv_first_date(match.group(0))
            if end_sale:
                break
    for pattern in (
        r"End of Sale\s*\(and EOL\)\s*:\s*[^.\n]+",
        r"Effective\s+[^.]+?\s+[^.]*?(?:enter End of Life|will be discontinued|End of Life)",
        r"Effective Date\s*:?\s*[^.\n]+",
    ):
        match = re.search(pattern, normalized, flags=re.I)
        if match:
            end_life = vertiv_first_date(match.group(0))
            if end_life:
                break
    for pattern in (
        r"End of Service\s*:\s*[^.\n]+",
        r"End of Support\s*:\s*[^.\n]+",
    ):
        match = re.search(pattern, normalized, flags=re.I)
        if match:
            end_service = vertiv_first_date(match.group(0))
            if end_service:
                break
    return {
        "announcement": announcement,
        "end_sale": end_sale,
        "end_life": end_life,
        "end_service": end_service,
    }


def vertiv_is_part_token(value: str) -> bool:
    text = normalize_text(value).strip(".,;:")
    if normalize_header(text) in {"part", "part no", "item", "item no", "model"}:
        return False
    return bool(VERTIV_PART_TOKEN_RE.match(text))


def vertiv_is_model_token(value: str) -> bool:
    text = normalize_text(value).strip(".,;:")
    if normalize_header(text) in {"model", "model no", "replacement", "part no"}:
        return False
    if vertiv_is_part_token(text):
        return False
    return bool(VERTIV_MODEL_TOKEN_RE.match(text))


def vertiv_add_part_model(
    rows: dict[tuple[str, str], dict[str, str]],
    part: str,
    model: str,
) -> None:
    part = normalize_text(part).strip(".,;:")
    model = normalize_text(model).strip(".,;:")
    if not (vertiv_is_part_token(part) and vertiv_is_model_token(model)):
        return
    rows.setdefault((part, model), {"part": part, "model": model})


def vertiv_geist_part_model_rows(text: str) -> list[dict[str, str]]:
    in_table = False
    replacement_table = False
    rows: dict[tuple[str, str], dict[str, str]] = {}
    start_re = re.compile(
        r"(?:Part No\.?\s+Model No\.?|Item #.*Model #|PRODUCT\s+END OF)",
        flags=re.I,
    )
    stop_re = re.compile(
        r"\b(?:Vertiv\.com|VertivCo\.com|Copyright|All rights reserved|"
        r"Key Dates|Contact your Vertiv|For more information|OVER VIEW|OVERVIEW)\b",
        flags=re.I,
    )
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        normalized = normalize_text(line)
        header = normalize_header(normalized)
        if not normalized:
            continue
        if start_re.search(normalized):
            in_table = True
            replacement_table = "replacement" in header
            continue
        if in_table and stop_re.search(normalized):
            in_table = False
            replacement_table = False
        if not in_table:
            continue
        if "replacement" in header and ("model" in header or "item" in header):
            replacement_table = True
            continue
        tokens = normalized.split()
        pairs: list[tuple[str, str]] = []
        index = 0
        while index + 1 < len(tokens):
            part = tokens[index]
            model = tokens[index + 1]
            if vertiv_is_part_token(part) and vertiv_is_model_token(model):
                pairs.append((part, model))
                index += 2
            else:
                index += 1
        if not pairs:
            continue
        if replacement_table:
            pairs = pairs[:1]
        for part, model in pairs:
            vertiv_add_part_model(rows, part, model)
    return [rows[key] for key in sorted(rows)]


def vertiv_geist_device_type(model: str, source_name: str) -> str:
    header = normalize_header(f"{model} {source_name}")
    if any(token in header for token in ("watchdog", "climate", "environmental")):
        return "Environmental monitor"
    if any(token in header for token in ("pdu", "powerit", "rpdus", "rack pdu", "geist")):
        return "Rack power distribution unit"
    if "transfer switch" in header or "ats" in header:
        return "Automatic transfer switch"
    return "Vertiv Geist power or monitoring product"


def vertiv_geist_row(
    *,
    part: str,
    model: str,
    source_name: str,
    dates: dict[str, str | None],
) -> dict[str, Any]:
    status_parts = ["Vertiv Geist/PDU lifecycle notice"]
    if dates.get("announcement"):
        status_parts.append(f"announcement date {dates['announcement']}")
    if dates.get("end_sale"):
        status_parts.append(f"end of sale {dates['end_sale']}")
    if dates.get("end_life"):
        status_parts.append(f"end of life {dates['end_life']}")
    if dates.get("end_service"):
        status_parts.append(f"end of service {dates['end_service']}")

    row: dict[str, Any] = {
        "Model": model,
        "Part Number": part,
        "Product Name": f"Vertiv {model}",
        "Description": vertiv_geist_device_type(model, source_name),
        "Product Status": "; ".join(status_parts),
        "Lifecycle Status Source": source_name,
        "_source_table": f"{source_name} Vertiv Geist/PDU lifecycle notice",
        "_source_hint": "Vertiv Geist/PDU lifecycle PDF import",
        "_review_policy": (
            "vertiv_geist_explicit_end_of_service"
            if dates.get("end_service")
            else "vertiv_geist_sale_or_eol_review"
        ),
        "_aliases": [part, model, f"Vertiv {part}", f"Vertiv {model}", f"Geist {model}"],
        "_prefer_model": True,
    }
    if dates.get("announcement"):
        row["Announcement Date"] = dates["announcement"]
    if dates.get("end_sale"):
        row["End of Sale"] = dates["end_sale"]
    if dates.get("end_life"):
        row["End of Life"] = dates["end_life"]
    if dates.get("end_service"):
        row["End of Service"] = dates["end_service"]
    else:
        row["_force_lifecycle_review"] = True
        row["_review_reason"] = (
            "The Vertiv Geist/PDU notice publishes sale, EOL, or replacement "
            "lifecycle evidence, but it does not explicitly state an exact "
            "support, service, firmware, vulnerability, or security-update "
            "end date for this SKU."
        )
    return row


def parse_vertiv_geist_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    if not VERTIV_GEIST_SOURCE_RE.match(source_name):
        return []
    if "product_change_notification" in source_name.lower():
        return []
    normalized = normalize_text(text)
    header = normalize_header(normalized[:3000])
    if "vertiv" not in header and "geist" not in header:
        return []
    if "end of life" not in header and "end-of-life" not in header:
        return []

    dates = vertiv_geist_dates(text)
    if not any(value for key, value in dates.items() if key != "announcement"):
        return []
    entries = vertiv_geist_part_model_rows(text)
    return [
        vertiv_geist_row(
            part=entry["part"],
            model=entry["model"],
            source_name=source_name,
            dates=dates,
        )
        for entry in entries
    ]


def parse_vertiv_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    rows = parse_vertiv_avocent_pdf_rows_from_text(text, source_name)
    if rows:
        return rows
    return parse_vertiv_geist_pdf_rows_from_text(text, source_name)


SIERRA_AIRLINK_SOURCE_BASE = (
    "https://source.sierrawireless.com/resources/airlink/hardware_reference_docs"
)


def sierra_airlink_source_url(source_name: str) -> str:
    slug = source_name.split("__", 1)[0].strip("_")
    if not slug:
        return "https://source.sierrawireless.com/"
    return f"{SIERRA_AIRLINK_SOURCE_BASE}/{slug}/"


SIERRA_AIRLINK_DATE_RE = re.compile(
    r"(?:\d{1,2}/\d{1,2}/\d{2,4}|"
    r"\d{1,2}[-\s]+[A-Za-z]{3,9}[-,\s]+\d{2,4}|"
    r"[A-Za-z]{3,9}[-\s]+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}|"
    r"[A-Za-z]{3,9}-\d{1,2}-\d{4})",
    flags=re.I,
)


def sierra_airlink_lifecycle_date(text: str, labels: tuple[str, ...]) -> str | None:
    lines = text.splitlines()
    for label in labels:
        normalized_label = normalize_header(label)
        for index, line in enumerate(lines):
            if not normalize_header(line).startswith(normalized_label):
                continue
            window = " ".join(lines[index:index + 8])
            match = SIERRA_AIRLINK_DATE_RE.search(window)
            if not match:
                continue
            parsed = parse_date_any(match.group(0))
            if parsed:
                return parsed
    return None


def sierra_airlink_text_section(
    text: str,
    start: str,
    stops: tuple[str, ...],
) -> str:
    match = re.search(re.escape(start), text, flags=re.I)
    if not match:
        return ""
    section = text[match.end():]
    stop_positions = [
        found.start()
        for stop in stops
        if (found := re.search(rf"^\s*{re.escape(stop)}\b", section, flags=re.I | re.M))
    ]
    if stop_positions:
        section = section[: min(stop_positions)]
    return section


def sierra_airlink_affected_models(text: str) -> list[str]:
    models: list[str] = []
    for line in text.splitlines():
        if not normalize_header(line).startswith("affected models"):
            continue
        value = normalize_text(line.split(":", 1)[1] if ":" in line else "")
        if value:
            models.append(value)
    return models


SIERRA_AIRLINK_FAMILIES = (
    "RV50X",
    "RV50",
    "RV55",
    "ES450",
    "GX400",
    "GX450",
    "LS300",
    "LX40",
    "LX60",
    "MG90",
    "MP70E",
    "MP70",
)


def sierra_airlink_family(*values: str) -> str:
    for value in values:
        for family in SIERRA_AIRLINK_FAMILIES:
            if re.search(rf"\b{re.escape(family)}\b", value or "", flags=re.I):
                return family
    return ""


def sierra_airlink_notice_title(text: str, fallback_model: str) -> str:
    for line in text.splitlines():
        clean = normalize_text(line)
        if re.search(r"\bEnd of Sale Announcement\b", clean, flags=re.I):
            return clean
    if re.search(r"\bEND-OF-SALE\s+ANNOUC?EMENT\b", text, flags=re.I):
        family = sierra_airlink_family(fallback_model)
        return f"End of Sale Announcement: {family or fallback_model}".strip()
    return "Sierra Wireless AirLink end-of-sale notice"


def sierra_airlink_sale_groups(text: str) -> list[tuple[str, str]]:
    section = sierra_airlink_text_section(
        text,
        "PRODUCTION MILESTONES",
        ("PRODUCT SUPPORT AND MAINTENANCE",),
    )
    if not section:
        return []
    groups: list[tuple[str, str]] = []
    matches = list(
        re.finditer(
            r"(?ims)^\s*AFFECTED MODELS:\s*(?P<model>.+?)\n(?P<body>.*?)(?=^\s*AFFECTED MODELS:|\Z)",
            section,
        )
    )
    for match in matches:
        model = normalize_text(match.group("model"))
        end_sale = sierra_airlink_lifecycle_date(
            match.group(0),
            ("Last Time Buy", "End of Sale Date"),
        )
        if model and end_sale:
            groups.append((model, end_sale))
    return groups


SIERRA_AIRLINK_VARIANT_TOKENS = (
    "AT&T",
    "VERIZON",
    "SPRINT",
    "ROW/CANADA",
    "CANADA",
    "AU/NZ",
    "APAC",
    "INTL",
    "NA GENERIC",
    "EMEA",
    "LPWA",
    "CBRS",
    "US",
    "WI-FI",
    "WIFI",
    "ETHERNET",
    "I/O",
)


def sierra_airlink_end_sale_for_description(
    description: str,
    groups: list[tuple[str, str]],
    default_end_sale: str,
) -> str:
    desc_upper = description.upper()
    for model, end_sale in groups:
        model_upper = model.upper()
        if "ALL" in model_upper:
            continue
        tokens = [token for token in SIERRA_AIRLINK_VARIANT_TOKENS if token in model_upper]
        if tokens and any(token in desc_upper for token in tokens):
            return end_sale
    return default_end_sale


def sierra_airlink_clean_part_description(description: str) -> str:
    description = normalize_text(description)
    description = re.sub(r"\bSee Suggested .*", "", description, flags=re.I).strip()
    description = re.sub(r"\s+PART No\.$", "", description, flags=re.I).strip()
    return description


def sierra_airlink_layout_part_rows(text: str, required_family: str = "") -> list[tuple[str, str]]:
    section = sierra_airlink_text_section(
        text,
        "AFFECTED PART NUMBERS",
        (
            "SUGGESTED ROUTER REPLACEMENTS",
            "SUGGESTED XR80/90 ROUTER REPLACEMENTS",
            "MG90 ACCESSORIES END OF SALE",
            "MG90 ANTENNAS END OF SALE",
            "CONTACT",
            "REVISION HISTORY",
        ),
    )
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in section.splitlines():
        leading_spaces = len(line) - len(line.lstrip())
        cells = [cell.strip() for cell in re.split(r"\s{2,}", line.strip()) if cell.strip()]
        part_index = next(
            (index for index, cell in enumerate(cells) if re.fullmatch(r"\d{7}", cell)),
            None,
        )
        if part_index is None:
            continue
        if part_index > 0 and leading_spaces > 24:
            continue
        if part_index == 0:
            description = cells[1] if len(cells) > 1 else ""
        else:
            description = cells[part_index - 1]
        description = sierra_airlink_clean_part_description(description)
        if (
            not description
            or not re.search(r"[A-Za-z]", description)
            or normalize_header(description) in {"part no", "model", "model description"}
        ):
            continue
        if required_family and not re.search(
            rf"\b{re.escape(required_family)}\b",
            description,
            flags=re.I,
        ):
            continue
        part = cells[part_index]
        if part in seen:
            continue
        rows.append((part, description))
        seen.add(part)
    return rows


def sierra_airlink_rv50x_raw_part_rows(raw_text: str) -> list[tuple[str, str]]:
    section = sierra_airlink_text_section(
        raw_text,
        "AFFECTED PART NUMBERS",
        ("SUGGESTED ROUTER REPLACEMENTS",),
    )
    rows: list[tuple[str, str]] = []
    lines = section.splitlines()
    for index, line in enumerate(lines):
        match = re.fullmatch(r"\s*(\d{7})\s*", line)
        if not match:
            continue
        description_parts: list[str] = []
        for next_line in lines[index + 1:index + 5]:
            clean = normalize_text(next_line)
            if not clean or re.fullmatch(r"\d{7}.*", clean):
                break
            if re.search(r"replacement|suggested", clean, flags=re.I):
                continue
            if re.search(r"\bRV50X\b", clean, flags=re.I):
                description_parts.append(clean)
                continue
            if description_parts and "AirLink Complete" in clean:
                description_parts.append(clean)
        description = sierra_airlink_clean_part_description(" ".join(description_parts))
        if description:
            rows.append((match.group(1), description))
    return rows


def sierra_airlink_part_rows(
    text: str,
    source_name: str,
    raw_text: str | None,
    required_family: str = "",
) -> list[tuple[str, str]]:
    rows = sierra_airlink_layout_part_rows(text, required_family)
    seen = {part for part, _ in rows}
    if raw_text and "rv50x-end-of-sale" in source_name:
        for part, description in sierra_airlink_rv50x_raw_part_rows(raw_text):
            if part not in seen:
                rows.append((part, description))
                seen.add(part)
    return rows


def sierra_airlink_skip_part_row(source_name: str, description: str) -> bool:
    desc = description.upper()
    if source_name == "airlink_es450_eol__es450_eol_notice.ashx.pdf":
        return "SPRINT" in desc
    if source_name == "airlink_gx450_eol_notices__gx450_eos_notice.ashx.pdf":
        return any(token in desc for token in ("SPRINT", "I/O", "ETHERNET"))
    return False


def parse_sierra_airlink_pdf_rows_from_text(
    text: str,
    source_name: str,
    *,
    raw_text: str | None = None,
) -> list[dict[str, Any]]:
    if not re.search(r"\bEnd of Sale Announcement\b|END-OF-SALE", text, flags=re.I):
        return []
    if "PRODUCT SUPPORT AND MAINTENANCE" not in text:
        return []
    if not re.search(
        r"No new (?:device|router) software will be released after this date",
        text,
        flags=re.I,
    ):
        return []

    affected_models = sierra_airlink_affected_models(text)
    affected_model = affected_models[0] if affected_models else ""
    family = sierra_airlink_family(affected_model, source_name)
    announcement = sierra_airlink_lifecycle_date(text, ("Date Issued",))
    default_end_sale = sierra_airlink_lifecycle_date(text, ("Last Time Buy", "End of Sale Date"))
    support_end = sierra_airlink_lifecycle_date(text, ("End of Software",))
    if not default_end_sale or not support_end:
        return []

    title = sierra_airlink_notice_title(text, affected_model)
    source_url = sierra_airlink_source_url(source_name)
    sale_groups = sierra_airlink_sale_groups(text)
    rows: list[dict[str, Any]] = []
    for part_number, description in sierra_airlink_part_rows(
        text,
        source_name,
        raw_text,
        family,
    ):
        if sierra_airlink_skip_part_row(source_name, description):
            continue
        row_family = sierra_airlink_family(description, affected_model, title) or family
        end_sale = sierra_airlink_end_sale_for_description(
            description,
            sale_groups,
            default_end_sale,
        )
        aliases = [part_number, description]
        if row_family:
            aliases.extend(
                [
                    row_family,
                    f"AirLink {row_family}",
                    f"Sierra Wireless AirLink {row_family}",
                ]
            )
        if affected_model:
            aliases.append(affected_model)
        row: dict[str, Any] = {
            "Model": part_number,
            "Part Number": part_number,
            "Product Name": f"Sierra Wireless AirLink {description}",
            "Description": description,
            "Product Status": title,
            "End of Sale": end_sale,
            "End of Support": support_end,
            "End of Security Updates": support_end,
            "_source_table": f"{source_name} affected part numbers",
            "_source_hint": "Sierra Wireless AirLink end-of-sale PDF import",
            "_source_url": source_url,
            "_review_policy": "sierra_airlink_end_of_software_maintenance_security_updates",
            "_aliases": aliases,
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        rows.append(row)
    return rows


def parse_telrad_cpe8100_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "Manufacturing Discontinued Notice" not in normalized:
        return []
    if "CPE 8100" not in normalized and "CPE8100" not in normalized:
        return []
    if "active Service Level Agreement" not in normalized:
        return []

    announcement = first_parsed_date(normalized)
    match = re.search(
        r"(?:end-of-life|end of life).*?as of\s+"
        r"([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})",
        normalized,
        flags=re.I,
    )
    end_sale = parse_date_any(match.group(1)) if match else None
    if not end_sale:
        return []

    row: dict[str, Any] = {
        "Model": "CPE8100",
        "Part Number": "735081xx",
        "Product Name": "CPE8100-PRO-1D-3.x",
        "Description": "LTE outdoor CPE",
        "Product Status": (
            "Manufacturing discontinued notice; expected end-of-life for "
            "CPE8100 model; support continues for customers with active SLA"
        ),
        "End of Sale": end_sale,
        "Last Sale": end_sale,
        "Replacement Products": "CPE9000; CPE9000HG; CPE12000",
        "Lifecycle Status Source": TELRAD_CPE8100_URL,
        "_source_table": f"{source_name} discontinued CPE table",
        "_source_hint": "Telrad CPE8100 manufacturing discontinued PDF import",
        "_source_url": TELRAD_CPE8100_URL,
        "_force_lifecycle_review": True,
        "_review_policy": "telrad_cpe8100_manufacturing_discontinued_support_continues",
        "_review_reason": (
            "Telrad's CPE8100 notice says manufacturing is discontinued "
            "and calls it end-of-life, but also says Telrad intends to "
            "continue support for customers holding an active SLA; no "
            "exact support or security-update end date is published."
        ),
        "_aliases": [
            "CPE8100",
            "CPE 8100",
            "CPE8100 Outdoor",
            "CPE8100-PRO-1D-3.x",
            "735081xx",
        ],
        "_prefer_model": True,
    }
    if announcement:
        row["Announcement Date"] = announcement
    return [row]


ZPE_EOL_PAGE_URL = "https://zpesystems.com/end-of-life/"
ZPE_NSC_PLUS_5G_PDF_URL = (
    "https://go.zpesystems.com/rs/004-BTR-463/images/"
    "2025-02-06%20-%20End%20of%20Sale%20Notice%20-%20"
    "ZPE-NSCP-T96R-STND-xxx-5G.pdf"
)
ZPE_GATE_SR_EOL_PDF_URL = (
    "https://go.zpesystems.com/rs/004-BTR-463/images/"
    "End%20of%20Life%20Announcement%20-%20Selected%20Nodegrid%20"
    "Gate%20SR%20Configurations.pdf"
)
ZPE_LINK_SR_EOL_PDF_URL = (
    "https://go.zpesystems.com/rs/004-BTR-463/images/"
    "End%20of%20Life%20Announcement%20-%20Selected%20Nodegrid%20"
    "Link%20SR%20Configurations.pdf"
)
ZPE_GATE_SR_REPLACEMENTS = {
    "GSR-T8-BASE": "ZPE-GSR-48-BASE-F",
    "ZPE-GSR-48-BASE": "ZPE-GSR-48-BASE-F",
    "ZPE-GSR-48-W5": "ZPE-GSR-48-W5-F",
    "ZPE-GSR-48-4G": "ZPE-GSR-48-4G-F",
    "ZPE-GSR-48-4G-W5": "ZPE-GSR-48-4G-W5-F",
    "ZPE-GSR-48-4G-W5-D128G": "ZPE-GSR-48-4G-W5-D128G-F",
    "ZPE-GSR-48-D128G": "ZPE-GSR-48-D128G-F",
    "ZPE-GSR-48-BASE-GW": "ZPE-GSR-48-BASE-F-GW",
    "ZPE-GSR-48-W5-GW": "ZPE-GSR-48-W5-F-GW",
    "ZPE-GSR-48-4G-GW": "ZPE-GSR-48-4G-F-GW",
}
ZPE_LINK_SR_PARTS = [
    "LSR-T1-UPG2",
    "ZPE-LSR-48-BASE",
    "ZPE-LSR-48-W5",
    "ZPE-LSR-48-4G",
    "ZPE-LSR-48-4G-W5",
]


def zpe_pdf_url(source_name: str) -> str:
    lowered = source_name.lower()
    if "nscp" in lowered or "t96r" in lowered:
        return ZPE_NSC_PLUS_5G_PDF_URL
    if "gate" in lowered:
        return ZPE_GATE_SR_EOL_PDF_URL
    if "link" in lowered:
        return ZPE_LINK_SR_EOL_PDF_URL
    return ZPE_EOL_PAGE_URL


def zpe_clean_sku(value: str) -> str:
    text = re.sub(r"[\x00-\x1f]+", " ", str(value or ""))
    text = normalize_text(text)
    text = re.sub(r"\s*-\s*", "-", text)
    text = re.sub(r"\b(T96R)\s+(STND)\b", r"\1-\2", text)
    text = re.sub(r"\b(D1)\s+(28G)\b", r"\1\2", text)
    text = re.sub(r"\b(F-G)\s+(W)\b", r"\1\2", text)
    return text


def zpe_text_contains_sku(text: str, sku: str) -> bool:
    cleaned = zpe_clean_sku(text)
    return bool(
        re.search(
            rf"(?<![A-Z0-9-]){re.escape(sku)}(?![A-Z0-9-])",
            cleaned,
        )
    )


def zpe_milestone_dates(text: str) -> dict[str, str | None]:
    normalized = normalize_text(text)
    dates: dict[str, str | None] = {
        "announcement": None,
        "end_of_sale": None,
        "last_ship": None,
        "end_of_support": None,
    }
    label_map = {
        "end of life announcement": "announcement",
        "last order sale date": "end_of_sale",
        "last ship date": "last_ship",
        "end of support date": "end_of_support",
    }
    date_re = r"[A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}"
    for match in re.finditer(
        rf"({date_re})\s+("
        r"End-of-Life Announcement|Last Order/Sale Date|Last Ship Date|"
        r"End of Support Date"
        r")",
        normalized,
        flags=re.I,
    ):
        parsed = parse_date_any(match.group(1))
        key = label_map.get(normalize_header(match.group(2)))
        if parsed and key:
            dates[key] = dates[key] or parsed
    label_patterns = {
        "announcement": r"End-of-Life Announcement\s*\(EOL\)",
        "end_of_sale": r"Last Order/Sale Date\s*\(LOD\)",
        "last_ship": r"Last Ship Date\s*\(LSD\)",
        "end_of_support": r"End of Support Date\s*\(EOS\)",
    }
    for key, label_pattern in label_patterns.items():
        if dates.get(key):
            continue
        match = re.search(label_pattern, normalized, flags=re.I)
        if not match:
            continue
        window = normalized[match.end():match.end() + 280]
        date_match = re.search(date_re, window, flags=re.I)
        if not date_match:
            continue
        parsed = parse_date_any(date_match.group(0))
        if parsed:
            dates[key] = parsed
    return dates


def zpe_common_pdf_row(
    *,
    model: str,
    product_name: str,
    description: str,
    status: str,
    source_name: str,
    source_hint: str,
    replacement: str = "",
    aliases: list[str] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "Model": model,
        "Part Number": model,
        "Product Name": product_name,
        "Description": description,
        "Product Status": status,
        "_source_table": f"{source_name} affected part numbers",
        "_source_hint": source_hint,
        "_source_url": zpe_pdf_url(source_name),
        "_aliases": aliases or [],
        "_prefer_model": True,
    }
    if replacement:
        row["Replacement Products"] = replacement
    return row


def parse_zpe_nscp_5g_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    cleaned = zpe_clean_sku(text)
    if "End of Sale Notice" not in text:
        return []
    if "ZPE-NSCP-T96R-STND-xxx-5G" not in cleaned:
        return []
    if "Nodegrid Serial Console Plus" not in text:
        return []

    announcement = pdf_lifecycle_date(text, ("End-of-Sale Announcement Date",))
    end_sale = pdf_lifecycle_date(text, ("End-of-Sale Date", "End of Sale Date"))
    end_life = pdf_lifecycle_date(text, ("End of Life",))
    if not end_sale or not end_life:
        return []

    power_descriptions = {
        "SAC": "Single AC",
        "DAC": "Dual AC",
        "DDC": "Dual DC",
    }
    rows: list[dict[str, Any]] = []
    for power_code, power_description in power_descriptions.items():
        model = f"ZPE-NSCP-T96R-STND-{power_code}-5G"
        replacement = f"ZPE-NSCP-T96R-STND-{power_code}-4G"
        if (
            not zpe_text_contains_sku(cleaned, model)
            and f"STND-{power_code}-5G" not in cleaned
        ):
            continue
        row = zpe_common_pdf_row(
            model=model,
            product_name=(
                "Nodegrid Serial Console Plus 96-port 5G cellular module "
                f"({power_description})"
            ),
            description=(
                "Nodegrid Serial Console Plus serial console, 96-port "
                f"5G cellular connectivity, {power_description}"
            ),
            status=(
                "End-of-Sale notice; End of Life date listed; extended support "
                "contract can go beyond End-of-Life date"
            ),
            source_name=source_name,
            source_hint="ZPE Systems Nodegrid Serial Console Plus end-of-sale PDF import",
            replacement=replacement,
            aliases=[
                model,
                replacement,
                "Nodegrid Serial Console Plus",
                "NSCP",
                "ZPE-NSCP-T96R-STND-xxx-5G",
            ],
        )
        if announcement:
            row["Announcement Date"] = announcement
        row["End of Sale"] = end_sale
        row["Last Sale"] = end_sale
        row["End of Life"] = end_life
        row["_force_lifecycle_review"] = True
        row["_review_policy"] = "zpe_nscp_end_of_life_not_support_or_security_end"
        row["_review_reason"] = (
            "ZPE lists an End of Life date for the NSCP 5G SKU, but the PDF "
            "FAQ says extended support contracts can go beyond that date; no "
            "exact End of Support or security-update end date is published."
        )
        rows.append(row)
    return rows


def parse_zpe_gate_link_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "ZPE Systems is announcing the End-of-Life" not in normalized:
        return []
    if "End of Support Date" not in normalized:
        return []

    is_gate = "Select Nodegrid Gate SR Configurations" in normalized
    is_link = "Select Nodegrid Link SR Configurations" in normalized
    if not is_gate and not is_link:
        return []

    dates = zpe_milestone_dates(text)
    if not dates.get("end_of_sale") or not dates.get("end_of_support"):
        return []

    if is_gate:
        source_hint = "ZPE Systems Nodegrid Gate SR end-of-life PDF import"
        product_family = "Nodegrid Gate SR"
        description = "Nodegrid Gate SR serial console/gateway"
        replacements = ZPE_GATE_SR_REPLACEMENTS
    else:
        source_hint = "ZPE Systems Nodegrid Link SR end-of-life PDF import"
        product_family = "Nodegrid Link SR"
        description = "Nodegrid Link SR serial console"
        replacements = {part: "Planned for 2026" for part in ZPE_LINK_SR_PARTS}

    rows: list[dict[str, Any]] = []
    for model, replacement in replacements.items():
        if not zpe_text_contains_sku(normalized, model):
            continue
        row = zpe_common_pdf_row(
            model=model,
            product_name=f"{product_family} {model}",
            description=description,
            status=(
                "End-of-Life announcement and discontinuation; Last Order/Sale "
                "Date and End of Support Date listed"
            ),
            source_name=source_name,
            source_hint=source_hint,
            replacement=replacement,
            aliases=[model, replacement, product_family, f"ZPE {product_family}"],
        )
        if dates.get("announcement"):
            row["Announcement Date"] = dates["announcement"]
        row["End of Sale"] = dates["end_of_sale"]
        row["Last Sale"] = dates["end_of_sale"]
        if dates.get("last_ship"):
            row["Last Ship Date"] = dates["last_ship"]
        row["End of Support"] = dates["end_of_support"]
        row["_review_policy"] = "zpe_end_of_support_date_is_technical_support_end"
        rows.append(row)
    return rows


def parse_zpe_systems_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    rows = parse_zpe_nscp_5g_pdf_rows_from_text(text, source_name)
    if rows:
        return rows
    return parse_zpe_gate_link_pdf_rows_from_text(text, source_name)


IDIRECTGOV_EOL_GUIDE_URL = (
    "https://www.idirectgov.com/media/tdvbip5s/"
    "idirectgov_eol_reference_guide_07152025_readyforfinalreviewrev2.pdf"
)
IDIRECT_PRODUCT_SUPPORT_POLICY_URL = (
    "https://www.idirect.net/wp-content/uploads/2023/10/"
    "End-of-Life-Policy-Final-Version08142023.pdf"
)
IDIRECTGOV_MONTH_DATE_RE = re.compile(
    r"(January|February|March|April|May|June|July|August|September|October|"
    r"November|December)\s+\d{1,2}(?:st|nd|rd|th)?,(?:\s+\d{4})?",
    flags=re.I,
)
IDIRECTGOV_YEAR_ONLY_RE = re.compile(r"^\s*\d{4}\s*$")


def idirectgov_skip_pdf_line(line: str) -> bool:
    text = normalize_text(line)
    if not text:
        return True
    if text.startswith("End of Life Reference Guide"):
        return True
    if text in {
        "About This Guide",
        "Contents",
        "Purpose",
        "Intended Audience",
        "End of Life Cycle Description",
        "Getting Help",
        "Hub Equipment",
        "Remote Satellite Routers",
        "Signal Management and Monitoring",
        "Newtec Products",
        "Miscellaneous",
        "Hubs",
    }:
        return True
    return "EOL Date" in text or "EOS Date" in text


def idirectgov_device_description(product: str) -> str:
    key = normalize_header(product)
    if "software" in key or "web optimizer" in key or "itoolkit" in key:
        return "Software"
    if "line card" in key or "board" in key:
        return "Satellite hub line card module"
    if "switch" in key:
        return "Network switch"
    if "router" in key:
        return "Satellite router"
    if "modem" in key:
        return "Satellite modem"
    if "server" in key or key.startswith(("dell ", "ibm ")):
        return "Server appliance"
    if "hub" in key:
        return "Satellite hub"
    if any(
        token in key
        for token in (
            "upconverter",
            "downconverter",
            "combiner",
            "lnb",
            "noise controller",
            "distribution unit",
            "geolocation",
            "spectrum monitoring",
            "pcma",
            "skymonitor",
            "summing chassis",
        )
    ):
        return "Satellite signal management device"
    return "Satellite network device"


def idirectgov_aliases(product: str) -> list[str]:
    aliases = [product, f"iDirect Government {product}", f"ST Engineering iDirect {product}"]
    match = re.fullmatch(r"([A-Za-z]+)(\d+)/(?:[A-Za-z]+)?(\d+)", product)
    if match:
        prefix, first, second = match.groups()
        aliases.extend([f"{prefix}{first}", f"{prefix}{second}"])
    return aliases


def parse_idirectgov_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    if "End of Life Reference Guide" not in text:
        return []
    if "EOS: End of Life + 3 years" not in text:
        return []
    if "Technical Support" not in text or "End of Life Date" not in text:
        return []

    lines = text.splitlines()
    rows: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    started = False
    index = 0
    while index < len(lines):
        line = lines[index].lstrip("\f")
        stripped = normalize_text(line)
        if stripped == "Hub Equipment":
            started = True
        if not started:
            index += 1
            continue
        if idirectgov_skip_pdf_line(line):
            if pending and not stripped:
                rows.append(pending)
                pending = None
            index += 1
            continue

        date_matches = list(IDIRECTGOV_MONTH_DATE_RE.finditer(line))
        if date_matches:
            if pending:
                rows.append(pending)
                pending = None
            next_line = lines[index + 1] if index + 1 < len(lines) else ""
            next_text = normalize_text(next_line)
            pieces: list[str] = []
            consume_next_year = False
            for match in date_matches[:2]:
                piece = normalize_text(match.group(0))
                if not re.search(r"\d{4}$", piece) and IDIRECTGOV_YEAR_ONLY_RE.match(next_text):
                    piece = f"{piece} {next_text}"
                    consume_next_year = True
                pieces.append(piece)
            if len(pieces) >= 2:
                eol = parse_date_any(pieces[0])
                eos = parse_date_any(pieces[1])
                product = normalize_text(line[: date_matches[0].start()]).strip(" -;")
                if product and eol and eos:
                    pending = {
                        "Model": product,
                        "Part Number": product,
                        "Product Name": product,
                        "Description": idirectgov_device_description(product),
                        "Product Status": "EOL and EOS dates listed",
                        "End of Life": eol,
                        "End of Support": eos,
                        "Lifecycle Status Source": IDIRECT_PRODUCT_SUPPORT_POLICY_URL,
                        "_source_table": f"{source_name} EOL/EOS schedule",
                        "_source_hint": "iDirectGov EOL/EOS reference guide PDF import",
                        "_source_url": IDIRECTGOV_EOL_GUIDE_URL,
                        "_review_policy": "idirectgov_eos_is_end_of_support",
                        "_review_reason": (
                            "iDirect Government defines EOS as End of Life plus "
                            "three years; the policy says End of Support means "
                            "the product is no longer repaired, maintained, or "
                            "supported."
                        ),
                        "_aliases": idirectgov_aliases(product),
                        "_prefer_model": True,
                    }
            index += 2 if consume_next_year else 1
            continue

        if pending and not IDIRECTGOV_YEAR_ONLY_RE.match(stripped):
            pending["Model"] = normalize_text(f"{pending['Model']} {stripped}").strip()
            pending["Part Number"] = pending["Model"]
            pending["Product Name"] = pending["Model"]
            pending["Description"] = idirectgov_device_description(pending["Model"])
            pending["_aliases"] = idirectgov_aliases(pending["Model"])
        index += 1

    if pending:
        rows.append(pending)
    return rows


SCHNEIDER_APC_CONNEXIUM_NOTICE_URL = (
    "https://www.se.com/us/en/download/document/RAL22AM0003-IDPAC/"
)


def parse_schneider_apc_connexium_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    normalized = normalize_text(text)
    if "ConneXium Unmanaged Switch 3TX" not in normalized:
        return []
    if "TCSESU033FN0" not in normalized or "MCSESU053FN0" not in normalized:
        return []
    if not re.search(r"\bProduct\b.{0,120}\bSupport Ends\b", normalized, flags=re.I):
        return []
    if "End of Commercialization" not in normalized:
        return []

    critical_match = re.search(
        r"Critical Dates(?P<section>.+?)(?:Transition Tools:|Definition of Dates:)",
        text,
        flags=re.I | re.S,
    )
    if not critical_match:
        return []
    critical_dates = [
        parsed
        for parsed in (
            parse_date_any(match.group(0))
            for match in re.finditer(r"\b\d{1,2}/\d{1,2}/\d{4}\b", critical_match.group("section"))
        )
        if parsed
    ]
    if len(critical_dates) < 3:
        return []

    announcement_text = re.split(
        r"\bDescription of Change:",
        text,
        maxsplit=1,
        flags=re.I,
    )[0]
    announcement = first_parsed_date(announcement_text)
    part_number = "TCSESU033FN0"
    replacement = "MCSESU053FN0"
    row: dict[str, Any] = {
        "Model": part_number,
        "Part Number": part_number,
        "Product Name": "Schneider Electric ConneXium Unmanaged Switch 3TX",
        "Description": "ConneXium unmanaged network switch",
        "Device Type": "Network Switch",
        "Product Status": (
            "End of commercialization notice; Critical Dates table lists "
            "Product Support Ends"
        ),
        "Last Sale": critical_dates[0],
        "End of Support": critical_dates[1],
        "End of Sale": critical_dates[-1],
        "Replacement Products": replacement,
        "_source_table": f"{source_name} critical dates",
        "_source_hint": "Schneider APC ConneXium end-of-commercialization PDF import",
        "_source_url": SCHNEIDER_APC_CONNEXIUM_NOTICE_URL,
        "_review_policy": "schneider_apc_connexium_product_support_end",
        "_review_reason": (
            "The Schneider Electric Critical Dates table explicitly lists "
            "Product Support Ends for TCSESU033FN0; no separate firmware, "
            "security-update, or vulnerability-support date is inferred."
        ),
        "_aliases": [
            part_number,
            "ConneXium Unmanaged Switch 3TX",
            "ConneXium 3TX",
        ],
        "_prefer_model": True,
    }
    if announcement:
        row["Announcement Date"] = announcement
    return [row]


def beijer_korenix_device_type(model: str, context: str) -> str:
    key = normalize_header(f"{model} {context}")
    if "jetnet" in key or "switch" in key:
        return "Industrial Ethernet Switch"
    if "jetcon" in key or "converter" in key:
        return "Industrial Media Converter"
    if "jetbox" in key:
        return "Industrial Network Computer"
    if "jetwave" in key:
        return "Industrial Wireless Device"
    return "Industrial Network Device"


BEIJER_KORENIX_PART_RE = re.compile(r"\bF[0-9A-Z]{10,}(?:-[0-9A-Z]+)?\b")
BEIJER_KORENIX_DATE_RE = re.compile(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b")
BEIJER_KORENIX_MODEL_RE = re.compile(
    r"\b(?:JetNet|JetLink|JetBox|JetCon|JetWave)\s*[A-Za-z0-9][A-Za-z0-9/(),. _+-]*",
    flags=re.I,
)


def beijer_korenix_normalize_model(value: str) -> str:
    text = normalize_text(value)
    text = re.sub(r"\bF[0-9A-Z]{10,}(?:-[0-9A-Z]+)?\b", " ", text)
    text = BEIJER_KORENIX_DATE_RE.sub(" ", text)
    text = re.sub(r"\b(?:N/A|NA|n/a|na)\b", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" -;,")
    match = BEIJER_KORENIX_MODEL_RE.search(text)
    if not match:
        return ""
    model = normalize_text(match.group(0)).strip(" -;,")
    model = re.sub(r"-\s+", "-", model)
    model = re.sub(r"\s+-", "-", model)
    model = re.sub(r"\s+", " ", model)
    return model


def beijer_korenix_join_model_segments(segments: list[str]) -> str:
    result = ""
    for segment in segments:
        segment = normalize_text(segment).strip(" ;,")
        if not segment:
            continue
        if result and result.endswith("-"):
            result += segment
        elif result:
            result += f" {segment}"
        else:
            result = segment
    return beijer_korenix_normalize_model(result)


def beijer_korenix_left_column_bracket_model(
    raw_lines: list[str],
    row_index: int,
    date_start: int,
) -> str:
    for index in range(row_index, max(-1, row_index - 8), -1):
        line = raw_lines[index]
        prefix = line[:date_start]
        for match in reversed(list(re.finditer(r"\[([^\]]+)\]", prefix))):
            model = beijer_korenix_normalize_model(match.group(1))
            if model:
                return model
        open_pos = prefix.rfind("[")
        if open_pos >= 0 and "]" not in prefix[open_pos:]:
            parts = [prefix[open_pos + 1 :]]
            for next_index in range(index + 1, min(row_index + 1, len(raw_lines))):
                next_prefix = raw_lines[next_index][:date_start]
                parts.append(next_prefix)
                if "]" in next_prefix:
                    break
            model = beijer_korenix_normalize_model(" ".join(parts).split("]", 1)[0])
            if model:
                return model
    return ""


def beijer_korenix_table_model(
    raw_lines: list[str],
    row_index: int,
    part_end: int,
    date_start: int,
) -> str:
    same_line = raw_lines[row_index][part_end:date_start]
    model = beijer_korenix_normalize_model(same_line)
    if model:
        return model

    segments: list[str] = []
    for index in (row_index - 2, row_index - 1):
        if 0 <= index < len(raw_lines):
            segment = raw_lines[index][:date_start]
            if beijer_korenix_normalize_model(segment):
                segments.append(segment)
    if beijer_korenix_normalize_model(same_line):
        segments.append(same_line)
    for index in (row_index + 1, row_index + 2):
        if 0 <= index < len(raw_lines):
            segment = raw_lines[index][:date_start]
            normalized = normalize_header(segment)
            if (
                not segment.strip()
                or "notification dot" in normalized
                or "part number" in normalized
                or "model name" in normalized
                or "end of life" in normalized
                or "replacement" in normalized
            ):
                break
            if segments and beijer_korenix_normalize_model(segment):
                break
            if segments or beijer_korenix_normalize_model(segment):
                segments.append(segment)
                if beijer_korenix_join_model_segments(segments) and not normalize_text(
                    segment
                ).endswith("-"):
                    break
    return beijer_korenix_join_model_segments(segments)


def parse_beijer_korenix_pdf_rows_from_text(
    text: str,
    source_name: str,
) -> list[dict[str, Any]]:
    source_key = source_name.lower()
    if not source_key.startswith("eol_korenix_life_cycle_notification-"):
        return []
    normalized = normalize_text(text)
    normalized_key = normalize_header(normalized)
    if (
        "life cycle notification" not in normalized_key
        or "part number" not in normalized_key
        or "end of life" not in normalized_key
    ):
        return []
    if (
        "end of life for" not in normalized_key
        and "issuing eol" not in normalized_key
    ):
        return []

    raw_lines = text.splitlines()
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw_line in enumerate(raw_lines):
        part_matches = list(BEIJER_KORENIX_PART_RE.finditer(raw_line))
        if not part_matches:
            continue
        date_match = BEIJER_KORENIX_DATE_RE.search(raw_line)
        if not date_match:
            continue
        date_start = date_match.start()
        old_part_match = next(
            (match for match in part_matches if match.start() < date_start),
            None,
        )
        if not old_part_match:
            continue
        part_number = old_part_match.group(0)
        eol_date = parse_date_any(date_match.group(0))
        if not eol_date:
            continue

        model = beijer_korenix_left_column_bracket_model(
            raw_lines,
            index,
            date_start,
        )
        if not model:
            model = beijer_korenix_table_model(
                raw_lines,
                index,
                old_part_match.end(),
                date_start,
            )
        if not model:
            continue

        key = (model, part_number, eol_date)
        if key in seen:
            continue
        seen.add(key)
        context = " ".join(
            normalize_text(line)
            for line in raw_lines[max(0, index - 4) : index + 5]
            if normalize_text(line)
        )
        device_type = beijer_korenix_device_type(model, context)
        rows.append(
            {
                "Model": model,
                "Part Number": part_number,
                "Product Name": f"Beijer Korenix {model}",
                "Description": device_type,
                "Product Status": (
                    f"End of life date {eol_date}; source announces product "
                    "discontinuation or no longer available for sales"
                ),
                "End of Sale": eol_date,
                "Lifecycle Status Source": source_name,
                "_source_table": f"{source_name} Life Cycle Notification",
                "_source_hint": "Beijer Korenix life-cycle notification PDF import",
                "_review_policy": "beijer_korenix_eol_date_not_support_end",
                "_review_reason": (
                    "The Beijer/Korenix notification publishes an End of Life "
                    "date for product discontinuation or sales availability, "
                    "but does not publish an exact support, service, "
                    "vulnerability, firmware, or security-update end date."
                ),
                "_aliases": [
                    model,
                    part_number,
                    f"Beijer {model}",
                    f"Korenix {model}",
                ],
                "_force_lifecycle_review": True,
                "_suppress_description_aliases": True,
                "_prefer_model": True,
            }
        )
    return rows


NETCONTROL_DATE_RE = re.compile(r"\b\d{1,2}\s+[A-Za-z]+,?\s+\d{4}\b")


def parse_netcontrol_date(value: str) -> str | None:
    text = normalize_text(value)
    text = re.sub(r"\b([A-Za-z]+),\s+(\d{4})\b", r"\1 \2", text)
    return parse_date_any(text)


def netcontrol_first_date(value: str) -> str | None:
    match = NETCONTROL_DATE_RE.search(normalize_text(value))
    return parse_netcontrol_date(match.group(0)) if match else None


def netcontrol_title_models(lines: list[str]) -> list[str]:
    titles: list[str] = []
    for line in lines[:12]:
        text = normalize_text(line)
        if "document" in text.lower() or "please see" in text.lower():
            continue
        match = re.search(r"(.+?)\s+End-of-Life\s+Announcement\b", text, flags=re.I)
        if not match:
            continue
        title = normalize_text(match.group(1))
        title = re.sub(r"\s+\d+\s*\(\d+\)$", "", title)
        if title:
            titles.append(title)
    if titles:
        title = sorted(titles, key=len, reverse=True)[0].replace(" and ", ", ")
        parts = [normalize_text(part) for part in title.split(",") if normalize_text(part)]
        return list(dict.fromkeys(parts))
    return []


def parse_netcontrol_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if not source_name.lower().startswith("netcontrol_") or not source_name.lower().endswith(".pdf"):
        return []
    normalized = normalize_header(text)
    if "end of life announcement" not in normalized or "end of life milestones" not in normalized:
        return []

    lines = text.splitlines()
    models = netcontrol_title_models(lines)
    if not models:
        return []

    announcement = None
    end_of_sale = None
    end_of_support = None
    for raw_line in lines:
        line = normalize_text(raw_line)
        header = normalize_header(line)
        if "end of life eol" in header and not announcement:
            announcement = netcontrol_first_date(line)
        if "last time buy ltb" in header and "n a" not in header and not end_of_sale:
            end_of_sale = netcontrol_first_date(line)
        if (
            ("end of support" in header or "end of spare parts" in header)
            and not end_of_support
        ):
            end_of_support = netcontrol_first_date(line)

    if not announcement and not end_of_support:
        return []

    rows: list[dict[str, Any]] = []
    for model in models:
        row: dict[str, Any] = {
            "Model": model,
            "Part Number": model,
            "Product Name": f"Netcontrol {model}",
            "Description": "Industrial remote terminal unit",
            "Product Status": (
                "Netcontrol formal End-of-Life announcement; "
                f"announcement date {announcement or 'not stated'}; "
                f"last time buy date {end_of_sale or 'not available'}; "
                f"support/service end date {end_of_support or 'not stated'}"
            ),
            "Lifecycle Status Source": source_name,
            "_source_table": f"{source_name} End of Life Milestones",
            "_source_hint": "Netcontrol End-of-Life announcement PDF import",
            "_review_policy": "netcontrol_end_of_support_and_service_milestone",
            "_aliases": [model, f"Netcontrol {model}"],
            "_prefer_model": True,
        }
        if announcement:
            row["Announcement Date"] = announcement
        if end_of_sale:
            row["End of Sale"] = end_of_sale
        if end_of_support:
            row["End of Support"] = end_of_support
        rows.append(row)
    return rows


def parse_spectralink_pdf_rows_from_text(text: str, source_name: str) -> list[dict[str, Any]]:
    if source_name != "cs_22_02_kirk_ip_base_eol_eos_bulletin.pdf":
        return []
    normalized = normalize_text(text)
    required = (
        "Compatibility ends for KIRK IP Base",
        "KIRK IP Base Station",
        "SKU# 02337300, 02337301",
        "went EOL (End of Life) on October 1, 2013",
        "EOS (End of Service) on October 31, 2016",
        "old base will no longer be supported",
    )
    if not all(item in normalized for item in required):
        return []

    eol = parse_date_any("October 1, 2013")
    eos = parse_date_any("October 31, 2016")
    if not eol or not eos:
        return []

    rows: list[dict[str, Any]] = []
    for sku in ("02337300", "02337301"):
        rows.append(
            {
                "Model": "KIRK IP Base Station",
                "Part Number": sku,
                "Product Name": "Spectralink KIRK IP Base Station",
                "Description": "IP-DECT base station",
                "Device Type": "IP-DECT Base Station",
                "Product Status": (
                    "KIRK IP Base Station went EOL on 2013-10-01 and EOS "
                    "on 2016-10-31; old base no longer supported beginning "
                    "with PCS22Aa"
                ),
                "End of Life": eol,
                "End of Service": eos,
                "Lifecycle Status Source": source_name,
                "_source_table": f"{source_name} Systems Affected and Description",
                "_source_hint": "Spectralink KIRK IP Base EOL/EOS bulletin import",
                "_review_policy": "spectralink_kirk_ip_base_eos_is_end_of_service",
                "_review_reason": (
                    "Spectralink states the old KIRK IP Base Station SKUs went "
                    "EOL on 2013-10-01, EOS (End of Service) on 2016-10-31, "
                    "and are no longer supported beginning with PCS22Aa."
                ),
                "_aliases": [
                    "KIRK IP Base",
                    "KIRK IP-Base Station",
                    "KIRK IP Base Station",
                    sku,
                    f"SKU {sku}",
                    f"SKU# {sku}",
                ],
                "_suppress_description_aliases": True,
                "_prefer_model": True,
            }
        )
    return rows


def extract_vendor_pdf_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug not in {
        "advantech_industrial_networking",
        "adtran",
        "alcatel_lucent_enterprise",
        "audiocodes",
        "aruba_hpe",
        "atx_networks",
        "avigilon",
        "avaya_nortel_networking",
        "beijer_korenix",
        "bosch_security",
        "broadcom_brocade",
        "calix",
        "celona",
        "ctsystem",
        "ctc_union",
        "eaton",
        "eltako",
        "genexis",
        "garland_technology",
        "geovision",
        "hikvision",
        "helmholz",
        "hirschmann_belden",
        "idirectgov",
        "ligowave",
        "mimosa",
        "mobotix",
        "netcontrol",
        "nvidia_mellanox_cumulus",
        "pilz",
        "ribbon_communications",
        "schneider_apc",
        "sierra_wireless_airlink",
        "silicom",
        "silver_peak_aruba_edgeconnect",
        "spectralink",
        "telrad_networks",
        "vertiv",
        "weidmueller",
        "westermo",
        "winmate",
        "zpe_systems",
    }:
        return []
    if vendor_slug == "sierra_wireless_airlink":
        text = extract_pdf_text(path)
        raw_text = extract_pdf_text(path, raw=True)
        if not text:
            return []
        return parse_sierra_airlink_pdf_rows_from_text(
            text,
            path.name,
            raw_text=raw_text,
        )
    text = extract_pdf_text(path, raw=vendor_slug == "avaya_nortel_networking")
    if not text:
        return []
    if vendor_slug == "advantech_industrial_networking":
        return parse_advantech_ntron_pdf_rows_from_text(text, path.name)
    if vendor_slug == "adtran":
        return parse_adtran_bluesocket_pdf_rows_from_text(text, path.name)
    if vendor_slug == "alcatel_lucent_enterprise":
        return parse_alcatel_lucent_pdf_rows_from_text(text, path.name)
    if vendor_slug == "audiocodes":
        return parse_audiocodes_pdf_rows_from_text(text, path.name)
    if vendor_slug == "aruba_hpe" and path.name == "aruba-hardware-end-of-sale-list.pdf":
        return parse_aruba_pdf_rows_from_text(text, path.name)
    if vendor_slug == "atx_networks":
        return parse_atx_digistream_pdf_rows_from_text(text, path.name)
    if vendor_slug == "avigilon":
        return parse_avigilon_pdf_rows_from_text(text, path.name)
    if vendor_slug == "avaya_nortel_networking":
        return parse_avaya_pdf_rows_from_text(text, path.name)
    if vendor_slug == "beijer_korenix":
        return parse_beijer_korenix_pdf_rows_from_text(text, path.name)
    if vendor_slug == "bosch_security":
        return parse_bosch_ip_video_firmware_pdf_rows_from_text(text, path.name)
    if vendor_slug == "broadcom_brocade":
        return parse_broadcom_brocade_pdf_rows_from_text(text, path.name)
    if vendor_slug == "calix":
        return parse_calix_pdf_rows_from_text(text, path.name)
    if vendor_slug == "celona":
        return parse_celona_pdf_rows_from_text(text, path.name)
    if vendor_slug == "ctsystem":
        return parse_ctsystem_eol_products_pdf_rows_from_text(text, path.name)
    if vendor_slug == "ctc_union":
        return parse_ctc_union_pdf_rows_from_text(text, path.name)
    if vendor_slug == "eaton":
        return parse_eaton_pdf_rows_from_text(text, path.name)
    if vendor_slug == "eltako":
        return parse_eltako_safe_iv_pdf_rows_from_text(text, path.name)
    if vendor_slug == "genexis":
        return parse_genexis_psti_pdf_rows_from_text(text, path.name)
    if vendor_slug == "garland_technology":
        return parse_garland_pdf_rows_from_text(text, path.name)
    if vendor_slug == "geovision":
        return parse_geovision_pdf_rows_from_text(text, path.name)
    if vendor_slug == "hikvision":
        return parse_hikvision_discontinuation_pdf_rows_from_text(text, path.name)
    if vendor_slug == "helmholz":
        return parse_helmholz_myrex24_pdf_rows_from_text(text, path.name)
    if vendor_slug == "hirschmann_belden":
        return parse_hirschmann_belden_pdn_rows_from_text(text, path.name)
    if vendor_slug == "idirectgov":
        return parse_idirectgov_pdf_rows_from_text(text, path.name)
    if vendor_slug == "ligowave":
        return parse_ligowave_pdf_rows_from_text(text, path.name)
    if vendor_slug == "mimosa":
        return parse_mimosa_eol_pdf_rows_from_text(text, path.name)
    if vendor_slug == "mobotix":
        return parse_mobotix_product_news_pdf_rows_from_text(text, path.name)
    if vendor_slug == "netcontrol":
        return parse_netcontrol_pdf_rows_from_text(text, path.name)
    if vendor_slug == "nvidia_mellanox_cumulus":
        return parse_nvidia_mellanox_pdf_rows_from_text(text, path.name)
    if vendor_slug == "pilz":
        return parse_pilz_pnozmulti_pdf_rows_from_text(text, path.name)
    if vendor_slug == "ribbon_communications":
        return parse_ribbon_pdf_rows_from_text(text, path.name)
    if vendor_slug == "schneider_apc":
        return parse_schneider_apc_connexium_pdf_rows_from_text(text, path.name)
    if vendor_slug == "silicom":
        return parse_silicom_pdf_rows_from_text(text, path.name)
    if vendor_slug == "silver_peak_aruba_edgeconnect":
        return parse_silver_peak_edgeconnect_pdf_rows_from_text(text, path.name)
    if vendor_slug == "spectralink":
        return parse_spectralink_pdf_rows_from_text(text, path.name)
    if vendor_slug == "telrad_networks":
        return parse_telrad_cpe8100_pdf_rows_from_text(text, path.name)
    if vendor_slug == "vertiv":
        return parse_vertiv_pdf_rows_from_text(text, path.name)
    if vendor_slug == "weidmueller":
        return parse_weidmueller_datasheet_pdf_rows_from_text(text, path.name)
    if vendor_slug == "westermo":
        return parse_westermo_pdf_rows_from_text(text, path.name)
    if vendor_slug == "winmate":
        return parse_winmate_pcn_pdf_rows_from_text(text, path.name)
    if vendor_slug == "zpe_systems":
        return parse_zpe_systems_pdf_rows_from_text(text, path.name)
    return []


def extract_csv_rows(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample) if sample.strip() else csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        rows = []
        for row in reader:
            item = {normalize_text(k): normalize_text(v) for k, v in row.items() if k}
            item["_source_table"] = path.name
            rows.append(item)
        return rows


def extract_sonicwall_sonicos_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "sonicwall_sonicos_release_eos_status.csv":
        return []
    extracted: list[dict[str, Any]] = []
    for row in extract_csv_rows(path):
        release = normalize_text(row.get("Release"))
        eos_date = parse_date_any(row.get("EOS Date"))
        if not release or not eos_date:
            continue
        target_models = normalize_text(row.get("Model"))
        status = normalize_text(row.get("Status")) or "End of Support"
        recommended = normalize_text(row.get("Recommended Upgrade"))
        extracted.append(
            {
                "Model": release,
                "Product Name": release,
                "Description": (
                    f"SonicOS release for {target_models}"
                    if target_models
                    else "SonicOS release"
                ),
                "Product Status": status,
                "End of Support": eos_date,
                "Replacement Products": recommended,
                "_source_table": path.name,
                "_source_hint": "SonicWall SonicOS release EOS status CSV import",
            }
        )
    return extracted


def sonicwall_family_from_filename(path: Path) -> tuple[str, str, str]:
    name = path.name
    if "email_security" in name:
        return "Email Security", "Email Security", "Email Security"
    if "firewall_lifecycle" in name:
        return "TZ Firewall", "Firewall", "TZ"
    if "nsa_series" in name:
        return "NSa Series Firewall", "Firewall", "NSa"
    if "nssp_series" in name:
        return "NSsp Series Firewall", "Firewall", ""
    if "nsv_series" in name:
        return "NSv Series Firewall", "Virtual Firewall", "NSv"
    if "sma_1000_series" in name:
        return "SMA 1000 Series", "Secure Mobile Access Appliance", ""
    if "sma_100_series" in name:
        return "SMA 100 Series", "Secure Mobile Access Appliance", ""
    if "sonicwave_series" in name:
        return "SonicWave Series", "Wireless Access Point", "SonicWave"
    if "supermassive_series" in name:
        return "SuperMassive Series Firewall", "Firewall", ""
    if "wireless_access_points" in name:
        return "Wireless Access Point", "Wireless Access Point", "SonicWall Wireless"
    if "wxa_series" in name:
        return "WXA Series", "WAN Acceleration Appliance", ""
    return "SonicWall Product", "Network Device", ""


def sonicwall_display_model(raw_model: str, prefix: str) -> str:
    model = normalize_text(raw_model)
    if not model or not prefix:
        return model
    if normalize_header(model).startswith(normalize_header(prefix)):
        return model
    if prefix == "TZ":
        if re.match(r"^\d", model):
            return f"TZ{model}"
        return model
    return f"{prefix} {model}"


def extract_sonicwall_lifecycle_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("sonicwall_") or not path.name.endswith("_lifecycle_dates.csv"):
        return []
    family, device_type, prefix = sonicwall_family_from_filename(path)
    extracted: list[dict[str, Any]] = []
    for row in extract_csv_rows(path):
        raw_model = normalize_text(row.get("Model"))
        if not raw_model:
            continue
        model = sonicwall_display_model(raw_model, prefix)
        lifecycle_row: dict[str, Any] = {
            "Model": model,
            "Part Number": raw_model,
            "Product Name": model,
            "Description": family,
            "Device Type": device_type,
            "Product Status": "lifecycle schedule",
            "_source_table": path.name,
            "_source_hint": "SonicWall lifecycle dates CSV import",
            "_prefer_model": True,
        }
        for source_key, target_key in (
            ("Last Order Day", "Last Order Day"),
            ("End Of Support", "End of Support"),
        ):
            value = normalize_text(row.get(source_key))
            if value:
                lifecycle_row[target_key] = value
        if lifecycle_row.get("Last Order Day") or lifecycle_row.get("End of Support"):
            extracted.append(lifecycle_row)
    return extracted


def extract_vendor_csv_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug == "sonicwall":
        return extract_sonicwall_sonicos_rows(path) or extract_sonicwall_lifecycle_csv_rows(path)
    return []


def column_index(cell_ref: str) -> int:
    letters = re.sub(r"[^A-Z]", "", cell_ref.upper())
    value = 0
    for char in letters:
        value = value * 26 + (ord(char) - ord("A") + 1)
    return max(value - 1, 0)


def xlsx_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    try:
        xml = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ET.fromstring(xml)
    ns = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    strings = []
    for si in root.findall("a:si", ns):
        parts = [node.text or "" for node in si.findall(".//a:t", ns)]
        strings.append("".join(parts))
    return strings


def xlsx_sheet_names(zf: zipfile.ZipFile) -> list[tuple[str, str]]:
    ns = {
        "a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    }
    workbook = ET.fromstring(zf.read("xl/workbook.xml"))
    rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    rel_map = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels
        if rel.attrib.get("Id") and rel.attrib.get("Target")
    }
    sheets = []
    for sheet in workbook.findall("a:sheets/a:sheet", ns):
        rid = sheet.attrib.get(f"{{{ns['r']}}}id")
        target = rel_map.get(rid or "")
        if not target:
            continue
        if not target.startswith("xl/"):
            target = f"xl/{target}"
        sheets.append((sheet.attrib.get("name") or target, target))
    return sheets


def extract_xlsx_rows(path: Path) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as zf:
        shared = xlsx_shared_strings(zf)
        for sheet_name, target in xlsx_sheet_names(zf):
            try:
                root = ET.fromstring(zf.read(target))
            except KeyError:
                continue
            ns = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            rows = []
            for row in root.findall(".//a:sheetData/a:row", ns):
                values: dict[int, str] = {}
                for cell in row.findall("a:c", ns):
                    idx = column_index(cell.attrib.get("r", "A1"))
                    cell_type = cell.attrib.get("t")
                    value = ""
                    if cell_type == "inlineStr":
                        value = "".join(node.text or "" for node in cell.findall(".//a:t", ns))
                    else:
                        node = cell.find("a:v", ns)
                        if node is not None and node.text is not None:
                            value = node.text
                            if cell_type == "s":
                                try:
                                    value = shared[int(value)]
                                except (ValueError, IndexError):
                                    pass
                    values[idx] = normalize_text(value)
                if values:
                    max_col = max(values)
                    rows.append([values.get(i, "") for i in range(max_col + 1)])
            for item in rows_to_dicts(rows, f"{path.name} {sheet_name}"):
                item["_source_table"] = f"{path.name} {sheet_name}"
                extracted.append(item)
    return extracted


def path_looks_like_pdf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(5) == b"%PDF-"
    except OSError:
        return False


def extract_rows(path: Path, vendor_slug: str = "") -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix != ".pdf" and path_looks_like_pdf(path):
        return extract_vendor_pdf_rows(path, vendor_slug)
    if suffix == ".csv":
        vendor_rows = extract_vendor_csv_rows(path, vendor_slug)
        if vendor_rows:
            return vendor_rows
        return extract_csv_rows(path)
    if suffix in {".html", ".htm"}:
        vendor_rows = extract_vendor_html_rows(path, vendor_slug)
        if vendor_slug in HTML_GENERIC_TABLE_BLOCKLIST:
            return vendor_rows
        return vendor_rows + extract_html_tables(path)
    if suffix == ".json":
        return extract_vendor_json_rows(path, vendor_slug)
    if suffix == ".txt":
        return extract_vendor_text_rows(path, vendor_slug)
    if suffix == ".xlsx":
        return extract_xlsx_rows(path)
    if suffix == ".pdf":
        return extract_vendor_pdf_rows(path, vendor_slug)
    return []


def find_value(row: dict[str, Any], patterns: list[str]) -> tuple[str, str]:
    normalized_patterns = [normalize_header(pattern) for pattern in patterns]
    for key, value in row.items():
        if str(key).startswith("_"):
            continue
        header = normalize_header(key)
        if "status" in header and not any(
            "status" in pattern or "lifecycle phase" in pattern
            for pattern in normalized_patterns
        ):
            continue
        if any(
            word in header
            for word in ("replacement", "replaced by", "successor", "alternative", "migration")
        ) and not any(
            word in pattern
            for pattern in normalized_patterns
            for word in ("replacement", "replaced by", "successor", "alternative", "migration")
        ):
            continue
        if any(pattern in header for pattern in normalized_patterns):
            text = normalize_text(value)
            if text:
                return text, header
    return "", ""


def header_matches(header: str, aliases: list[str]) -> bool:
    compact_header = header.replace(" ", "")
    for alias in aliases:
        normalized = normalize_header(alias)
        compact_alias = normalized.replace(" ", "")
        if not normalized:
            continue
        # Short lifecycle abbreviations like EOS must match exactly once
        # compacted, otherwise EOS would also match EOSL/EOSM.
        if len(compact_alias) <= 3:
            if compact_header == compact_alias:
                return True
            continue
        if normalized in header:
            return True
        if compact_alias and compact_alias in compact_header:
            return True
    return False


def find_model_value(row: dict[str, Any], patterns: list[str]) -> tuple[str, str]:
    excluded = (
        "status",
        "date",
        "support",
        "sale",
        "life",
        "replacement",
        "alternative",
        "migration",
        "successor",
        "policy",
        "family",
    )
    for key, value in row.items():
        if str(key).startswith("_"):
            continue
        header = normalize_header(key)
        identifier_header = any(
            word in header
            for word in (
                "part number",
                "part no",
                "p n",
                "sku",
                "pid",
                "product number",
                "model number",
                "model no",
                "order code",
            )
        )
        if any(word in header for word in excluded) and not identifier_header:
            continue
        if any(pattern in header for pattern in patterns):
            text = normalize_text(value)
            if text:
                return text, header
    return "", ""


def split_alias_values(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        aliases: list[str] = []
        for item in value:
            aliases.extend(split_alias_values(item))
        return aliases

    text = normalize_text(value)
    if not text:
        return []

    aliases = [text]
    aliases.extend(
        normalize_text(part)
        for part in re.split(
            r"\s*(?:,|;|\||\s+/\s+|\s+\baka\b\s+|\s+\balso known as\b\s+)\s*",
            text,
            flags=re.I,
        )
        if normalize_text(part)
    )
    result: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        key = normalize_alias_dedupe_key(alias)
        if key and key not in seen and len(alias) <= 200:
            result.append(alias)
            seen.add(key)
    return result


def row_alias_values(row: dict[str, Any]) -> list[str]:
    aliases = split_alias_values(row.get("_aliases"))
    for key, value in row.items():
        if str(key).startswith("_"):
            continue
        header = normalize_header(key)
        if header_matches(header, CANONICAL_FIELD_ALIASES["aliases"]):
            aliases.extend(split_alias_values(value))
    result: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        key = normalize_alias_dedupe_key(alias)
        if key and key not in seen:
            result.append(alias)
            seen.add(key)
    return result


def normalize_alias_key(builder: Any, value: str) -> str:
    normalizer = getattr(builder, "normalize_lookup_key", None)
    if callable(normalizer):
        return normalizer(value)
    return normalize_header(value)


def normalize_alias_keys(builder: Any, value: str) -> list[str]:
    keys: list[str] = []
    for key in (scanner_normalize_key(value), normalize_alias_key(builder, value)):
        if key and key not in keys:
            keys.append(key)
    return keys


def add_record_aliases(builder: Any, record: dict[str, Any], aliases: list[str]) -> None:
    match = record.setdefault("match", {})
    existing_aliases = list(match.get("aliases") or [])
    seen_keys = {str(key) for key in (match.get("alias_keys") or []) if key}
    for alias in existing_aliases:
        seen_keys.update(normalize_alias_keys(builder, alias))
    vendor = normalize_text(record.get("vendor"))
    vendor_keys = normalize_alias_keys(builder, vendor) if vendor else []

    for alias in aliases:
        alias = normalize_text(alias)
        alias_keys = normalize_alias_keys(builder, alias)
        if not alias or not alias_keys or all(key in seen_keys for key in alias_keys):
            continue
        existing_aliases.append(alias)
        seen_keys.update(alias_keys)
        if vendor and vendor_keys and not any(
            key.startswith(vendor_key)
            for key in alias_keys
            for vendor_key in vendor_keys
        ):
            vendor_alias = f"{vendor} {alias}"
            vendor_alias_keys = normalize_alias_keys(builder, vendor_alias)
            if vendor_alias_keys and any(key not in seen_keys for key in vendor_alias_keys):
                existing_aliases.append(vendor_alias)
                seen_keys.update(vendor_alias_keys)

    match["aliases"] = sorted(existing_aliases)
    match["alias_keys"] = sorted(seen_keys)


def remove_record_aliases(builder: Any, record: dict[str, Any], aliases: list[str]) -> None:
    match = record.setdefault("match", {})
    remove_keys: set[str] = set()
    for alias in aliases:
        alias = normalize_text(alias)
        if alias:
            remove_keys.update(normalize_alias_keys(builder, alias))
    if not remove_keys:
        return

    kept_aliases: list[str] = []
    seen_keys: set[str] = set()
    for alias in match.get("aliases") or []:
        alias_keys = set(normalize_alias_keys(builder, alias))
        if alias_keys and alias_keys <= remove_keys:
            continue
        kept_aliases.append(alias)
        seen_keys.update(alias_keys)
    match["aliases"] = sorted(kept_aliases)
    match["alias_keys"] = sorted(seen_keys)


def lifecycle_dates(row: dict[str, Any], *, dayfirst: bool = False) -> dict[str, str | None]:
    result = {
        "announcement": None,
        "last_sale": None,
        "end_of_sale": None,
        "end_of_life": None,
        "end_of_support": None,
        "end_of_service": None,
        "end_of_vulnerability": None,
    }
    for key, value in row.items():
        header = normalize_header(key)
        parsed = parse_date_any(value, dayfirst=dayfirst)
        if not parsed:
            continue
        for canonical_name, aliases in CANONICAL_DATE_ALIASES.items():
            if canonical_name in {"end_of_life", "end_of_sale"} and any(
                word in header for word in ("announcement", "announce", "eola", "eosa")
            ):
                continue
            if header_matches(header, aliases):
                result[canonical_name] = result[canonical_name] or parsed
    return result


def choose_model(row: dict[str, Any]) -> tuple[str, str, str]:
    if row.get("_prefer_model"):
        model, model_header = find_model_value(
            row,
            CANONICAL_FIELD_ALIASES["model"],
        )
        part, part_header = find_model_value(
            row,
            CANONICAL_FIELD_ALIASES["part_number"],
        )
        selected = model or part
        header = model_header or part_header
        return selected, part or selected, header

    part, part_header = find_model_value(
        row,
        CANONICAL_FIELD_ALIASES["part_number"],
    )
    model, model_header = find_model_value(
        row,
        CANONICAL_FIELD_ALIASES["model"],
    )
    selected = part or model
    header = part_header or model_header
    return selected, part or selected, header


def apply_lifecycle_review_override(
    builder: Any,
    record: dict[str, Any],
    row: dict[str, Any],
) -> None:
    policy = normalize_text(row.get("_review_policy")) or "raw_status_not_security_eol"
    reason = normalize_text(row.get("_review_reason")) or (
        "Source identifies this model as vendor-declared EOL, discontinued, "
        "or replacement-listed, but it does not prove that firmware/security "
        "updates have stopped."
    )
    lifecycle = record.setdefault("lifecycle", {})
    dates = record.setdefault("dates", {})
    # Conservative review rows may carry a vendor EOL/status date, but that is
    # not proof that security updates ended.
    dates["end_of_security_updates"] = None
    record.setdefault("quality", {})["interpretation_policy"] = policy
    record["quality"]["previous_lifecycle"] = {
        "status": lifecycle.get("status"),
        "risk": lifecycle.get("risk"),
        "receives_security_updates": lifecycle.get("receives_security_updates"),
        "reason": lifecycle.get("reason"),
    }
    record["quality"]["review_required"] = True
    lifecycle["status"] = "lifecycle_review"
    lifecycle["risk"] = "low"
    lifecycle["receives_security_updates"] = None
    lifecycle["replacement_recommended"] = False
    lifecycle["confidence"] = "low"
    lifecycle["reason"] = reason
    lifecycle["days_to_security_eol"] = None

    record.setdefault("sunsetscan", {})["finding_title"] = (
        f"{record.get('vendor') or record.get('vendor_slug') or ''} "
        f"{record.get('model') or record.get('model_key') or ''} "
        "vendor-declared EOL; lifecycle review needed"
    ).strip()
    if hasattr(builder, "match_priority"):
        record["sunsetscan"]["match_priority"] = builder.match_priority(
            record.get("device_class") or "network_device",
            "lifecycle_review",
        )


def apply_security_updates_ended_without_exact_date_override(
    builder: Any,
    record: dict[str, Any],
    row: dict[str, Any],
) -> None:
    policy = normalize_text(row.get("_review_policy")) or (
        "security_updates_ended_without_exact_date"
    )
    reason = normalize_text(row.get("_review_reason")) or (
        "Source says this product no longer receives software, firmware, "
        "or security updates, but does not publish an exact end date."
    )
    lifecycle = record.setdefault("lifecycle", {})
    record.setdefault("quality", {})["interpretation_policy"] = policy
    record["quality"]["previous_lifecycle"] = {
        "status": lifecycle.get("status"),
        "risk": lifecycle.get("risk"),
        "receives_security_updates": lifecycle.get("receives_security_updates"),
        "reason": lifecycle.get("reason"),
    }
    record["quality"]["review_required"] = True
    lifecycle["status"] = "unsupported"
    lifecycle["risk"] = "critical"
    lifecycle["receives_security_updates"] = False
    lifecycle["replacement_recommended"] = True
    lifecycle["confidence"] = "medium"
    lifecycle["reason"] = reason
    lifecycle["days_to_security_eol"] = None

    record.setdefault("sunsetscan", {})["finding_title"] = (
        f"{record.get('vendor') or record.get('vendor_slug') or ''} "
        f"{record.get('model') or record.get('model_key') or ''} "
        "no longer receives security updates"
    ).strip()
    if hasattr(builder, "match_priority"):
        record["sunsetscan"]["match_priority"] = builder.match_priority(
            record.get("device_class") or "network_device",
            "unsupported",
        )


def apply_end_of_security_updates_override(
    *,
    builder: Any,
    record: dict[str, Any],
    row: dict[str, Any],
    vendor_slug: str,
    raw_status: str,
    source_hint: str,
    as_of: date,
) -> None:
    override_date = parse_date_any(row.get("_end_of_security_updates_override"))
    if not override_date:
        return
    dates = record.setdefault("dates", {})
    previous_lifecycle = dict(record.get("lifecycle") or {})
    dates["end_of_security_updates"] = override_date

    classifier = getattr(builder, "classify_lifecycle", None)
    if callable(classifier):
        record["lifecycle"] = classifier(
            vendor_slug=vendor_slug,
            dates=dates,
            raw_status=raw_status,
            source_hint=source_hint,
            as_of=as_of,
        )

    lifecycle = record.get("lifecycle") or {}
    sunsetscan = record.setdefault("sunsetscan", {})
    if hasattr(builder, "match_priority"):
        sunsetscan["match_priority"] = builder.match_priority(
            record.get("device_class") or "network_device",
            lifecycle.get("status") or "unknown",
        )
    title_builder = getattr(builder, "build_finding_title", None)
    if callable(title_builder):
        sunsetscan["finding_title"] = title_builder(
            record.get("vendor") or vendor_slug,
            record.get("model") or record.get("model_key") or "",
            lifecycle,
        )
    elif lifecycle.get("receives_security_updates") is False:
        sunsetscan["finding_title"] = (
            f"{record.get('vendor') or vendor_slug} "
            f"{record.get('model') or record.get('model_key') or ''} "
            "no longer receives security updates"
        ).strip()

    quality = record.setdefault("quality", {})
    quality["interpretation_policy"] = (
        normalize_text(row.get("_review_policy"))
        or "explicit_security_update_date_override"
    )
    quality["previous_lifecycle"] = {
        "status": previous_lifecycle.get("status"),
        "risk": previous_lifecycle.get("risk"),
        "receives_security_updates": previous_lifecycle.get(
            "receives_security_updates"
        ),
        "reason": previous_lifecycle.get("reason"),
    }
    quality["review_required"] = True


def normalize_record_output_shape(record: dict[str, Any]) -> dict[str, Any]:
    """Keep imported records on the current SunsetScan artifact schema."""
    if "netwatch" in record and "sunsetscan" not in record:
        record["sunsetscan"] = record.pop("netwatch")
    else:
        record.pop("netwatch", None)
    return record


def builder_compatible_raw_file(
    builder: Any,
    raw_file: Path,
    vendor_slug: str,
) -> tuple[Path, bool]:
    """Return a path old builders can relativize, plus whether it was synthetic."""
    root = getattr(builder, "ROOT", None)
    if not root:
        return raw_file, False
    root_path = Path(root)
    try:
        raw_file.relative_to(root_path)
        return raw_file, False
    except ValueError:
        return root_path / "_external_rawdata" / vendor_slug / raw_file.name, True


def row_to_record(
    *,
    builder: Any,
    vendor_slug: str,
    display_name: str,
    raw_file: Path,
    row: dict[str, Any],
    source_url: str,
    source_hint: str,
    as_of: date,
    dayfirst: bool = False,
) -> dict[str, Any] | None:
    source_hint = normalize_text(row.get("_source_hint")) or source_hint
    model, part_number, model_header = choose_model(row)
    if not model:
        return None

    dates = lifecycle_dates(row, dayfirst=dayfirst)
    raw_status, _ = find_value(row, CANONICAL_FIELD_ALIASES["raw_status"])
    status_only_review = bool(row.get("_status_only_review"))
    status_only_allowed = status_only_review or bool(row.get("_allow_status_only"))
    force_review = bool(row.get("_force_lifecycle_review") or status_only_review)
    has_decision_date = any(
        value
        for key, value in dates.items()
        if key not in {"announcement"}
    )
    if not has_decision_date and not (status_only_allowed and raw_status):
        return None

    product_name, _ = find_value(row, CANONICAL_FIELD_ALIASES["product_name"])
    description, _ = find_value(row, CANONICAL_FIELD_ALIASES["description"])
    replacement, _ = find_value(row, CANONICAL_FIELD_ALIASES["replacement"])
    source_url = normalize_text(row.get("_source_url")) or source_url

    # Avoid policy/definition rows accidentally parsed as lifecycle products.
    rejected_models = {
        "product",
        "service",
        "major version",
        "life cycle milestone",
        "lifecycle milestone",
        "protection for",
        "available",
        "end of sale",
        "end of life",
        "discontinued",
    }
    if normalize_header(model) in rejected_models:
        return None
    if len(model) > 500:
        return None

    builder_raw_file, raw_file_is_external = builder_compatible_raw_file(
        builder,
        raw_file,
        vendor_slug,
    )
    record = builder.make_record(
        vendor_slug=vendor_slug,
        raw_file=builder_raw_file,
        model=model,
        product_name=product_name or f"{display_name} {model}",
        part_number=part_number,
        hardware_version=find_value(row, CANONICAL_FIELD_ALIASES["hardware_version"])[0],
        region=find_value(row, CANONICAL_FIELD_ALIASES["region"])[0],
        device_type=description or product_name or "Network Device",
        description=description or model_header,
        dates=dates,
        raw_status=raw_status,
        replacement=replacement,
        source_url=source_url,
        source_hint=source_hint,
        raw=row,
        as_of=as_of,
    )
    if record:
        normalize_record_output_shape(record)
        if raw_file_is_external:
            record.setdefault("source", {})["raw_file"] = str(raw_file)
        extra_aliases = row_alias_values(row)
        if extra_aliases:
            add_record_aliases(builder, record, extra_aliases)
        if row.get("_suppress_description_aliases") and description:
            remove_record_aliases(
                builder,
                record,
                [description, f"{display_name} {description}"],
            )
        remove_aliases = split_alias_values(row.get("_remove_aliases"))
        if remove_aliases:
            remove_record_aliases(builder, record, remove_aliases)
        if row.get("_end_of_security_updates_override"):
            apply_end_of_security_updates_override(
                builder=builder,
                record=record,
                row=row,
                vendor_slug=vendor_slug,
                raw_status=raw_status,
                source_hint=source_hint,
                as_of=as_of,
            )
            normalize_record_output_shape(record)
        if row.get("_security_updates_ended_without_exact_date"):
            apply_security_updates_ended_without_exact_date_override(
                builder,
                record,
                row,
            )
            normalize_record_output_shape(record)
        elif force_review:
            apply_lifecycle_review_override(builder, record, row)
            normalize_record_output_shape(record)
    return record


def manifest_files(scraper_root: Path, vendor_dir: Path, manifest: dict[str, Any]) -> list[tuple[Path, dict[str, Any]]]:
    result = []
    for entry in manifest.get("files", []):
        if entry.get("status") and int(entry.get("status")) != 200:
            continue
        if entry.get("blocked_hint"):
            continue
        rel = entry.get("local_path")
        if not rel:
            continue
        path = scraper_root / rel
        if not path.exists():
            path = vendor_dir / rel
        if not path.exists() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        result.append((path, entry))
    return result


def local_rawdata_files(vendor_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    raw_dir = vendor_dir / "rawdata"
    if not raw_dir.exists():
        return []
    result = []
    for path in sorted(raw_dir.iterdir()):
        suffix = path.suffix.lower()
        if not path.is_file() or suffix not in SUPPORTED_SUFFIXES:
            continue
        if suffix == ".txt":
            continue
        result.append(
            (
                path,
                {
                    "url": None,
                    "status": 200,
                    "notes": "Local rawdata file present without source_manifest.json",
                    "local_path": str(path),
                },
            )
        )
    return result


def orphan_raw_files(vendor_dir: Path, known_paths: set[Path]) -> list[tuple[Path, dict[str, Any]]]:
    raw_dir = vendor_dir / "raw"
    if not raw_dir.exists():
        return []
    result = []
    for path in sorted(raw_dir.iterdir()):
        suffix = path.suffix.lower()
        if not path.is_file() or suffix not in SUPPORTED_SUFFIXES:
            continue
        if suffix == ".txt" and vendor_dir.name != "peplink":
            continue
        resolved = path.resolve()
        if resolved in known_paths:
            continue
        result.append(
            (
                path,
                {
                    "url": None,
                    "status": 200,
                    "notes": "Local raw file present outside source_manifest.json",
                    "local_path": str(path),
                },
            )
        )
    return result


def source_uses_dayfirst_dates(path: Path, entry: dict[str, Any], vendor_slug: str) -> bool:
    text = " ".join(
        normalize_text(part)
        for part in (
            path.name,
            path.parent.name,
            entry.get("url"),
            entry.get("notes"),
            vendor_slug,
        )
    ).lower()
    return any(token in text for token in (" uk", "uk-", "united kingdom", "europe", " eu "))


def normalize_vendor_slug(value: Any) -> str:
    text = normalize_text(value).lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_")


def split_vendor_slug_values(values: list[str] | None) -> set[str]:
    slugs: set[str] = set()
    for value in values or []:
        for part in re.split(r"[\s,]+", normalize_text(value)):
            slug = normalize_vendor_slug(part)
            if slug:
                slugs.add(slug)
    return slugs


def load_vendor_slug_file(path: Path) -> set[str]:
    slugs: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0]
        slugs.update(split_vendor_slug_values([line]))
    return slugs


def build_vendor_filter(values: list[str] | None, files: list[Path] | None = None) -> set[str]:
    slugs = split_vendor_slug_values(values)
    for path in files or []:
        slugs.update(load_vendor_slug_file(path))
    return slugs


def vendor_skip_reason(
    *,
    vendor_slug: str,
    selected_vendors: set[str],
    skipped_vendors: set[str],
    existing_vendors: set[str],
    include_existing_vendors: bool,
) -> str | None:
    if selected_vendors and vendor_slug not in selected_vendors:
        return "not_selected"
    if vendor_slug in skipped_vendors:
        return "explicitly_skipped"
    if vendor_slug in SKIP_VENDOR_SLUGS and not include_existing_vendors:
        return "default_existing_builder_vendor"
    if vendor_slug in existing_vendors and not include_existing_vendors:
        return "already_in_database"
    return None


def vendor_display_name(vendor_slug: str, manifest: dict[str, Any] | None = None) -> str:
    manifest_name = normalize_text((manifest or {}).get("display_name"))
    if manifest_name:
        return manifest_name
    if vendor_slug in VENDOR_DISPLAY_NAME_OVERRIDES:
        return VENDOR_DISPLAY_NAME_OVERRIDES[vendor_slug]
    return " ".join(part.upper() if len(part) <= 3 else part.title() for part in vendor_slug.split("_"))


def raw_vendor_dirs(raw_root: Path) -> list[Path]:
    if not raw_root.exists():
        return []
    result = []
    for vendor_dir in sorted(path for path in raw_root.iterdir() if path.is_dir()):
        if (vendor_dir / "source_manifest.json").exists() or (vendor_dir / "rawdata").exists():
            result.append(vendor_dir)
    return result


def update_vendor_metadata(builder: Any, raw_root: Path) -> dict[str, str]:
    display_names = {}
    for vendor_dir in raw_vendor_dirs(raw_root):
        vendor_slug = vendor_dir.name
        manifest: dict[str, Any] = {}
        manifest_path = vendor_dir / "source_manifest.json"
        if manifest_path.exists():
            try:
                manifest = load_json(manifest_path)
            except Exception:
                continue
        display_name = vendor_display_name(vendor_slug, manifest)
        display_names[vendor_slug] = display_name
        builder.VENDOR_NAMES[vendor_slug] = display_name
        aliases = {
            vendor_slug,
            display_name,
            display_name.replace("/", " "),
            display_name.replace("&", " and "),
        }
        if vendor_slug == "arris_commscope_cpe":
            aliases.update({"ARRIS", "Motorola", "CommScope", "SURFboard"})
        if vendor_slug == "insys_icom":
            aliases.update({"INSYS", "INSYS icom"})
        if vendor_slug == "hanwha":
            aliases.update(
                {
                    "Hanwha",
                    "Hanwha Vision",
                    "Samsung Techwin",
                    "Samsung SmartCam",
                    "Wisenet",
                }
            )
        if vendor_slug == "silver_peak_aruba_edgeconnect":
            aliases.update(
                {
                    "Silver Peak",
                    "Aruba EdgeConnect",
                    "HPE Aruba EdgeConnect",
                    "HPE Aruba Networking EdgeConnect",
                    "EdgeConnect",
                }
            )
        for alias in aliases:
            key = builder.normalize_lookup_key(alias)
            if key:
                builder.VENDOR_ALIASES[key] = vendor_slug
    return display_names


def ingest_raw_sources(
    *,
    builder: Any,
    database: dict[str, Any],
    scraper_root: Path,
    raw_root: Path | None,
    as_of: date,
    include_existing_vendors: bool,
    selected_vendors: set[str] | None = None,
    skipped_vendors: set[str] | None = None,
    include_orphan_raw_files: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_root = raw_root or scraper_root / "output" / "RawData"
    display_names = update_vendor_metadata(builder, raw_root)
    database_records = list(database.get("records") or [])
    existing_ids = {record.get("id") for record in database_records}
    existing_vendors = {record.get("vendor_slug") for record in database_records}
    selected_vendors = selected_vendors or set()
    skipped_vendors = skipped_vendors or set()
    database_index_by_key: dict[tuple[str, str, str, str], int] = {}
    for index, record in enumerate(database_records):
        database_index_by_key.setdefault(import_dedupe_key(record), index)
    addition_index_by_key: dict[tuple[str, str, str, str], int] = {}
    additions: list[dict[str, Any]] = []
    attempted = Counter()
    accepted = Counter()
    updated = Counter()
    deduped_existing = Counter()
    deduped_new_rows = Counter()
    duplicate_record_ids = Counter()
    skipped = Counter()

    for vendor_dir in raw_vendor_dirs(raw_root):
        manifest_path = vendor_dir / "source_manifest.json"
        vendor_slug = vendor_dir.name
        skip_reason = vendor_skip_reason(
            vendor_slug=vendor_slug,
            selected_vendors=selected_vendors,
            skipped_vendors=skipped_vendors,
            existing_vendors=existing_vendors,
            include_existing_vendors=include_existing_vendors,
        )
        if skip_reason:
            skipped[skip_reason] += 1
            continue

        manifest = load_json(manifest_path) if manifest_path.exists() else {}
        display_name = display_names.get(vendor_slug, vendor_slug)
        files = (
            manifest_files(scraper_root, vendor_dir, manifest)
            if manifest_path.exists()
            else local_rawdata_files(vendor_dir)
        )
        if include_orphan_raw_files:
            files.extend(
                orphan_raw_files(vendor_dir, {path.resolve() for path, _ in files})
            )
        for path, entry in files:
            try:
                rows = extract_rows(path, vendor_slug)
            except Exception:
                continue
            if not rows:
                continue
            source_url = normalize_text(entry.get("url"))
            source_hint = f"{display_name} raw lifecycle table import"
            dayfirst = source_uses_dayfirst_dates(path, entry, vendor_slug)
            for row in rows:
                attempted[vendor_slug] += 1
                record = row_to_record(
                    builder=builder,
                    vendor_slug=vendor_slug,
                    display_name=display_name,
                    raw_file=path,
                    row=row,
                    source_url=source_url,
                    source_hint=source_hint,
                    as_of=as_of,
                    dayfirst=dayfirst,
                )
                if not record:
                    continue
                key = import_dedupe_key(record)
                existing_index = database_index_by_key.get(key)
                if existing_index is not None:
                    if row.get("_replace_existing_raw_record"):
                        existing_record = database_records[existing_index]
                        record["id"] = existing_record["id"]
                        database_records[existing_index] = record
                        existing_ids.add(record["id"])
                        updated[vendor_slug] += 1
                    else:
                        deduped_existing[vendor_slug] += 1
                    continue
                if key in addition_index_by_key:
                    existing_index = addition_index_by_key[key]
                    existing_record = additions[existing_index]
                    if record_dedupe_score(record) > record_dedupe_score(existing_record):
                        existing_ids.discard(existing_record["id"])
                        additions[existing_index] = record
                        existing_ids.add(record["id"])
                    deduped_new_rows[vendor_slug] += 1
                    continue
                if record["id"] in existing_ids:
                    duplicate_record_ids[vendor_slug] += 1
                    continue
                additions.append(record)
                existing_ids.add(record["id"])
                addition_index_by_key[key] = len(additions) - 1
                accepted[vendor_slug] += 1

    records = builder.dedupe_records(database_records + additions)
    records.sort(
        key=lambda r: (
            r["vendor_slug"],
            r.get("model_key") or "",
            r.get("part_number") or "",
            r.get("region") or "",
        )
    )
    database["records"] = records
    database["model_summaries"] = builder.build_model_summaries(records)
    database["indexes"] = builder.build_indexes(records)
    database["summary"] = builder.build_summary(records, database["model_summaries"])
    rebuild_model_summaries(database)
    rebuild_summary(database)
    metadata = database.setdefault("metadata", {})
    metadata["raw_table_import"] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_project": "nhedb-scraper",
        "raw_root": str(raw_root),
        "imported_records": len(additions),
        "updated_records": sum(updated.values()),
        "imported_vendors": len([vendor for vendor, count in accepted.items() if count]),
        "updated_vendors": len([vendor for vendor, count in updated.items() if count]),
        "policy": "Conservative table import from raw source manifests; prose-only and blocked sources are not normalized.",
    }

    report = {
        "attempted_rows_by_vendor": dict(sorted(attempted.items())),
        "accepted_records_by_vendor": dict(sorted(accepted.items())),
        "updated_records_by_vendor": dict(sorted(updated.items())),
        "deduped_existing_records_by_vendor": dict(sorted(deduped_existing.items())),
        "deduped_new_rows_by_vendor": dict(sorted(deduped_new_rows.items())),
        "duplicate_record_ids_skipped_by_vendor": dict(sorted(duplicate_record_ids.items())),
        "selected_vendors": sorted(selected_vendors),
        "skipped_vendors": sorted(skipped_vendors),
        "skipped_vendor_counts": dict(sorted(skipped.items())),
        "imported_records": len(additions),
        "updated_records": sum(updated.values()),
        "database_total_records": len(records),
        "database_total_vendors": len(database["summary"]["vendors"]),
    }
    return database, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--scraper-root", required=True, type=Path)
    parser.add_argument(
        "--raw-root",
        type=Path,
        help=(
            "Optional RawData-style directory containing vendor/source_manifest.json "
            "files. The scraper root is still used for builder/schema helpers."
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--as-of", default=date.today().isoformat())
    parser.add_argument("--include-existing-vendors", action="store_true")
    parser.add_argument(
        "--vendor",
        action="append",
        default=[],
        help="Vendor slug to import. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--vendor-file",
        action="append",
        default=[],
        type=Path,
        help="File containing vendor slugs, one per line or comma-separated.",
    )
    parser.add_argument(
        "--skip-vendors",
        action="append",
        default=[],
        help="Vendor slugs to skip. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--include-orphan-raw-files",
        action="store_true",
        help="Also read supported files under vendor/raw that are not listed in source_manifest.json.",
    )
    args = parser.parse_args()

    builder = import_builder(args.scraper_root)
    database = load_database_for_ingest(args.input)
    as_of = date.fromisoformat(args.as_of)
    selected_vendors = build_vendor_filter(args.vendor, args.vendor_file)
    skipped_vendors = build_vendor_filter(args.skip_vendors)
    database, report = ingest_raw_sources(
        builder=builder,
        database=database,
        scraper_root=args.scraper_root,
        raw_root=args.raw_root,
        as_of=as_of,
        include_existing_vendors=args.include_existing_vendors,
        selected_vendors=selected_vendors,
        skipped_vendors=skipped_vendors,
        include_orphan_raw_files=args.include_orphan_raw_files,
    )
    write_json(args.output, database)
    if args.report:
        write_json(args.report, report)
    print(f"imported_records={report['imported_records']}")
    print(f"database_total_records={report['database_total_records']}")
    print(f"database_total_vendors={report['database_total_vendors']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
