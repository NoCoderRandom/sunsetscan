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

SUPPORTED_SUFFIXES = {".csv", ".html", ".htm", ".json", ".xlsx", ".pdf"}
HTML_GENERIC_TABLE_BLOCKLIST = {
    # These pages contain support/advisory/login tables that are not product
    # lifecycle tables. Use vendor-specific parsers for them instead.
    "arris_commscope_cpe",
    "beckhoff",
    "bosch_security",
    "broadcom_bluecoat",
    "geovision",
    "hanwha",
    "hp_printers_official",
    "insys_icom",
    "kyocera_printers",
    "lexmark_printers",
    "lupus_electronics",
    "mobotix",
    "nokia_networks",
    "nvidia_mellanox_cumulus",
    "synology",
    "zebra_printers_scanners",
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
        "product",
        "description",
        "service",
    ],
    "description": [
        "description",
        "product family",
        "family",
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
        "eosm",
        "eosm date",
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
        (table_index, html_table_matrix(table, separator="\n"))
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
                item: dict[str, Any] = {
                    "Affected Product": product,
                    "Product Name": description or product,
                    "Description": description,
                    "Replacement Products": replacement,
                    "_source_table": f"{path.name} split milestone table {table_index}",
                    "_source_hint": source_hints[vendor_slug],
                }
                add_date_fields(item, dates)
                extracted.append(item)
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


def extract_grandstream_status_rows(path: Path) -> list[dict[str, Any]]:
    if path.name != "firmware.html":
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
                extracted.append(
                    {
                        "Model": model,
                        "Product Name": model,
                        "Description": "Network Device",
                        "Firmware": firmware,
                        "Product Status": "end-of-life",
                        "_source_table": f"{path.name} end-of-life table {table_index}",
                        "_source_hint": "Grandstream End-Of-Life Products firmware table review import",
                        "_status_only_review": True,
                        "_review_policy": "status_only_not_security_eol",
                    }
                )
    return extracted


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
    if path.name != "adtran-product-page-discontinued-example.html":
        return []
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    text = normalize_text(soup.get_text(" ", strip=True))
    if "product has been discontinued" not in text.lower():
        return []
    model = ""
    for selector in ("h1", "title"):
        node = soup.find(selector)
        if node:
            model = normalize_text(node.get_text(" ", strip=True))
            model = re.sub(r"\s*\|\s*ADTRAN.*$", "", model, flags=re.I)
            if model:
                break
    part_number = ""
    for raw in (str(soup), text):
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
            end_vulnerability = (
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
                    "End of Vulnerability Support": end_vulnerability,
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
    if path.name != "ewon-flexy-103-end-of-life.html":
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


def extract_oring_phase_out_rows(path: Path) -> list[dict[str, Any]]:
    if not path.name.startswith("phase-out-") or path.suffix.lower() not in {".html", ".htm"}:
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


def extract_vendor_html_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []
    if vendor_slug in {"arista", "h3c"}:
        extracted.extend(extract_split_milestone_rows(path, vendor_slug))
    if vendor_slug == "amcrest":
        extracted.extend(extract_amcrest_discontinued_firmware_rows(path))
    if vendor_slug == "axis":
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
    elif vendor_slug == "beckhoff":
        extracted.extend(extract_beckhoff_service_product_rows(path))
    elif vendor_slug == "broadcom_bluecoat":
        extracted.extend(extract_broadcom_bluecoat_packetshaper_rows(path))
    elif vendor_slug == "buffalo_nas":
        extracted.extend(extract_buffalo_nas_eol_rows(path))
    elif vendor_slug == "fiberhome":
        extracted.extend(extract_fiberhome_milestone_rows(path))
    elif vendor_slug == "hanwha":
        extracted.extend(extract_hanwha_discontinued_product_rows(path))
    elif vendor_slug == "hms_ewon":
        extracted.extend(extract_hms_ewon_eol_rows(path))
    elif vendor_slug == "insys_icom":
        extracted.extend(extract_insys_icom_discontinued_rows(path))
    elif vendor_slug == "ipro_panasonic":
        extracted.extend(extract_ipro_panasonic_discontinued_firmware_rows(path))
    elif vendor_slug == "kyocera_printers":
        extracted.extend(extract_kyocera_taskalfa_sales_end_rows(path))
    elif vendor_slug == "lexmark_printers":
        extracted.extend(extract_lexmark_product_eosl_rows(path))
    elif vendor_slug == "oring":
        extracted.extend(extract_oring_phase_out_rows(path))
    elif vendor_slug == "phoenix_contact":
        extracted.extend(extract_phoenix_contact_sfn_rows(path))
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
    elif vendor_slug == "grandstream":
        extracted.extend(extract_grandstream_status_rows(path))
    elif vendor_slug == "supermicro_networking":
        extracted.extend(extract_supermicro_status_rows(path))
    elif vendor_slug == "adtran":
        extracted.extend(extract_adtran_discontinued_page(path))
    elif vendor_slug == "moxa":
        extracted.extend(extract_moxa_eol_product_page(path))
    elif vendor_slug == "imperva":
        extracted.extend(extract_imperva_hardware_schedule_rows(path))
    elif vendor_slug == "softing_industrial":
        extracted.extend(extract_softing_discontinued_rows(path))
    elif vendor_slug == "red_lion_ntron":
        extracted.extend(extract_red_lion_ntron_eol_rows(path))
    elif vendor_slug == "qnap":
        extracted.extend(extract_qnap_support_status_rows(path))
    elif vendor_slug == "seagate_lacie_nas":
        extracted.extend(extract_seagate_lacie_nas_os4_rows(path))
    elif vendor_slug == "versa":
        extracted.extend(extract_versa_eol_rows(path))
    elif vendor_slug == "wd_my_cloud":
        extracted.extend(extract_wd_my_cloud_rows(path))
    elif vendor_slug == "screenbeam_actiontec":
        extracted.extend(extract_screenbeam_eol_rows(path))
    elif vendor_slug == "digi":
        extracted.extend(extract_digi_eol_model_rows(path))
    elif vendor_slug == "edgecore":
        extracted.extend(extract_edgecore_eol_rows(path))
    elif vendor_slug == "sophos":
        extracted.extend(extract_sophos_product_lifecycle_rows(path))
    elif vendor_slug == "lorex":
        extracted.extend(extract_lorex_psti_rows(path))
    elif vendor_slug == "siedle":
        extracted.extend(extract_siedle_discontinued_product_rows(path))
    elif vendor_slug == "synology":
        extracted.extend(extract_synology_product_status_rows(path))
    elif vendor_slug == "terramaster":
        extracted.extend(extract_terramaster_support_termination_rows(path))
    elif vendor_slug == "zebra_printers_scanners":
        extracted.extend(extract_zebra_discontinued_product_rows(path))
    return extracted


def extract_vendor_json_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug == "hp_printers_official":
        return extract_hp_designjet_eosl_json_rows(path)
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


def extract_vendor_pdf_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug not in {
        "advantech_industrial_networking",
        "alcatel_lucent_enterprise",
        "aruba_hpe",
        "atx_networks",
        "avigilon",
        "avaya_nortel_networking",
        "bosch_security",
        "broadcom_brocade",
        "calix",
        "celona",
        "eltako",
        "genexis",
        "geovision",
        "hikvision",
        "helmholz",
        "hirschmann_belden",
        "mobotix",
        "nvidia_mellanox_cumulus",
        "pilz",
        "silver_peak_aruba_edgeconnect",
        "weidmueller",
        "westermo",
    }:
        return []
    text = extract_pdf_text(path, raw=vendor_slug == "avaya_nortel_networking")
    if not text:
        return []
    if vendor_slug == "advantech_industrial_networking":
        return parse_advantech_ntron_pdf_rows_from_text(text, path.name)
    if vendor_slug == "alcatel_lucent_enterprise":
        return parse_alcatel_lucent_pdf_rows_from_text(text, path.name)
    if vendor_slug == "aruba_hpe" and path.name == "aruba-hardware-end-of-sale-list.pdf":
        return parse_aruba_pdf_rows_from_text(text, path.name)
    if vendor_slug == "atx_networks":
        return parse_atx_digistream_pdf_rows_from_text(text, path.name)
    if vendor_slug == "avigilon":
        return parse_avigilon_pdf_rows_from_text(text, path.name)
    if vendor_slug == "avaya_nortel_networking":
        return parse_avaya_pdf_rows_from_text(text, path.name)
    if vendor_slug == "bosch_security":
        return parse_bosch_ip_video_firmware_pdf_rows_from_text(text, path.name)
    if vendor_slug == "broadcom_brocade":
        return parse_broadcom_brocade_pdf_rows_from_text(text, path.name)
    if vendor_slug == "calix":
        return parse_calix_pdf_rows_from_text(text, path.name)
    if vendor_slug == "celona":
        return parse_celona_pdf_rows_from_text(text, path.name)
    if vendor_slug == "eltako":
        return parse_eltako_safe_iv_pdf_rows_from_text(text, path.name)
    if vendor_slug == "genexis":
        return parse_genexis_psti_pdf_rows_from_text(text, path.name)
    if vendor_slug == "geovision":
        return parse_geovision_pdf_rows_from_text(text, path.name)
    if vendor_slug == "hikvision":
        return parse_hikvision_discontinuation_pdf_rows_from_text(text, path.name)
    if vendor_slug == "helmholz":
        return parse_helmholz_myrex24_pdf_rows_from_text(text, path.name)
    if vendor_slug == "hirschmann_belden":
        return parse_hirschmann_belden_pdn_rows_from_text(text, path.name)
    if vendor_slug == "mobotix":
        return parse_mobotix_product_news_pdf_rows_from_text(text, path.name)
    if vendor_slug == "nvidia_mellanox_cumulus":
        return parse_nvidia_mellanox_pdf_rows_from_text(text, path.name)
    if vendor_slug == "pilz":
        return parse_pilz_pnozmulti_pdf_rows_from_text(text, path.name)
    if vendor_slug == "silver_peak_aruba_edgeconnect":
        return parse_silver_peak_edgeconnect_pdf_rows_from_text(text, path.name)
    if vendor_slug == "weidmueller":
        return parse_weidmueller_datasheet_pdf_rows_from_text(text, path.name)
    if vendor_slug == "westermo":
        return parse_westermo_pdf_rows_from_text(text, path.name)
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
    )
    for key, value in row.items():
        if str(key).startswith("_"):
            continue
        header = normalize_header(key)
        if any(word in header for word in excluded):
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


def normalize_record_output_shape(record: dict[str, Any]) -> dict[str, Any]:
    """Keep imported records on the current SunsetScan artifact schema."""
    if "netwatch" in record and "sunsetscan" not in record:
        record["sunsetscan"] = record.pop("netwatch")
    else:
        record.pop("netwatch", None)
    return record


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
    if not any(dates.values()) and not (status_only_allowed and raw_status):
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

    record = builder.make_record(
        vendor_slug=vendor_slug,
        raw_file=raw_file,
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
        extra_aliases = row_alias_values(row)
        if extra_aliases:
            add_record_aliases(builder, record, extra_aliases)
        if force_review:
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


def orphan_raw_files(vendor_dir: Path, known_paths: set[Path]) -> list[tuple[Path, dict[str, Any]]]:
    raw_dir = vendor_dir / "raw"
    if not raw_dir.exists():
        return []
    result = []
    for path in sorted(raw_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
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


def update_vendor_metadata(builder: Any, raw_root: Path) -> dict[str, str]:
    display_names = {}
    for manifest_path in sorted(raw_root.glob("*/source_manifest.json")):
        vendor_slug = manifest_path.parent.name
        try:
            manifest = load_json(manifest_path)
        except Exception:
            continue
        display_name = normalize_text(manifest.get("display_name")) or vendor_slug
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
    as_of: date,
    include_existing_vendors: bool,
    selected_vendors: set[str] | None = None,
    skipped_vendors: set[str] | None = None,
    include_orphan_raw_files: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_root = scraper_root / "output" / "RawData"
    display_names = update_vendor_metadata(builder, raw_root)
    existing_ids = {record.get("id") for record in database.get("records", [])}
    existing_vendors = {record.get("vendor_slug") for record in database.get("records", [])}
    selected_vendors = selected_vendors or set()
    skipped_vendors = skipped_vendors or set()
    database_import_keys = {
        import_dedupe_key(record)
        for record in database.get("records", [])
    }
    addition_index_by_key: dict[tuple[str, str, str, str], int] = {}
    additions: list[dict[str, Any]] = []
    attempted = Counter()
    accepted = Counter()
    skipped = Counter()

    for manifest_path in sorted(raw_root.glob("*/source_manifest.json")):
        vendor_dir = manifest_path.parent
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

        manifest = load_json(manifest_path)
        display_name = display_names.get(vendor_slug, vendor_slug)
        files = manifest_files(scraper_root, vendor_dir, manifest)
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
                if not record or record["id"] in existing_ids:
                    continue
                key = import_dedupe_key(record)
                if key in database_import_keys:
                    continue
                if key in addition_index_by_key:
                    existing_index = addition_index_by_key[key]
                    existing_record = additions[existing_index]
                    if record_date_score(record) > record_date_score(existing_record):
                        existing_ids.discard(existing_record["id"])
                        additions[existing_index] = record
                        existing_ids.add(record["id"])
                    continue
                additions.append(record)
                existing_ids.add(record["id"])
                addition_index_by_key[key] = len(additions) - 1
                accepted[vendor_slug] += 1

    records = builder.dedupe_records((database.get("records") or []) + additions)
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
        "raw_root": "output/RawData",
        "imported_records": len(additions),
        "imported_vendors": len([vendor for vendor, count in accepted.items() if count]),
        "policy": "Conservative table import from raw source manifests; prose-only and blocked sources are not normalized.",
    }

    report = {
        "attempted_rows_by_vendor": dict(sorted(attempted.items())),
        "accepted_records_by_vendor": dict(sorted(accepted.items())),
        "selected_vendors": sorted(selected_vendors),
        "skipped_vendors": sorted(skipped_vendors),
        "skipped_vendor_counts": dict(sorted(skipped.items())),
        "imported_records": len(additions),
        "database_total_records": len(records),
        "database_total_vendors": len(database["summary"]["vendors"]),
    }
    return database, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--scraper-root", required=True, type=Path)
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
