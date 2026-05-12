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
import importlib.util
import json
import re
import shutil
import subprocess
import sys
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

SUPPORTED_SUFFIXES = {".csv", ".html", ".htm", ".xlsx", ".pdf"}
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
        "replacement product #",
        "replacement products",
        "replacement model",
        "replacement",
        "successor",
        "alternative",
        "migration",
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
        "end of availability",
        "eoa",
        "eoa date",
        "eos",
        "eos date",
    ],
    "end_of_life": [
        "end of life",
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


def parse_date_any(value: Any, *, dayfirst: bool = False) -> str | None:
    text = re.sub(r"[\u200b-\u200f\ufeff]", "", normalize_text(value))
    if not text:
        return None
    low = text.lower()
    if low in {"-", "n/a", "na", "none", "null", "tbd", "unknown", "not announced"}:
        return None

    text = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", text, flags=re.I)
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
        normalize_header(record.get("part_number") or record.get("model")),
        normalize_header(record.get("hardware_version")),
        normalize_header(record.get("region")),
    )


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
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        for row in html_table_matrix(table):
            if len(row) < 2:
                continue
            category = normalize_text(row[0])
            if normalize_header(category) in {"end of life product list", "network camera"}:
                continue
            for model in split_comma_values(row[1]):
                extracted.append(
                    {
                        "Model": model,
                        "Product Name": model,
                        "Description": f"{category} IP Camera".strip(),
                        "Product Status": "end-of-life",
                        "_source_table": f"{path.name} product list table {table_index}",
                        "_source_hint": "VIVOTEK end-of-life product list review import",
                        "_status_only_review": True,
                        "_review_policy": "status_only_not_security_eol",
                    }
                )
    return extracted


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


def extract_vendor_html_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []
    if vendor_slug in {"arista", "h3c"}:
        extracted.extend(extract_split_milestone_rows(path, vendor_slug))
    if vendor_slug == "perle":
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
    return extracted


def extract_pdf_text(path: Path) -> str:
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        return ""
    try:
        completed = subprocess.run(
            [pdftotext, "-layout", str(path), "-"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return ""
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


def extract_vendor_pdf_rows(path: Path, vendor_slug: str) -> list[dict[str, Any]]:
    if vendor_slug not in {"aruba_hpe", "calix", "westermo"}:
        return []
    text = extract_pdf_text(path)
    if not text:
        return []
    if vendor_slug == "aruba_hpe" and path.name == "aruba-hardware-end-of-sale-list.pdf":
        return parse_aruba_pdf_rows_from_text(text, path.name)
    if vendor_slug == "calix":
        return parse_calix_pdf_rows_from_text(text, path.name)
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


def extract_rows(path: Path, vendor_slug: str = "") -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return extract_csv_rows(path)
    if suffix in {".html", ".htm"}:
        return extract_vendor_html_rows(path, vendor_slug) + extract_html_tables(path)
    if suffix == ".xlsx":
        return extract_xlsx_rows(path)
    if suffix == ".pdf":
        return extract_vendor_pdf_rows(path, vendor_slug)
    return []


def find_value(row: dict[str, Any], patterns: list[str]) -> tuple[str, str]:
    for key, value in row.items():
        header = normalize_header(key)
        if any(pattern in header for pattern in patterns):
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
        if normalized in header:
            return True
        # Short lifecycle abbreviations like EOS must match exactly once
        # compacted, otherwise EOS would also match EOSL/EOSM.
        if len(compact_alias) <= 3:
            if compact_header == compact_alias:
                return True
            continue
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
        header = normalize_header(key)
        if any(word in header for word in excluded):
            continue
        if any(pattern in header for pattern in patterns):
            text = normalize_text(value)
            if text:
                return text, header
    return "", ""


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
        "Source shows EOL, discontinued, or replacement status, but it does "
        "not prove that firmware/security updates have stopped."
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
        "lifecycle review needed"
    ).strip()
    if hasattr(builder, "match_priority"):
        record["sunsetscan"]["match_priority"] = builder.match_priority(
            record.get("device_class") or "network_device",
            "lifecycle_review",
        )


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
    force_review = bool(row.get("_force_lifecycle_review") or status_only_review)
    if not any(dates.values()) and not (status_only_review and raw_status):
        return None

    product_name, _ = find_value(row, CANONICAL_FIELD_ALIASES["product_name"])
    description, _ = find_value(row, CANONICAL_FIELD_ALIASES["description"])
    replacement, _ = find_value(row, CANONICAL_FIELD_ALIASES["replacement"])

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
    if record and force_review:
        apply_lifecycle_review_override(builder, record, row)
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_root = scraper_root / "output" / "RawData"
    display_names = update_vendor_metadata(builder, raw_root)
    existing_ids = {record.get("id") for record in database.get("records", [])}
    existing_vendors = {record.get("vendor_slug") for record in database.get("records", [])}
    seen_import_keys = {
        import_dedupe_key(record)
        for record in database.get("records", [])
    }
    additions: list[dict[str, Any]] = []
    attempted = Counter()
    accepted = Counter()

    for manifest_path in sorted(raw_root.glob("*/source_manifest.json")):
        vendor_dir = manifest_path.parent
        vendor_slug = vendor_dir.name
        if vendor_slug in SKIP_VENDOR_SLUGS and not include_existing_vendors:
            continue
        if vendor_slug in existing_vendors and not include_existing_vendors:
            continue

        manifest = load_json(manifest_path)
        display_name = display_names.get(vendor_slug, vendor_slug)
        for path, entry in manifest_files(scraper_root, vendor_dir, manifest):
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
                if key in seen_import_keys:
                    continue
                additions.append(record)
                existing_ids.add(record["id"])
                seen_import_keys.add(key)
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
    args = parser.parse_args()

    builder = import_builder(args.scraper_root)
    database = load_json(args.input)
    as_of = date.fromisoformat(args.as_of)
    database, report = ingest_raw_sources(
        builder=builder,
        database=database,
        scraper_root=args.scraper_root,
        as_of=as_of,
        include_existing_vendors=args.include_existing_vendors,
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
