"""
SunsetScan hardware end-of-life lookup.

This module reads the hardware lifecycle database installed by the SunsetScan
module manager in data/cache/hardware_eol/. It is separate from the software
EOL checker because the source data is vendor hardware lifecycle data, not
endoflife.date cycles.
"""

import gzip
import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "sunsetscan_hardware_eol.json"
_DEFAULT_INDEX_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "sunsetscan_hardware_eol_index.json"
_DEFAULT_MANIFEST_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "manifest.json"
_DEFAULT_MANIFEST_GZ_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "manifest.json.gz"
_DEVELOPER_DB_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "sunsetscan_hardware_eol.json"
_DEVELOPER_DB_GZ_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "sunsetscan_hardware_eol.json.gz"
_DEVELOPER_INDEX_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "sunsetscan_hardware_eol_index.json"
_DEVELOPER_INDEX_GZ_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "sunsetscan_hardware_eol_index.json.gz"
_DEVELOPER_MANIFEST_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "manifest.json"
_DEVELOPER_MANIFEST_GZ_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "manifest.json.gz"

_LEGACY_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "netwatch_hardware_eol.json"
_LEGACY_DEFAULT_INDEX_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "netwatch_hardware_eol_index.json"
_LEGACY_DEVELOPER_DB_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "netwatch_hardware_eol.json"
_LEGACY_DEVELOPER_DB_GZ_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "netwatch_hardware_eol.json.gz"
_LEGACY_DEVELOPER_INDEX_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "netwatch_hardware_eol_index.json"
_LEGACY_DEVELOPER_INDEX_GZ_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "netwatch_hardware_eol_index.json.gz"


def normalize_key(value: Any) -> str:
    """Normalize a vendor, model, part, or alias value for database lookup."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value)).casefold()
    text = text.replace("&", " and ")
    text = text.replace("+", " plus ")
    text = text.replace("@", " at ")
    text = re.sub(r"[\u2010-\u2015]", "-", text)
    chars = [char if char.isalnum() else " " for char in text]
    return re.sub(r"\s+", " ", "".join(chars)).strip()


def _legacy_normalize_key(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).lower()
    text = text.replace("&", " and ")
    text = text.replace("+", " plus ")
    text = text.replace("@", " at ")
    text = re.sub(r"[\u2010-\u2015]", "-", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _lookup_key_variants(value: Any) -> List[str]:
    variants: List[str] = []
    for key in (normalize_key(value), _legacy_normalize_key(value)):
        if key and key not in variants:
            variants.append(key)
    return variants


def _normalize_version_key(value: Any) -> str:
    key = normalize_key(value)
    if len(key) > 1 and key[0] == "v" and key[1].isdigit():
        return key[1:].strip()
    return key


def _review_title_suffix(records: List[Dict[str, Any]]) -> str:
    evidence = " ".join(
        str((record.get("source") or {}).get(key) or "")
        for record in records
        for key in ("status_text", "source_hint")
    )
    normalized = normalize_key(evidence)
    if any(
        needle in normalized
        for needle in (
            "end of support",
            "end of service",
            "end of updates",
            "support ended",
            "updates ended",
        )
    ):
        return "vendor-declared support/update end; review needed"
    if "end of life" in normalized or re.search(r"\beol\b", normalized):
        return "vendor-declared EOL; review needed"
    if "discontinued" in normalized:
        return "vendor-declared discontinued; review needed"
    if "end of sale" in normalized or re.search(r"\beos\b", normalized):
        return "vendor-declared end of sale; review needed"
    return "lifecycle review needed"


@dataclass
class HardwareEOLMatch:
    """A hardware lifecycle match that should be emitted as a finding."""

    vendor: str
    model: str
    canonical_vendor: str
    model_key: str
    match_type: str
    status: str
    risk: str
    finding_title: str
    receives_security_updates: Optional[bool]
    records: List[Dict[str, Any]] = field(default_factory=list)
    selected_record: Optional[Dict[str, Any]] = None
    model_summary: Optional[Dict[str, Any]] = None
    mixed: bool = False
    review_required: bool = False
    confidence: str = "medium"

    @property
    def dedup_id(self) -> str:
        if self.selected_record:
            return str(self.selected_record.get("id") or "")
        if self.records and not self.mixed:
            ids = sorted(str(r.get("id") or "") for r in self.records if r.get("id"))
            if ids:
                return ",".join(ids[:5])
        if self.model_summary:
            return str(self.model_summary.get("id") or "")
        if self.records:
            ids = sorted(str(r.get("id") or "") for r in self.records if r.get("id"))
            if ids:
                return ",".join(ids[:5])
        return f"{self.canonical_vendor}|{self.model_key}"

    @property
    def record_count(self) -> int:
        if self.selected_record:
            return 1
        if self.records:
            return len(self.records)
        if self.model_summary:
            count = self.model_summary.get("record_count")
            if isinstance(count, int):
                return count
        return 0

    @property
    def security_eol_date(self) -> str:
        if self.selected_record:
            dates = self.selected_record.get("dates") or {}
            return str(dates.get("end_of_security_updates") or "")
        for record in self.records:
            dates = record.get("dates") or {}
            if dates.get("end_of_security_updates"):
                return str(dates["end_of_security_updates"])
        if self.model_summary:
            return str(
                self.model_summary.get("earliest_security_eol")
                or self.model_summary.get("latest_security_eol")
                or ""
            )
        return ""

    @property
    def reason(self) -> str:
        if self.selected_record:
            lifecycle = self.selected_record.get("lifecycle") or {}
            return str(lifecycle.get("reason") or "")
        for record in self.records:
            lifecycle = record.get("lifecycle") or {}
            if lifecycle.get("reason"):
                return str(lifecycle["reason"])
        if self.model_summary:
            return str(
                self.model_summary.get("sunsetscan_note")
                or self.model_summary.get("netwatch_note")
                or ""
            )
        return ""

    @property
    def source_url(self) -> str:
        if self.selected_record:
            source = self.selected_record.get("source") or {}
            return str(source.get("url") or "")
        for record in self.records:
            source = record.get("source") or {}
            if source.get("url"):
                return str(source["url"])
        return ""


class HardwareEOLDatabase:
    """Lazy hardware lifecycle database lookup."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path is not None else _DEFAULT_DB_PATH
        self._db_path: Optional[Path] = None
        self._db: Optional[Dict[str, Any]] = None
        self._indexes: Dict[str, Any] = {}
        self._records: List[Dict[str, Any]] = []
        self._record_positions: Dict[str, int] = {}
        self._summary_by_key: Dict[str, Dict[str, Any]] = {}
        self._record_locations: Dict[str, str] = {}
        self._record_shards: Dict[str, Any] = {}
        self._shard_cache: Dict[str, Dict[str, Any]] = {}
        self._installed_packs: set[str] = set()
        self._vendor_pack_hints: Dict[str, Any] = {}

    def available(self) -> bool:
        """Return True if a hardware lifecycle database file exists."""
        return self._candidate_path().exists()

    def canonical_vendor(self, vendor: str) -> str:
        """Normalize and canonicalize a vendor through indexes.vendor_aliases."""
        self._ensure_loaded()
        aliases = self._indexes.get("vendor_aliases") or {}
        vendor_keys = _lookup_key_variants(vendor)
        for vendor_key in vendor_keys:
            if vendor_key in aliases:
                return aliases[vendor_key]
        return vendor_keys[0] if vendor_keys else ""

    def lookup(
        self,
        vendor: str,
        model: str,
        part_number: str = "",
        hardware_version: str = "",
        region: str = "",
    ) -> Optional[HardwareEOLMatch]:
        """Look up hardware lifecycle data for a detected vendor/model.

        Returns a match only when SunsetScan should emit a finding: unsupported
        hardware, mixed lifecycle status, or a vendor lifecycle signal that
        needs manual review.
        """
        if not model:
            return None

        self._ensure_loaded()
        if not self._db:
            return None

        vendor_key = self.canonical_vendor(vendor)
        model_keys = _lookup_key_variants(model)
        if not model_keys:
            return None

        record_ids: List[str] = []
        match_type = ""
        model_key = model_keys[0]
        for candidate_model_key in model_keys:
            record_ids, match_type = self._lookup_record_ids(vendor_key, candidate_model_key)
            if record_ids:
                model_key = candidate_model_key
                break
        if not record_ids:
            return None

        records = self._records_for_ids(record_ids)
        if not records:
            return None

        summary = self._summary_for(vendor_key, model_key, records)
        focused, focused_by_specific_input = self._focus_records(
            records,
            part_number=part_number,
            hardware_version=hardware_version,
            region=region,
        )

        if focused_by_specific_input:
            match = self._match_from_focused_records(
                vendor=vendor,
                model=model,
                vendor_key=vendor_key,
                model_key=model_key,
                match_type=match_type,
                focused=focused,
                summary=summary,
            )
            if match:
                return match

        if summary:
            return self._match_from_summary(
                vendor=vendor,
                model=model,
                vendor_key=vendor_key,
                model_key=model_key,
                match_type=match_type,
                summary=summary,
                records=records,
            )

        return self._match_from_focused_records(
            vendor=vendor,
            model=model,
            vendor_key=vendor_key,
            model_key=model_key,
            match_type=match_type,
            focused=records,
            summary=None,
        )

    def missing_profile_hint(self, vendor: str) -> Optional[Dict[str, Any]]:
        """Return smart-pack profile guidance for a vendor outside installed packs."""
        self._ensure_loaded()
        if not vendor or not self._vendor_pack_hints:
            return None

        for vendor_key in _lookup_key_variants(vendor):
            hint = self._vendor_pack_hints.get(vendor_key)
            if not isinstance(hint, dict):
                continue
            packs = hint.get("packs") or {}
            if not isinstance(packs, dict):
                continue
            missing = {
                str(pack): count
                for pack, count in packs.items()
                if str(pack) not in self._installed_packs
            }
            if not missing:
                return None
            primary_missing = max(missing, key=lambda pack: missing[pack])
            return {
                "vendor_slug": vendor_key,
                "missing_pack": primary_missing,
                "recommended_profile": self._profile_for_pack(primary_missing),
                "known_packs": sorted(packs),
                "installed_packs": sorted(self._installed_packs),
            }
        return None

    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._db is not None:
            return

        db_path = self._candidate_path()
        if not db_path.exists():
            logger.debug("Hardware EOL database not found: %s", self.path)
            self._db = {}
            return

        try:
            self._db = self._load_json_file(db_path)
        except Exception as e:
            logger.warning("Could not load hardware EOL database: %s", e)
            self._db = {}
            return

        self._db_path = db_path
        if self._is_smart_pack_manifest(self._db):
            self._load_smart_pack_manifest(db_path, self._db)
            return

        self._indexes = self._db.get("indexes") or {}
        self._records = self._db.get("records") or []
        self._record_positions = self._indexes.get("by_id") or {}
        if self._records and not self._record_positions:
            self._record_positions = {
                str(record["id"]): pos
                for pos, record in enumerate(self._records)
                if record.get("id")
            }
        self._record_locations = self._db.get("record_locations") or {}
        self._record_shards = self._db.get("record_shards") or {}
        self._installed_packs = set()
        self._vendor_pack_hints = {}
        self._summary_by_key = {}
        for summary in self._db.get("model_summaries") or []:
            vendor_slug = summary.get("vendor_slug") or ""
            model_key = summary.get("model_key") or ""
            if vendor_slug and model_key:
                self._summary_by_key[f"{vendor_slug}|{model_key}"] = summary

        summary = self._db.get("summary") or {}
        total_records = len(self._records) or summary.get("total_records") or 0
        layout = "split" if self._record_locations else "monolithic"
        logger.debug(
            "Hardware EOL database loaded from %s: %d records, %d model summaries, %s layout",
            db_path,
            total_records,
            len(self._summary_by_key),
            layout,
        )

    def _candidate_path(self) -> Path:
        if self.path != _DEFAULT_DB_PATH:
            return self.path

        candidates = (
            _DEFAULT_MANIFEST_PATH,
            _DEFAULT_MANIFEST_GZ_PATH,
            _DEFAULT_INDEX_PATH,
            _DEVELOPER_MANIFEST_PATH,
            _DEVELOPER_MANIFEST_GZ_PATH,
            _DEVELOPER_INDEX_PATH,
            _DEVELOPER_INDEX_GZ_PATH,
            _LEGACY_DEFAULT_INDEX_PATH,
            _LEGACY_DEVELOPER_INDEX_PATH,
            _LEGACY_DEVELOPER_INDEX_GZ_PATH,
            _DEFAULT_DB_PATH,
            _DEVELOPER_DB_PATH,
            _DEVELOPER_DB_GZ_PATH,
            _LEGACY_DEFAULT_DB_PATH,
            _LEGACY_DEVELOPER_DB_PATH,
            _LEGACY_DEVELOPER_DB_GZ_PATH,
        )
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return self.path

    @staticmethod
    def _load_json_file(path: Path) -> Dict[str, Any]:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                return json.load(f)
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _is_smart_pack_manifest(database: Dict[str, Any]) -> bool:
        return (
            isinstance(database, dict)
            and isinstance(database.get("packs"), dict)
            and isinstance(database.get("profiles"), dict)
            and "indexes" not in database
        )

    def _load_smart_pack_manifest(self, manifest_path: Path, manifest: Dict[str, Any]) -> None:
        """Load all installed smart-pack indexes as one logical lookup database."""
        pack_indexes: List[Tuple[str, Path, Dict[str, Any]]] = []
        for pack, info in sorted((manifest.get("packs") or {}).items()):
            if not isinstance(info, dict):
                continue
            index_path = self._resolve_manifest_file(manifest_path, info.get("index"))
            if not index_path.exists():
                continue
            try:
                index = self._load_json_file(index_path)
            except Exception as e:
                logger.warning("Could not load hardware EOL pack index %s: %s", index_path, e)
                continue
            if index.get("record_shards") and index.get("record_locations"):
                pack_indexes.append((str(pack), index_path, index))

        if not pack_indexes:
            logger.debug("Hardware EOL smart manifest has no installed packs: %s", manifest_path)
            self._db = {}
            return

        merged_indexes: Dict[str, Any] = {"vendor_aliases": {}}
        merged_summaries: List[Dict[str, Any]] = []
        merged_shards: Dict[str, Any] = {}
        merged_locations: Dict[str, str] = {}
        total_records = 0
        installed_packs = {pack for pack, _, _ in pack_indexes}

        for pack, index_path, index in pack_indexes:
            self._merge_lookup_indexes(merged_indexes, index.get("indexes") or {})
            merged_summaries.extend(index.get("model_summaries") or [])
            for category, shard_info in (index.get("record_shards") or {}).items():
                shard_key = f"{pack}/{category}"
                merged_info = dict(shard_info)
                shard_path = self._resolve_pack_file(index_path, merged_info.get("path"))
                merged_info["path"] = str(shard_path)
                merged_info["pack"] = pack
                merged_info["category"] = category
                merged_shards[shard_key] = merged_info
            for record_id, category in (index.get("record_locations") or {}).items():
                merged_locations[str(record_id)] = f"{pack}/{category}"
            total_records += int((index.get("summary") or {}).get("total_records") or 0)

        for name, value in list(merged_indexes.items()):
            if name in {"vendor_aliases", "by_id"} or not isinstance(value, dict):
                continue
            merged_indexes[name] = {
                key: sorted(dict.fromkeys(ids))
                for key, ids in sorted(value.items())
            }
        merged_indexes["vendor_aliases"] = dict(sorted(merged_indexes["vendor_aliases"].items()))

        self._db = {
            "metadata": {
                "schema": (manifest.get("metadata") or {}).get("source_schema")
                or "sunsetscan.hardware_eol.v1",
                "artifact_layout": {
                    "format": "smart_packs",
                    "pack_count": len(pack_indexes),
                    "manifest": str(manifest_path),
                },
            },
            "summary": {
                "total_records": total_records or len(merged_locations),
                "total_model_summaries": len(merged_summaries),
            },
            "indexes": merged_indexes,
            "model_summaries": merged_summaries,
            "record_shards": merged_shards,
            "record_locations": merged_locations,
        }
        self._db_path = manifest_path
        self._indexes = merged_indexes
        self._records = []
        self._record_positions = {}
        self._record_locations = merged_locations
        self._record_shards = merged_shards
        self._installed_packs = installed_packs
        self._vendor_pack_hints = manifest.get("vendor_pack_hints") or {}
        self._summary_by_key = {}
        for summary in merged_summaries:
            vendor_slug = summary.get("vendor_slug") or ""
            model_key = summary.get("model_key") or ""
            if vendor_slug and model_key:
                self._summary_by_key[f"{vendor_slug}|{model_key}"] = summary

        logger.debug(
            "Hardware EOL smart packs loaded from %s: %d records, %d model summaries, %d packs",
            manifest_path,
            total_records or len(merged_locations),
            len(self._summary_by_key),
            len(pack_indexes),
        )

    @staticmethod
    def _profile_for_pack(pack: str) -> str:
        return {
            "home": "hardware-eol-home",
            "office": "hardware-eol-office",
            "enterprise": "hardware-eol-enterprise",
            "industrial_ot": "hardware-eol-industrial",
            "service_provider": "hardware-eol-service-provider",
        }.get(pack, "hardware-eol-full")

    @staticmethod
    def _merge_lookup_indexes(target: Dict[str, Any], source: Dict[str, Any]) -> None:
        for index_name, index_value in source.items():
            if not isinstance(index_value, dict):
                continue
            if index_name == "vendor_aliases":
                aliases = target.setdefault("vendor_aliases", {})
                aliases.update(index_value)
                continue
            merged = target.setdefault(index_name, {})
            for key, value in index_value.items():
                if index_name == "by_id":
                    merged[str(key)] = value
                elif isinstance(value, list):
                    bucket = merged.setdefault(str(key), [])
                    bucket.extend(str(item) for item in value)

    @staticmethod
    def _resolve_manifest_file(manifest_path: Path, file_info: Any) -> Path:
        if not isinstance(file_info, dict):
            return manifest_path.parent / "__missing__"
        rel_path = str(file_info.get("path") or "")
        path = Path(rel_path)
        if path.is_absolute():
            candidates = [path]
        else:
            candidates = [manifest_path.parent / path]
        for candidate in list(candidates):
            if candidate.suffix == ".gz":
                candidates.append(candidate.with_suffix(""))
            else:
                candidates.append(Path(f"{candidate}.gz"))
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    @staticmethod
    def _resolve_pack_file(index_path: Path, rel_path: Any) -> Path:
        path = Path(str(rel_path or ""))
        if path.is_absolute():
            candidates = [path]
        else:
            candidates = [index_path.parent / path]
        for candidate in list(candidates):
            if candidate.suffix == ".gz":
                candidates.append(candidate.with_suffix(""))
            else:
                candidates.append(Path(f"{candidate}.gz"))
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    def _lookup_record_ids(self, vendor_key: str, model_key: str) -> Tuple[List[str], str]:
        composite = f"{vendor_key}|{model_key}" if vendor_key else ""
        lookup_plan = [
            ("by_vendor_model_key", [composite]),
            ("by_part_key", [composite, model_key]),
            ("by_alias_key", [composite, model_key]),
        ]

        for index_name, keys in lookup_plan:
            index = self._indexes.get(index_name) or {}
            for key in keys:
                if not key:
                    continue
                record_ids = index.get(key)
                if not record_ids:
                    continue
                records = self._records_for_ids(record_ids)
                if vendor_key:
                    records = [
                        r for r in records
                        if (r.get("vendor_slug") or "") == vendor_key
                    ]
                ids = self._ids_for_records(records)
                if ids:
                    return ids, index_name.replace("by_", "").replace("_key", "")

        return [], ""

    def _records_for_ids(self, record_ids: List[str]) -> List[Dict[str, Any]]:
        if self._record_locations:
            return self._records_for_ids_from_shards(record_ids)

        seen = set()
        records: List[Dict[str, Any]] = []
        for record_id in record_ids:
            if record_id in seen:
                continue
            seen.add(record_id)
            pos = self._record_positions.get(record_id)
            if isinstance(pos, int) and 0 <= pos < len(self._records):
                records.append(self._records[pos])
        return records

    def _records_for_ids_from_shards(self, record_ids: List[str]) -> List[Dict[str, Any]]:
        seen = set()
        records: List[Dict[str, Any]] = []
        for record_id in record_ids:
            if record_id in seen:
                continue
            seen.add(record_id)
            category = self._record_locations.get(record_id)
            if not category:
                continue
            record = self._record_from_shard(category, record_id)
            if record:
                records.append(record)
        return records

    def _record_from_shard(self, category: str, record_id: str) -> Optional[Dict[str, Any]]:
        shard = self._load_record_shard(category)
        records = shard.get("records") or []
        positions = shard.get("positions") or {}
        pos = positions.get(record_id)
        if isinstance(pos, int) and 0 <= pos < len(records):
            return records[pos]
        for record in records:
            if str(record.get("id") or "") == record_id:
                return record
        return None

    def _load_record_shard(self, category: str) -> Dict[str, Any]:
        if category in self._shard_cache:
            return self._shard_cache[category]

        info = self._record_shards.get(category) or {}
        rel_path = info.get("path") if isinstance(info, dict) else str(info)
        if not rel_path:
            self._shard_cache[category] = {"records": [], "positions": {}}
            return self._shard_cache[category]

        path = self._resolve_related_path(rel_path)
        try:
            shard_data = self._load_json_file(path)
        except Exception as e:
            logger.warning("Could not load hardware EOL shard %s: %s", path, e)
            self._shard_cache[category] = {"records": [], "positions": {}}
            return self._shard_cache[category]

        records = shard_data.get("records") or []
        positions = (shard_data.get("indexes") or {}).get("by_id") or {}
        if not positions:
            positions = {
                str(record["id"]): pos
                for pos, record in enumerate(records)
                if record.get("id")
            }
        self._shard_cache[category] = {"records": records, "positions": positions}
        return self._shard_cache[category]

    def _resolve_related_path(self, rel_path: str) -> Path:
        path = Path(rel_path)
        if path.is_absolute():
            candidates = [path]
        else:
            base = self._db_path.parent if self._db_path else self.path.parent
            candidate = base / path
            candidates = [candidate]

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

    @staticmethod
    def _ids_for_records(records: List[Dict[str, Any]]) -> List[str]:
        result = []
        for record in records:
            record_id = record.get("id")
            if record_id:
                result.append(str(record_id))
        return result

    def _summary_for(
        self,
        vendor_key: str,
        model_key: str,
        records: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        summary = self._summary_by_key.get(f"{vendor_key}|{model_key}")
        if summary:
            return summary
        if records:
            record = records[0]
            record_vendor = record.get("vendor_slug") or vendor_key
            record_model = record.get("model_key") or model_key
            return self._summary_by_key.get(f"{record_vendor}|{record_model}")
        return None

    def _focus_records(
        self,
        records: List[Dict[str, Any]],
        part_number: str,
        hardware_version: str,
        region: str,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        focused = records
        used_specific_input = False

        part_keys = set(_lookup_key_variants(part_number))
        if part_keys:
            exact_part = [
                r for r in focused
                if part_keys.intersection(_lookup_key_variants(r.get("part_number")))
            ]
            if exact_part:
                focused = exact_part
                used_specific_input = True

        hw_keys = {
            _normalize_version_key(key)
            for key in _lookup_key_variants(hardware_version)
            if _normalize_version_key(key)
        }
        if hw_keys:
            exact_hw = [
                r for r in focused
                if hw_keys.intersection(
                    {
                        _normalize_version_key(key)
                        for key in _lookup_key_variants(r.get("hardware_version"))
                        if _normalize_version_key(key)
                    }
                )
            ]
            if exact_hw:
                focused = exact_hw
                used_specific_input = True

        region_keys = set(_lookup_key_variants(region))
        if region_keys:
            exact_region = [
                r for r in focused
                if region_keys.intersection(_lookup_key_variants(r.get("region")))
            ]
            if exact_region:
                focused = exact_region
                used_specific_input = True

        return focused, used_specific_input

    def _match_from_focused_records(
        self,
        vendor: str,
        model: str,
        vendor_key: str,
        model_key: str,
        match_type: str,
        focused: List[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
    ) -> Optional[HardwareEOLMatch]:
        if not focused:
            return None

        unsupported = [
            r for r in focused
            if (r.get("lifecycle") or {}).get("receives_security_updates") is False
        ]
        supported_or_unknown = [
            r for r in focused
            if (r.get("lifecycle") or {}).get("receives_security_updates") is not False
        ]
        review_records = [
            r for r in focused
            if str((r.get("lifecycle") or {}).get("status") or "") == "lifecycle_review"
        ]

        if unsupported and not supported_or_unknown:
            selected = focused[0] if len(focused) == 1 else None
            status = self._strongest_status(focused)
            risk = self._strongest_risk(focused)
            title = self._finding_title(vendor, model, selected, summary)
            confidence = "high" if selected else "medium"
            return HardwareEOLMatch(
                vendor=vendor,
                model=model,
                canonical_vendor=vendor_key,
                model_key=model_key,
                match_type=match_type,
                status=status,
                risk=risk,
                finding_title=title,
                receives_security_updates=False,
                records=focused,
                selected_record=selected,
                model_summary=summary,
                mixed=False,
                confidence=confidence,
            )

        if unsupported and supported_or_unknown:
            return self._mixed_match(
                vendor, model, vendor_key, model_key, match_type, summary, focused
            )

        if review_records:
            return self._review_match(
                vendor, model, vendor_key, model_key, match_type, summary, review_records
            )

        return None

    def _match_from_summary(
        self,
        vendor: str,
        model: str,
        vendor_key: str,
        model_key: str,
        match_type: str,
        summary: Dict[str, Any],
        records: List[Dict[str, Any]],
    ) -> Optional[HardwareEOLMatch]:
        overall_status = str(summary.get("overall_status") or "")
        receives_updates = summary.get("receives_security_updates")

        if receives_updates is False or overall_status == "unsupported":
            return HardwareEOLMatch(
                vendor=vendor,
                model=model,
                canonical_vendor=vendor_key,
                model_key=model_key,
                match_type=match_type,
                status=overall_status or "unsupported",
                risk=str(summary.get("strongest_risk") or "high"),
                finding_title=self._finding_title(vendor, model, None, summary),
                receives_security_updates=False,
                records=records,
                selected_record=None,
                model_summary=summary,
                mixed=False,
                confidence="medium",
            )

        if overall_status == "mixed":
            return self._mixed_match(
                vendor, model, vendor_key, model_key, match_type, summary, records
            )

        if overall_status == "lifecycle_review":
            return self._review_match(
                vendor, model, vendor_key, model_key, match_type, summary, records
            )

        return None

    def _mixed_match(
        self,
        vendor: str,
        model: str,
        vendor_key: str,
        model_key: str,
        match_type: str,
        summary: Optional[Dict[str, Any]],
        records: List[Dict[str, Any]],
    ) -> HardwareEOLMatch:
        display_vendor = (summary or {}).get("vendor") or vendor or vendor_key
        display_model = (summary or {}).get("model") or model
        title = (
            f"{display_vendor} {display_model} lifecycle varies by "
            "hardware revision or region"
        ).strip()
        risk = str((summary or {}).get("strongest_risk") or self._strongest_risk(records))
        return HardwareEOLMatch(
            vendor=vendor,
            model=model,
            canonical_vendor=vendor_key,
            model_key=model_key,
            match_type=match_type,
            status="mixed",
            risk=risk,
            finding_title=title,
            receives_security_updates=None,
            records=records,
            selected_record=None,
            model_summary=summary,
            mixed=True,
            review_required=False,
            confidence="low",
        )

    def _review_match(
        self,
        vendor: str,
        model: str,
        vendor_key: str,
        model_key: str,
        match_type: str,
        summary: Optional[Dict[str, Any]],
        records: List[Dict[str, Any]],
    ) -> HardwareEOLMatch:
        display_vendor = (summary or {}).get("vendor") or vendor or vendor_key
        display_model = (summary or {}).get("model") or model
        title = f"{display_vendor} {display_model} {_review_title_suffix(records)}".strip()
        return HardwareEOLMatch(
            vendor=vendor,
            model=model,
            canonical_vendor=vendor_key,
            model_key=model_key,
            match_type=match_type,
            status="lifecycle_review",
            risk=str((summary or {}).get("strongest_risk") or self._strongest_risk(records)),
            finding_title=title,
            receives_security_updates=None,
            records=records,
            selected_record=records[0] if len(records) == 1 else None,
            model_summary=summary,
            mixed=False,
            review_required=True,
            confidence="low",
        )

    @staticmethod
    def _finding_title(
        vendor: str,
        model: str,
        record: Optional[Dict[str, Any]],
        summary: Optional[Dict[str, Any]],
    ) -> str:
        if record:
            sunsetscan = record.get("sunsetscan") or record.get("netwatch") or {}
            if sunsetscan.get("finding_title"):
                return str(sunsetscan["finding_title"])
        display_vendor = (summary or {}).get("vendor") or vendor
        display_model = (summary or {}).get("model") or model
        if (summary or {}).get("overall_status") == "lifecycle_review":
            return f"{display_vendor} {display_model} lifecycle review needed".strip()
        return f"{display_vendor} {display_model} no longer receives security updates".strip()

    @staticmethod
    def _strongest_status(records: List[Dict[str, Any]]) -> str:
        order = [
            "unsupported",
            "unsupported_status_only",
            "support_ending_soon",
            "lifecycle_review",
            "vendor_eol_but_supported",
            "end_of_sale",
            "supported",
            "supported_status_only",
            "unknown",
        ]
        found = {
            str((record.get("lifecycle") or {}).get("status") or "unknown")
            for record in records
        }
        for status in order:
            if status in found:
                return status
        return "unknown"

    @staticmethod
    def _strongest_risk(records: List[Dict[str, Any]]) -> str:
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        found = {
            str((record.get("lifecycle") or {}).get("risk") or "unknown")
            for record in records
        }
        for risk in order:
            if risk in found:
                return risk
        return "unknown"
