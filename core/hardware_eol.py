"""
NetWatch hardware end-of-life lookup.

This module reads the hardware lifecycle database installed by the NetWatch
module manager in data/cache/hardware_eol/. It is separate from the software
EOL checker because the source data is vendor hardware lifecycle data, not
endoflife.date cycles.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent
_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "cache" / "hardware_eol" / "netwatch_hardware_eol.json"
_DEVELOPER_DB_PATH = _PROJECT_ROOT / "data" / "hardware_eol" / "netwatch_hardware_eol.json"


def normalize_key(value: Any) -> str:
    """Normalize a vendor, model, part, or alias value for database lookup."""
    if value is None:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def _normalize_version_key(value: Any) -> str:
    key = normalize_key(value)
    if len(key) > 1 and key[0] == "v" and key[1].isdigit():
        return key[1:].strip()
    return key


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
            return str(self.model_summary.get("netwatch_note") or "")
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
        self._db: Optional[Dict[str, Any]] = None
        self._indexes: Dict[str, Any] = {}
        self._records: List[Dict[str, Any]] = []
        self._record_positions: Dict[str, int] = {}
        self._summary_by_key: Dict[str, Dict[str, Any]] = {}

    def available(self) -> bool:
        """Return True if a hardware lifecycle database file exists."""
        return self._candidate_path().exists()

    def canonical_vendor(self, vendor: str) -> str:
        """Normalize and canonicalize a vendor through indexes.vendor_aliases."""
        self._ensure_loaded()
        vendor_key = normalize_key(vendor)
        aliases = self._indexes.get("vendor_aliases") or {}
        return aliases.get(vendor_key, vendor_key)

    def lookup(
        self,
        vendor: str,
        model: str,
        part_number: str = "",
        hardware_version: str = "",
        region: str = "",
    ) -> Optional[HardwareEOLMatch]:
        """Look up hardware lifecycle data for a detected vendor/model.

        Returns a match only when NetWatch should emit a finding: unsupported
        hardware, mixed lifecycle status, or a vendor lifecycle signal that
        needs manual review.
        """
        if not model:
            return None

        self._ensure_loaded()
        if not self._db:
            return None

        vendor_key = self.canonical_vendor(vendor)
        model_key = normalize_key(model)
        if not model_key:
            return None

        record_ids, match_type = self._lookup_record_ids(vendor_key, model_key)
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
            with db_path.open("r", encoding="utf-8") as f:
                self._db = json.load(f)
        except Exception as e:
            logger.warning("Could not load hardware EOL database: %s", e)
            self._db = {}
            return

        self._indexes = self._db.get("indexes") or {}
        self._records = self._db.get("records") or []
        self._record_positions = self._indexes.get("by_id") or {}
        self._summary_by_key = {}
        for summary in self._db.get("model_summaries") or []:
            vendor_slug = summary.get("vendor_slug") or ""
            model_key = summary.get("model_key") or ""
            if vendor_slug and model_key:
                self._summary_by_key[f"{vendor_slug}|{model_key}"] = summary

        logger.debug(
            "Hardware EOL database loaded from %s: %d records, %d model summaries",
            db_path,
            len(self._records),
            len(self._summary_by_key),
        )

    def _candidate_path(self) -> Path:
        if self.path.exists():
            return self.path
        if self.path == _DEFAULT_DB_PATH and _DEVELOPER_DB_PATH.exists():
            return _DEVELOPER_DB_PATH
        return self.path

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

        part_key = normalize_key(part_number)
        if part_key:
            exact_part = [
                r for r in focused
                if normalize_key(r.get("part_number")) == part_key
            ]
            if exact_part:
                focused = exact_part
                used_specific_input = True

        hw_key = _normalize_version_key(hardware_version)
        if hw_key:
            exact_hw = [
                r for r in focused
                if _normalize_version_key(r.get("hardware_version")) == hw_key
            ]
            if exact_hw:
                focused = exact_hw
                used_specific_input = True

        region_key = normalize_key(region)
        if region_key:
            exact_region = [
                r for r in focused
                if normalize_key(r.get("region")) == region_key
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
        title = f"{display_vendor} {display_model} lifecycle review needed".strip()
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
            netwatch = record.get("netwatch") or {}
            if netwatch.get("finding_title"):
                return str(netwatch["finding_title"])
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
