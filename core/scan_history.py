"""
NetWatch Scan History & Diff Module.

Saves compressed scan snapshots to data/history/ and can diff any two
snapshots to show what changed between scans (new hosts, closed ports,
new/resolved findings, changed versions).

Retention: 90 days. Older snapshots are pruned automatically on save.

Exports:
    ScanHistory: Main class
    ScanDiff: Dataclass with diff results
"""

import gzip
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_HISTORY_DIR = Path(__file__).parent.parent / "data" / "history"
_RETENTION_DAYS = 90


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HostSnapshot:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    ports: Dict[int, dict] = field(default_factory=dict)  # port → {service, version, state}
    finding_titles: List[str] = field(default_factory=list)


@dataclass
class ScanSnapshot:
    timestamp: str          # ISO-8601
    target: str
    profile: str
    hosts: Dict[str, HostSnapshot] = field(default_factory=dict)
    finding_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScanDiff:
    """Differences between two scan snapshots."""
    older_ts: str
    newer_ts: str
    new_hosts: List[str] = field(default_factory=list)
    removed_hosts: List[str] = field(default_factory=list)
    new_ports: List[Tuple[str, int]] = field(default_factory=list)   # (ip, port)
    closed_ports: List[Tuple[str, int]] = field(default_factory=list)
    version_changes: List[dict] = field(default_factory=list)        # {ip, port, old, new}
    new_findings: List[str] = field(default_factory=list)            # titles unique to newer
    resolved_findings: List[str] = field(default_factory=list)       # titles in older, gone now

    @property
    def has_changes(self) -> bool:
        return any([
            self.new_hosts, self.removed_hosts,
            self.new_ports, self.closed_ports,
            self.version_changes, self.new_findings, self.resolved_findings,
        ])

    def summary_lines(self) -> List[str]:
        lines = []
        if self.new_hosts:
            lines.append(f"New devices detected: {', '.join(self.new_hosts)}")
        if self.removed_hosts:
            lines.append(f"Devices no longer visible: {', '.join(self.removed_hosts)}")
        if self.new_ports:
            ps = [f"{ip}:{p}" for ip, p in self.new_ports]
            lines.append(f"New open ports: {', '.join(ps)}")
        if self.closed_ports:
            ps = [f"{ip}:{p}" for ip, p in self.closed_ports]
            lines.append(f"Closed ports: {', '.join(ps)}")
        if self.version_changes:
            for vc in self.version_changes:
                lines.append(f"Version change {vc['ip']}:{vc['port']} — {vc['old']} → {vc['new']}")
        if self.new_findings:
            lines.append(f"New findings ({len(self.new_findings)}): {', '.join(self.new_findings[:5])}")
        if self.resolved_findings:
            lines.append(f"Resolved findings ({len(self.resolved_findings)}): {', '.join(self.resolved_findings[:5])}")
        if not lines:
            lines.append("No changes detected since last scan.")
        return lines


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _snapshot_to_dict(snap: ScanSnapshot) -> dict:
    return {
        "timestamp": snap.timestamp,
        "target": snap.target,
        "profile": snap.profile,
        "finding_counts": snap.finding_counts,
        "hosts": {
            ip: {
                "ip": hs.ip,
                "hostname": hs.hostname,
                "os_guess": hs.os_guess,
                "ports": {str(p): v for p, v in hs.ports.items()},
                "finding_titles": hs.finding_titles,
            }
            for ip, hs in snap.hosts.items()
        },
    }


def _dict_to_snapshot(d: dict) -> ScanSnapshot:
    hosts = {}
    for ip, hd in d.get("hosts", {}).items():
        ports = {int(p): v for p, v in hd.get("ports", {}).items()}
        hosts[ip] = HostSnapshot(
            ip=hd.get("ip", ip),
            hostname=hd.get("hostname", ""),
            os_guess=hd.get("os_guess", ""),
            ports=ports,
            finding_titles=hd.get("finding_titles", []),
        )
    return ScanSnapshot(
        timestamp=d["timestamp"],
        target=d.get("target", ""),
        profile=d.get("profile", ""),
        hosts=hosts,
        finding_counts=d.get("finding_counts", {}),
    )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ScanHistory:
    """Persist and query scan snapshots.

    Usage:
        history = ScanHistory()
        history.save(scan_result, finding_registry, target="192.168.1.0/24")

        # List saved scans
        snaps = history.list_snapshots()

        # Diff last two scans
        diff = history.diff_last_two()

        # Diff against scans from at least N days ago
        diff = history.diff_since_days(7)
    """

    def __init__(self, history_dir: Optional[Path] = None):
        self.history_dir = history_dir or _HISTORY_DIR
        self.history_dir.mkdir(parents=True, exist_ok=True)

    # ---- Saving -----------------------------------------------------------

    def save(self, scan_result, finding_registry=None, target: str = "") -> Path:
        """Save a scan snapshot.  Returns the path of the saved file."""
        from core.scanner import ScanResult  # local import to avoid circular
        snap = self._build_snapshot(scan_result, finding_registry, target)
        ts = snap.timestamp.replace(":", "-").replace(".", "-")
        fname = self.history_dir / f"scan_{ts}.json.gz"
        data = json.dumps(_snapshot_to_dict(snap), indent=None).encode("utf-8")
        with gzip.open(fname, "wb") as f:
            f.write(data)
        logger.info(f"Scan history saved: {fname}")
        self._prune_old()
        return fname

    def _build_snapshot(self, scan_result, finding_registry, target: str) -> ScanSnapshot:
        ts = datetime.now(timezone.utc).isoformat()
        profile = getattr(scan_result, "profile", "")
        snap = ScanSnapshot(timestamp=ts, target=target or getattr(scan_result, "target", ""), profile=profile)

        for ip, host in scan_result.hosts.items():
            ports = {}
            for port_num, port_info in host.ports.items():
                ports[port_num] = {
                    "service": getattr(port_info, "service", ""),
                    "version": getattr(port_info, "version", ""),
                    "state": getattr(port_info, "state", "open"),
                }
            snap.hosts[ip] = HostSnapshot(
                ip=ip,
                hostname=getattr(host, "hostname", ""),
                os_guess=getattr(host, "os_guess", ""),
                ports=ports,
            )

        if finding_registry:
            snap.finding_counts = finding_registry.counts()
            for f in finding_registry.get_all(sort=False):
                if f.host in snap.hosts:
                    snap.hosts[f.host].finding_titles.append(f.title)

        return snap

    # ---- Loading ----------------------------------------------------------

    def list_snapshots(self) -> List[Tuple[datetime, Path]]:
        """Return list of (datetime, path) sorted oldest-first."""
        result = []
        for p in self.history_dir.glob("scan_*.json.gz"):
            try:
                with gzip.open(p, "rb") as f:
                    d = json.loads(f.read())
                ts = datetime.fromisoformat(d["timestamp"])
                result.append((ts, p))
            except Exception:
                pass
        return sorted(result, key=lambda x: x[0])

    def load_snapshot(self, path: Path) -> Optional[ScanSnapshot]:
        try:
            with gzip.open(path, "rb") as f:
                d = json.loads(f.read())
            return _dict_to_snapshot(d)
        except Exception as e:
            logger.error(f"Could not load snapshot {path}: {e}")
            return None

    # ---- Diffing ----------------------------------------------------------

    def diff(self, older: ScanSnapshot, newer: ScanSnapshot) -> ScanDiff:
        d = ScanDiff(older_ts=older.timestamp, newer_ts=newer.timestamp)

        old_hosts = set(older.hosts.keys())
        new_hosts = set(newer.hosts.keys())
        d.new_hosts = sorted(new_hosts - old_hosts)
        d.removed_hosts = sorted(old_hosts - new_hosts)

        for ip in old_hosts & new_hosts:
            old_ports = set(p for p, v in older.hosts[ip].ports.items() if v.get("state") == "open")
            new_ports_set = set(p for p, v in newer.hosts[ip].ports.items() if v.get("state") == "open")
            for p in new_ports_set - old_ports:
                d.new_ports.append((ip, p))
            for p in old_ports - new_ports_set:
                d.closed_ports.append((ip, p))
            # Version changes
            for p in old_ports & new_ports_set:
                old_v = older.hosts[ip].ports.get(p, {}).get("version", "")
                new_v = newer.hosts[ip].ports.get(p, {}).get("version", "")
                if old_v and new_v and old_v != new_v:
                    d.version_changes.append({"ip": ip, "port": p, "old": old_v, "new": new_v})

        old_titles = set(t for hs in older.hosts.values() for t in hs.finding_titles)
        new_titles = set(t for hs in newer.hosts.values() for t in hs.finding_titles)
        d.new_findings = sorted(new_titles - old_titles)
        d.resolved_findings = sorted(old_titles - new_titles)

        return d

    def diff_last_two(self) -> Optional[ScanDiff]:
        snaps = self.list_snapshots()
        if len(snaps) < 2:
            return None
        older = self.load_snapshot(snaps[-2][1])
        newer = self.load_snapshot(snaps[-1][1])
        if older and newer:
            return self.diff(older, newer)
        return None

    def diff_since_days(self, days: int) -> Optional[ScanDiff]:
        """Diff latest snapshot against the oldest one at least `days` ago."""
        snaps = self.list_snapshots()
        if not snaps:
            return None
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        older_candidates = [(ts, p) for ts, p in snaps if ts.replace(tzinfo=timezone.utc) <= cutoff]
        if not older_candidates:
            older_candidates = [snaps[0]]
        older = self.load_snapshot(older_candidates[-1][1])
        newer = self.load_snapshot(snaps[-1][1])
        if older and newer:
            return self.diff(older, newer)
        return None

    def history_table(self) -> List[dict]:
        """Return list of snapshot metadata for display."""
        rows = []
        for ts, p in self.list_snapshots():
            snap = self.load_snapshot(p)
            if snap:
                counts = snap.finding_counts
                rows.append({
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M"),
                    "target": snap.target,
                    "profile": snap.profile,
                    "hosts": len(snap.hosts),
                    "critical": counts.get("CRITICAL", 0),
                    "high": counts.get("HIGH", 0),
                    "medium": counts.get("MEDIUM", 0),
                    "low": counts.get("LOW", 0),
                    "file": str(p.name),
                })
        return rows

    # ---- Pruning ----------------------------------------------------------

    def _prune_old(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)
        for ts, p in self.list_snapshots():
            aware_ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            if aware_ts < cutoff:
                try:
                    p.unlink()
                    logger.debug(f"Pruned old snapshot: {p}")
                except Exception:
                    pass
