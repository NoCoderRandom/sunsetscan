import gzip
import json

from core.scan_history import (
    HostSnapshot,
    ScanHistory,
    ScanSnapshot,
    _snapshot_to_dict,
)


def _write_snapshot(history_dir, name, snap):
    path = history_dir / f"scan_{name}.json.gz"
    with gzip.open(path, "wb") as handle:
        handle.write(json.dumps(_snapshot_to_dict(snap)).encode("utf-8"))
    return path


def _snapshot(timestamp, target, profile, hosts):
    return ScanSnapshot(
        timestamp=timestamp,
        target=target,
        profile=profile,
        hosts={ip: HostSnapshot(ip=ip) for ip in hosts},
    )


def test_diff_last_two_uses_latest_matching_target_and_profile(tmp_path):
    history = ScanHistory(history_dir=tmp_path)
    _write_snapshot(
        tmp_path,
        "one_old",
        _snapshot("2026-05-11T10:00:00+00:00", "192.168.1.0/24", "QUICK", ["192.168.1.1"]),
    )
    _write_snapshot(
        tmp_path,
        "other_interleaved",
        _snapshot("2026-05-11T10:01:00+00:00", "10.0.0.0/24", "QUICK", ["10.0.0.1"]),
    )
    _write_snapshot(
        tmp_path,
        "one_latest",
        _snapshot(
            "2026-05-11T10:02:00+00:00",
            "192.168.1.0/24",
            "QUICK",
            ["192.168.1.1", "192.168.1.115"],
        ),
    )

    diff = history.diff_last_two()

    assert diff is not None
    assert diff.older_target == "192.168.1.0/24"
    assert diff.newer_target == "192.168.1.0/24"
    assert diff.older_profile == "QUICK"
    assert diff.new_hosts == ["192.168.1.115"]
    assert diff.removed_hosts == []


def test_diff_last_two_returns_none_without_matching_target_and_profile(tmp_path):
    history = ScanHistory(history_dir=tmp_path)
    _write_snapshot(
        tmp_path,
        "quick",
        _snapshot("2026-05-11T10:00:00+00:00", "192.168.1.0/24", "QUICK", ["192.168.1.1"]),
    )
    _write_snapshot(
        tmp_path,
        "full",
        _snapshot("2026-05-11T10:01:00+00:00", "192.168.1.0/24", "FULL", ["192.168.1.1"]),
    )

    assert history.diff_last_two() is None
