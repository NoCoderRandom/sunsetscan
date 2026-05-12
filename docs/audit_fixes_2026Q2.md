# Audit remediation summary — April 2026

## Shipped

- **Prompt 01**: Rewired EOL cache from monolithic `eol_cache.json` to per-product files via `eol/cache.py` CacheManager. Added `core/data_loader.py` and externalized hardcoded maps (`_IDENTITY_EOL_MAP`, `_SSH_CVE_PATTERNS`, `_UBUNTU_SSH_RELEASE_MAP`) to `data/*.json`.
- **Prompt 02**: Fixed identity fusion so chassis identity (router/vendor/model) is not overwritten by HTTP server banners. Deduplicated EOL findings per product. Fixed thread pool sizing in scanner.
- **Prompt 03**: Hardened `config/settings.py`, `core/findings.py`, `core/host_capability.py`, and `core/identity_fusion.py` with type safety and edge-case fixes.
- **Prompt 04**: Mechanical cleanup — CRLF normalization, dead code removal (wildcard check, unreachable regexes, self-assignment), typo fixes.
- **Prompt 05**: Rendered fused identities in reports, recognised AirTunes `am` model TXT, Apple Remote Pairing TXT, preferred avahi-browse over zeroconf for mDNS.
- **Prompt 06**: Removed orphaned methods (`SunsetScan.recheck_eol`, `CacheManager.cleanup_expired`, `EOLChecker.refresh_cache`, `RiskScorer.network_summary`). Slimmed `core/__init__.py` to stable public API only. Fixed setup wizard summary to read EOL stats from per-product cache.
- **May validation pass**: Added root-assisted validation collection, bounded
  safe-mode nmap/masscan behavior, discovery-limited full-assessment port
  scans, timeout recovery with discovery-only reports, and report wording that
  separates network-level checks from per-device findings.
- **May TUI/auth safety pass**: Rewired guided `-i` scans to the shared scanner
  path and changed default credential testing to an opt-in, exact-model,
  rate-limited audit with lockout detection. Full assessments no longer enable
  credential checks automatically.

## Deferred

- Gateway identity-vs-banner test (Step 4): WSL2 virtual NAT adapter does not expose services; requires a real LAN router for full verification.
- Regression diff (Step 7): No `/tmp/before.txt` baseline from prompt 05 was available.
- 67 pre-existing pyflakes warnings (unused imports, empty f-strings): out of scope for this audit series.
- 103 pre-existing `print()` calls across the codebase: migration to `logger`/Rich console deferred.

## Follow-ups

- `UpdateManager.update_cache` was already removed before prompt 06; only the docstring reference remained (cleaned up).
- `core/risk_scorer.py` still imports `Severity` without using it (pre-existing).
- Consider adding a menu binding for EOL recheck if the feature is wanted (the orphaned `recheck_eol` was removed; a new implementation would be needed).
