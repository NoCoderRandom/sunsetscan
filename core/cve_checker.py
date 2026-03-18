"""
NetWatch CVE Checker Module.

Provides scan-time CVE lookups against the local cache ONLY.
Never calls any external API during a scan.

For building or refreshing the CVE cache, use CVECacheBuilder —
which is called by `python netwatch.py --setup` and `--update-cache`.

Data sources (cache-build time only):
    PRIMARY:   OSV.dev batch API (no key, no rate limits)
    FALLBACK:  NVD API (6-second mandatory delay between requests)

Severity mapping from CVSS v3 base score:
    >= 9.0  -> CRITICAL
    >= 7.0  -> HIGH
    >= 4.0  -> MEDIUM
    < 4.0   -> LOW
    no score -> MEDIUM (conservative default)
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.cache_manager import UnifiedCacheManager
from core.findings import Finding, Severity

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------
# CVSS score to Severity mapping
# -------------------------------------------------------------------------

def _cvss_to_severity(cvss: Optional[float]) -> Severity:
    """Map a CVSS base score to a Severity level."""
    if cvss is None:
        return Severity.MEDIUM  # Conservative default when score is unknown
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# -------------------------------------------------------------------------
# Scan-time checker (cache reads only)
# -------------------------------------------------------------------------

class CVEChecker:
    """Scan-time CVE lookup — reads from local cache only.

    Usage:
        checker = CVEChecker(cache)
        findings = checker.check(
            host="192.168.1.1",
            product="openssh",
            version="7.4",
            port=22,
        )
    """

    def __init__(self, cache: Optional[UnifiedCacheManager] = None):
        self.cache = cache or UnifiedCacheManager()

    def check(
        self,
        host: str,
        product: str,
        version: str,
        port: int = 0,
        protocol: str = "tcp",
        max_results: int = 5,
    ) -> List[Finding]:
        """Look up CVEs for a product:version from local cache.

        Returns a list of Finding objects (may be empty).
        Never raises — returns [] on any error.
        """
        if not product or not version:
            return []

        # Skip non-meaningful version strings
        if version.lower() in ("unknown", "", "0", "none", "-"):
            return []

        raw_vulns = self.cache.get_cve(product, version)
        if raw_vulns is None:
            logger.debug(f"CVE cache miss for {product}:{version} — run --setup")
            return []

        if not raw_vulns:
            return []

        # Sort by CVSS score descending and cap at max_results
        sorted_vulns = sorted(
            raw_vulns,
            key=lambda v: v.get("cvss_v3") or 0.0,
            reverse=True,
        )[:max_results]

        findings: List[Finding] = []
        for vuln in sorted_vulns:
            cvss = vuln.get("cvss_v3")
            sev = _cvss_to_severity(cvss)
            cve_id = vuln.get("id", "UNKNOWN-CVE")
            summary = vuln.get("summary", "No description available")
            fixed_in = vuln.get("fixed_in")

            cvss_str = f"CVSS {cvss:.1f}" if cvss is not None else "no CVSS score"
            fix_text = (
                f"Update {product} to version {fixed_in} or later. "
                "Check your device vendor's support site for firmware updates."
            ) if fixed_in else (
                f"Update {product} to the latest available version. "
                "Check your device vendor's support site for firmware updates."
            )

            finding = Finding(
                severity=sev,
                title=f"Known vulnerability: {cve_id} in {product} {version}",
                host=host,
                port=port,
                protocol=protocol,
                category="Known Vulnerabilities (CVE)",
                description=(
                    f"{cve_id} affects {product} {version} ({cvss_str}). "
                    f"{summary}"
                ),
                explanation=(
                    f"A publicly known security vulnerability exists in the version of "
                    f"{product} detected on this device. This vulnerability has been "
                    f"disclosed publicly, meaning attackers know about it and may have "
                    f"tools to exploit it."
                ),
                recommendation=fix_text,
                evidence=f"Detected service: {product} {version}",
                cve_ids=[cve_id],
                cvss_score=cvss,
                tags=["cve", product.lower()],
            )
            findings.append(finding)

        return findings

    def cache_age_warning(self) -> Optional[str]:
        """Return a warning string if the CVE cache is stale or missing."""
        age = self.cache.get_cve_cache_age_days()
        if age is None:
            return "CVE cache not found — run: python netwatch.py --setup"
        if not self.cache.is_cve_cache_current():
            return (
                f"CVE data is {age} days old — "
                "run: python netwatch.py --update-cache"
            )
        return None


# -------------------------------------------------------------------------
# Cache builder (called by --setup and --update-cache only)
# -------------------------------------------------------------------------

class CVECacheBuilder:
    """Builds and refreshes the local CVE cache from OSV.dev.

    This class is ONLY used by the --setup and --update-cache commands.
    It is never instantiated during a normal scan.

    Strategy:
        1. Query OSV.dev batch API for all tracked product:version pairs.
        2. Cache results in data/cache/cve_cache.json.
        3. Use NVD API only as a last-resort fallback, with mandatory 6s delay.
    """

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_DELAY_SECONDS = 6

    # Maps NetWatch product slugs to (OSV ecosystem, package name) tuples.
    # Multiple entries per product = we try the first one that returns results.
    OSV_ECOSYSTEMS: Dict[str, List[Tuple[str, str]]] = {
        "openssh": [("Alpine", "openssh"), ("Debian", "openssh")],
        "openssl": [("Alpine", "openssl"), ("Debian", "openssl")],
        "apache-http-server": [("Debian", "apache2"), ("Alpine", "apache2")],
        "nginx": [("Alpine", "nginx"), ("Debian", "nginx")],
        "samba": [("Debian", "samba"), ("Alpine", "samba")],
        "vsftpd": [("Debian", "vsftpd"), ("Alpine", "vsftpd")],
        "proftpd": [("Debian", "proftpd")],
        "php": [("Alpine", "php"), ("Debian", "php8.2"), ("Debian", "php7.4")],
        "mysql": [("Debian", "mysql-server"), ("Alpine", "mysql")],
        "mariadb": [("Debian", "mariadb-server"), ("Alpine", "mariadb")],
        "postgresql": [("Debian", "postgresql"), ("Alpine", "postgresql")],
        "redis": [("Alpine", "redis"), ("Debian", "redis")],
        "mongodb": [("Debian", "mongodb")],
        "tomcat": [("Debian", "tomcat9"), ("Debian", "tomcat10")],
        "lighttpd": [("Alpine", "lighttpd"), ("Debian", "lighttpd")],
        "postfix": [("Debian", "postfix"), ("Alpine", "postfix")],
        "exim": [("Debian", "exim4")],
        "dovecot": [("Debian", "dovecot-core"), ("Alpine", "dovecot")],
        "bind": [("Debian", "bind9"), ("Alpine", "bind")],
        "curl": [("Alpine", "curl"), ("Debian", "curl")],
        "git": [("Alpine", "git"), ("Debian", "git")],
        "dropbear": [("Alpine", "dropbear"), ("Debian", "dropbear-bin")],
        "libssh": [("Debian", "libssh-4"), ("Alpine", "libssh")],
        "openvpn": [("Debian", "openvpn"), ("Alpine", "openvpn")],
        "squid": [("Debian", "squid"), ("Alpine", "squid")],
        "haproxy": [("Debian", "haproxy"), ("Alpine", "haproxy")],
        "wordpress": [("Packagist", "roots/wordpress")],
        "drupal": [("Packagist", "drupal/core")],
        "jenkins": [("Maven", "org.jenkins-ci.main:jenkins-core")],
    }

    def __init__(self, cache: Optional[UnifiedCacheManager] = None):
        self.cache = cache or UnifiedCacheManager()
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "NetWatch/1.1.0 (+https://github.com/netwatch)",
        })

    def build_cache(
        self,
        product_version_pairs: List[Tuple[str, str]],
        progress_callback=None,
    ) -> int:
        """Query OSV for all product:version pairs and persist results.

        Args:
            product_version_pairs: List of (product_slug, version) tuples.
            progress_callback: Optional callable(current, total, message).

        Returns:
            Total number of CVE entries cached.
        """
        total = len(product_version_pairs)
        cve_count = 0
        batch_size = 20

        for batch_start in range(0, total, batch_size):
            batch = product_version_pairs[batch_start: batch_start + batch_size]

            if progress_callback:
                msg = f"Querying OSV (batch {batch_start // batch_size + 1} of {(total + batch_size - 1) // batch_size})"
                progress_callback(batch_start, total, msg)

            try:
                results = self._query_osv_batch(batch)
            except Exception as e:
                logger.warning(f"OSV batch query failed, skipping batch: {e}")
                results = [[] for _ in batch]

            for (product, version), vulns in zip(batch, results):
                self.cache.set_cve(product, version, vulns, source="osv")
                cve_count += len(vulns)

        if progress_callback:
            progress_callback(total, total, "OSV queries complete")

        self.cache.mark_cve_updated()
        logger.info(f"CVE cache built: {cve_count} vulnerabilities across {total} product:version pairs")
        return cve_count

    def _query_osv_batch(self, pairs: List[Tuple[str, str]]) -> List[List[Dict]]:
        """Query OSV batch endpoint for a list of (product, version) pairs.

        Returns a list parallel to `pairs`, each element being a list of
        parsed vulnerability dicts.
        """
        queries: List[Dict] = []
        for product, version in pairs:
            eco_packages = self.OSV_ECOSYSTEMS.get(product)
            if eco_packages:
                ecosystem, pkg_name = eco_packages[0]
                queries.append({
                    "version": version,
                    "package": {"name": pkg_name, "ecosystem": ecosystem},
                })
            else:
                # Generic fallback: try Alpine ecosystem with product name
                queries.append({
                    "version": version,
                    "package": {"name": product, "ecosystem": "Alpine"},
                })

        try:
            response = self.session.post(
                self.OSV_BATCH_URL,
                json={"queries": queries},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.error(f"OSV API request failed: {e}")
            return [[] for _ in pairs]

        results: List[List[Dict]] = []
        for result_entry in data.get("results", []):
            vulns = [
                parsed
                for v in result_entry.get("vulns", [])
                for parsed in [self._parse_osv_vuln(v)]
                if parsed is not None
            ]
            results.append(vulns)

        # Pad in case the API returned fewer entries than we sent
        while len(results) < len(pairs):
            results.append([])

        return results

    def _parse_osv_vuln(self, vuln: Dict) -> Optional[Dict]:
        """Extract the fields we care about from an OSV record."""
        vuln_id = vuln.get("id", "")
        if not vuln_id:
            return None

        summary = vuln.get("summary") or (vuln.get("details") or "")[:200]

        # Extract numeric CVSS score from severity array
        cvss: Optional[float] = None
        for sev_entry in vuln.get("severity", []):
            score_raw = sev_entry.get("score", "")
            try:
                score_str = str(score_raw)
                # CVSS vector strings contain "/" — skip those, only want numeric
                if "/" not in score_str and score_str:
                    cvss = float(score_str)
                    break
            except (ValueError, TypeError):
                pass

        # Also check database_specific in affected entries
        if cvss is None:
            for affected in vuln.get("affected", []):
                db = affected.get("database_specific", {})
                for key in ("cvss", "cvss_score", "severity_score"):
                    if key in db:
                        try:
                            cvss = float(db[key])
                            break
                        except (ValueError, TypeError):
                            pass
                if cvss is not None:
                    break

        # Extract earliest fix version
        fixed_in: Optional[str] = None
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_in = event["fixed"]
                        break
                if fixed_in:
                    break
            if fixed_in:
                break

        # Prefer a CVE alias over the OSV ID
        cve_id = vuln_id
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        references = [
            r.get("url", "") for r in vuln.get("references", [])[:3] if r.get("url")
        ]

        return {
            "id": cve_id,
            "osv_id": vuln_id,
            "summary": (summary[:300] if summary else "No description available"),
            "cvss_v3": cvss,
            "fixed_in": fixed_in,
            "published": (vuln.get("published") or "")[:10],
            "references": references,
        }

    def fetch_nvd_fallback(self, cve_id: str) -> Optional[Dict]:
        """Fetch a specific CVE from NVD as a last resort.

        Enforces a mandatory 6-second delay before the request to respect
        NVD rate limits. Only call this for CVE IDs not found in OSV.
        """
        logger.info(f"NVD fallback: waiting {self.NVD_DELAY_SECONDS}s before fetching {cve_id}")
        time.sleep(self.NVD_DELAY_SECONDS)

        try:
            response = requests.get(
                self.NVD_URL,
                params={"cveId": cve_id},
                timeout=30,
                headers={"User-Agent": "NetWatch/1.1.0"},
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.error(f"NVD fallback request failed for {cve_id}: {e}")
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get("cve", {})

        # Extract CVSS score (prefer v3.1, fall back through v3.0, v2)
        cvss: Optional[float] = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve_data.get("metrics", {}).get(metric_key, [])
            if metrics:
                try:
                    cvss = float(metrics[0]["cvssData"]["baseScore"])
                    break
                except (KeyError, ValueError, TypeError):
                    pass

        # English description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        return {
            "id": cve_id,
            "osv_id": cve_id,
            "summary": description[:300] if description else "No description available",
            "cvss_v3": cvss,
            "fixed_in": None,
            "published": (cve_data.get("published") or "")[:10],
            "references": [],
        }
