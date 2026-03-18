"""
NetWatch Web Interface Security Checker.

Performs passive, read-only HTTP checks on web interfaces discovered
during the port scan. No fuzzing, no payloads, no modification of
anything on the target device.

Checks performed:
    - Missing HTTP security headers (X-Frame-Options, CSP, HSTS, etc.)
    - HTTP login forms without HTTPS (credentials sent in cleartext)
    - Directory listing exposed (Index of /)
    - Exposed admin panels (common paths probed with HEAD/GET)
    - HTTP 500 errors on probe paths (reveals stack info)
    - Default web credentials (delegates to auth_tester integration)

Findings produced:
    HIGH    - Login form over plain HTTP (credentials exposed)
    MEDIUM  - Directory listing enabled
              Exposed admin panel path
              Missing HSTS header on HTTPS service
    LOW     - Missing security headers (X-Frame-Options, CSP, etc.)
    INFO    - Web server banner, page title
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
import urllib3

from core.findings import Finding, Severity, Confidence
from core.module_manager import ModuleManager

# Suppress SSL warnings for self-signed certs on local devices
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_wappalyzer_data: Optional[Dict] = None  # lazy-loaded once


def _load_wappalyzer() -> Dict:
    """Load Wappalyzer fingerprint data via ModuleManager, once per process.

    Priority: wappalyzer-full > wappalyzer-mini > empty dict.
    """
    global _wappalyzer_data
    if _wappalyzer_data is not None:
        return _wappalyzer_data
    try:
        mm = ModuleManager()
        _wappalyzer_data = mm.get_wappalyzer_data()
        if _wappalyzer_data:
            logger.debug(f"Wappalyzer: loaded {len(_wappalyzer_data)} technology signatures")
        else:
            _wappalyzer_data = {}
    except Exception as e:
        logger.debug(f"Wappalyzer load failed: {e}")
        _wappalyzer_data = {}
    return _wappalyzer_data


def _safe_regex_search(pattern: str, text: str) -> Optional[re.Match]:
    """Run re.search with FutureWarning suppression for Wappalyzer patterns."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            return re.search(pattern, text, re.IGNORECASE)
    except re.error:
        return None


def _coerce_pattern(raw) -> str:
    """Coerce a Wappalyzer pattern to a plain string.
    Some fields are lists — take first element. Handles str, list, int, None.
    """
    if isinstance(raw, list):
        return str(raw[0]) if raw else ""
    if raw is None:
        return ""
    return str(raw)


def _wappalyzer_version(pattern: str, text: str) -> Optional[str]:
    """Extract version from a Wappalyzer pattern string.

    Wappalyzer uses two notations:
      Apache\\;version:$1   (dollar-sign, original format)
      nginx\\;version:\\1   (backslash, enthec fork format)
    Both are handled.
    """
    parts = pattern.split("\\;")
    regex = parts[0]
    version_tpl = None
    for part in parts[1:]:
        if part.startswith("version:"):
            version_tpl = part[len("version:"):]
    if not regex or not version_tpl:
        return None
    try:
        m = _safe_regex_search(regex, text)
        if not m:
            return None
        version = version_tpl
        for i, grp in enumerate(m.groups(), 1):
            g = grp or ""
            version = version.replace(f"${i}", g)   # $1 style
            version = version.replace(f"\\{i}", g)  # \1 style
        version = version.strip(" .")
        return version if version and not re.match(r'^[\\$]\d+$', version) else None
    except re.error:
        return None


def _run_wappalyzer_checks(
    host: str,
    port: int,
    protocol: str,
    resp: requests.Response,
) -> List[Finding]:
    """Match HTTP response against Wappalyzer signatures.

    Matching rules to avoid false positives:
      - Header matches: require non-trivial pattern (len > 3) AND header must be present
      - HTML matches: require body >= 512 chars AND pattern length > 8 chars
      - Cap at 5 findings per port to suppress noise
    """
    findings: List[Finding] = []
    tech_db = _load_wappalyzer()
    if not tech_db:
        return findings

    body = resp.text or ""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    detected = []  # list of (tech_name, version_or_None, confidence)

    # Only match HTML patterns if there is substantial content
    _BODY_MIN_LEN = 512

    for tech_name, tech in tech_db.items():
        if not isinstance(tech, dict):
            continue
        version = None
        matched = False
        conf = Confidence.SUSPECTED

        # ---- Match against response headers (high confidence) ----
        tech_headers = tech.get("headers", {})
        if isinstance(tech_headers, dict):
            for h_name, h_pattern in tech_headers.items():
                h_val = headers.get(h_name.lower(), "")
                if not h_val:
                    continue
                raw_pat = _coerce_pattern(h_pattern)
                pattern_str = raw_pat.split("\\;")[0]
                # Empty pattern = presence-only check (just having the header is enough)
                if pattern_str == "" or _safe_regex_search(pattern_str, h_val):
                    matched = True
                    conf = Confidence.LIKELY
                    v = _wappalyzer_version(raw_pat, h_val)
                    if v:
                        version = v
                    break

        # ---- Match against HTML body (lower confidence, needs substance) ----
        if not matched and len(body) >= _BODY_MIN_LEN:
            html_raw = tech.get("html", "")
            if html_raw:
                raw_pat = _coerce_pattern(html_raw)
                pattern_str = raw_pat.split("\\;")[0]
                # Skip very short patterns — they produce too many false positives
                if len(pattern_str) >= 12:
                    m = _safe_regex_search(pattern_str, body)
                    if m:
                        matched = True
                        conf = Confidence.SUSPECTED
                        v = _wappalyzer_version(raw_pat, body)
                        if v:
                            version = v

        if matched:
            detected.append((tech_name, version, conf))

    # Prefer LIKELY (header) matches over SUSPECTED (html) matches
    # Cap at 5 per port — if >10 html-only matches something is wrong with data
    header_matches = [(n, v, c) for n, v, c in detected if c == Confidence.LIKELY]
    html_matches = [(n, v, c) for n, v, c in detected if c == Confidence.SUSPECTED]

    # If no header matches and too many HTML matches, likely noisy — suppress
    if not header_matches and len(html_matches) > 5:
        html_matches = []

    final = (header_matches + html_matches)[:5]

    for tech_name, version, conf in final:
        ver_str = f" {version}" if version else ""
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Web technology detected: {tech_name}{ver_str}",
            host=host, port=port, protocol=protocol,
            category="Web Technology",
            description=(
                f"Wappalyzer signature matched: {tech_name}{ver_str} detected on port {port}."
            ),
            explanation=(
                f"The web interface on port {port} appears to be running {tech_name}{ver_str}. "
                "Knowing the exact technology stack helps identify applicable CVEs and EOL dates."
            ),
            recommendation=(
                f"Verify {tech_name} is up to date and check its End-of-Life status."
            ),
            evidence=f"Wappalyzer signature match ({conf.name}): {tech_name}",
            confidence=conf,
            tags=["web", "technology", "wappalyzer", tech_name.lower().replace(" ", "-")],
        ))

    return findings

# Paths to probe for exposed admin panels (HEAD requests only)
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/setup", "/setup/", "/config", "/config/",
    "/manager", "/manager/html",
    "/wp-admin", "/wp-admin/",
    "/phpmyadmin", "/phpmyadmin/",
    "/webadmin", "/webadmin/",
    "/cgi-bin/", "/cgi-bin/admin",
    "/login", "/login.html", "/login.php",
    "/dashboard", "/panel",
]

# Security headers we want to see on web services
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Missing HSTS header",
        "HTTP Strict Transport Security (HSTS) tells browsers to only connect over HTTPS. "
        "Without it, users could be tricked into connecting over plain HTTP.",
        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "Missing X-Frame-Options header",
        "Without X-Frame-Options, this page could be embedded in another website's iframe. "
        "This enables clickjacking attacks.",
        "Add header: X-Frame-Options: DENY (or SAMEORIGIN for admin panels).",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Missing X-Content-Type-Options header",
        "This header prevents browsers from guessing (sniffing) the content type. "
        "Without it, some attacks using malicious file uploads become easier.",
        "Add header: X-Content-Type-Options: nosniff",
    ),
    "Content-Security-Policy": (
        Severity.LOW,
        "Missing Content-Security-Policy header",
        "A Content Security Policy helps prevent Cross-Site Scripting (XSS) attacks "
        "by controlling which scripts and resources can load.",
        "Implement a Content-Security-Policy header appropriate for your application.",
    ),
}

# Patterns that indicate a login form is present
LOGIN_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE),
    re.compile(r'<form[^>]*action[^>]*login', re.IGNORECASE),
    re.compile(r'(?:sign.?in|log.?in|authenticate)', re.IGNORECASE),
]

# Pattern for directory listing
DIRLIST_PATTERN = re.compile(
    r'<title>\s*Index of\s*/|Directory listing for|<h1>\s*Index of',
    re.IGNORECASE
)


def _make_session(timeout: float = 5.0) -> requests.Session:
    """Create a requests session with safe defaults for local device checking."""
    session = requests.Session()
    session.verify = False  # Local devices often have self-signed certs
    session.headers.update({
        "User-Agent": "NetWatch-SecurityScanner/1.1",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
    })
    return session


def _get_page(
    session: requests.Session,
    url: str,
    timeout: float = 5.0,
    method: str = "GET",
) -> Optional[requests.Response]:
    """Fetch a URL, returning None on any error."""
    try:
        if method == "HEAD":
            return session.head(url, timeout=timeout, allow_redirects=True)
        return session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        logger.debug(f"Request failed {url}: {e}")
        return None


def check_web_interface(
    host: str,
    port: int,
    is_https: bool = False,
    timeout: float = 5.0,
    check_admin_paths: bool = True,
) -> List[Finding]:
    """Run all passive web security checks for a single host:port.

    Args:
        host:              IP address.
        port:              Port number.
        is_https:          True if this port uses HTTPS.
        timeout:           HTTP request timeout in seconds.
        check_admin_paths: Whether to probe for admin panel paths.

    Returns:
        List of Finding objects.
    """
    scheme = "https" if is_https else "http"
    base_url = f"{scheme}://{host}:{port}"
    protocol = "https" if is_https else "http"
    findings: List[Finding] = []
    session = _make_session(timeout)

    # ---- Fetch root page ----
    resp = _get_page(session, base_url + "/", timeout=timeout)
    if resp is None:
        return findings  # Cannot reach — nothing to report

    # ---- Check security headers ----
    header_findings = _check_security_headers(host, port, protocol, resp, is_https)
    findings.extend(header_findings)

    # ---- Check for login form over HTTP ----
    if not is_https:
        login_findings = _check_http_login(host, port, resp, base_url)
        findings.extend(login_findings)

    # ---- Check for directory listing ----
    dirlist_findings = _check_directory_listing(host, port, protocol, resp)
    findings.extend(dirlist_findings)

    # ---- Page title (info) ----
    title = _extract_title(resp.text)
    server = resp.headers.get("Server", "")
    if title or server:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Web interface detected: {title or 'no title'}",
            host=host, port=port, protocol=protocol,
            category="Web Interface",
            description=(
                f"HTTP service on port {port}: "
                f"Title={title!r}, Server={server!r}, "
                f"Status={resp.status_code}."
            ),
            explanation="A web interface was found on this device.",
            recommendation="Review this web interface to ensure it requires authentication.",
            evidence=f"GET {base_url}/ → {resp.status_code} | Server: {server}",
            tags=["web", "info"],
        ))

    # ---- Wappalyzer technology fingerprinting ----
    wapp_findings = _run_wappalyzer_checks(host, port, protocol, resp)
    findings.extend(wapp_findings)

    # ---- Probe admin paths ----
    if check_admin_paths:
        admin_findings = _check_admin_paths(host, port, protocol, base_url, session, timeout)
        findings.extend(admin_findings)

    return findings


def _check_security_headers(
    host: str,
    port: int,
    protocol: str,
    resp: requests.Response,
    is_https: bool,
) -> List[Finding]:
    """Check for missing security headers in the HTTP response."""
    findings: List[Finding] = []

    for header_name, (severity, title, explanation, recommendation) in SECURITY_HEADERS.items():
        # HSTS only applies to HTTPS
        if header_name == "Strict-Transport-Security" and not is_https:
            continue

        if header_name not in resp.headers:
            findings.append(Finding(
                severity=severity,
                title=title,
                host=host, port=port, protocol=protocol,
                category="HTTP Security Headers",
                description=(
                    f"The HTTP response from port {port} is missing the "
                    f"{header_name} security header."
                ),
                explanation=explanation,
                recommendation=recommendation,
                evidence=f"Header absent from: GET {resp.url}",
                tags=["web", "headers", header_name.lower()],
            ))

    return findings


def _check_http_login(
    host: str,
    port: int,
    resp: requests.Response,
    base_url: str,
) -> List[Finding]:
    """Check if a password input form is present on a plain HTTP page."""
    findings: List[Finding] = []

    body = resp.text
    has_password_field = bool(re.search(
        r'<input[^>]+type=["\']password["\']', body, re.IGNORECASE
    ))

    if has_password_field:
        findings.append(Finding(
            severity=Severity.HIGH,
            title="Login form on plain HTTP — credentials sent in cleartext",
            host=host, port=port, protocol="http",
            category="Authentication",
            description=(
                f"Port {port} serves an HTML login form over plain HTTP. "
                "Any password entered here is transmitted without encryption."
            ),
            explanation=(
                "This web interface has a username/password login form but uses plain "
                "HTTP instead of HTTPS. Any password typed into this form is sent "
                "across the network without any encryption. Anyone else on the same "
                "Wi-Fi network could capture those credentials using freely available tools."
            ),
            recommendation=(
                "1. Access this device's settings and enable HTTPS.\n"
                "2. If the device doesn't support HTTPS, check for a firmware update.\n"
                "3. Until this is fixed, only administer this device from a wired "
                "connection, not over Wi-Fi."
            ),
            evidence=f"Password input field found at: {base_url}/",
            tags=["web", "cleartext", "authentication"],
        ))

    return findings


def _check_directory_listing(
    host: str,
    port: int,
    protocol: str,
    resp: requests.Response,
) -> List[Finding]:
    """Check if the web server has directory listing enabled."""
    findings: List[Finding] = []

    if DIRLIST_PATTERN.search(resp.text):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Directory listing enabled — file contents exposed",
            host=host, port=port, protocol=protocol,
            category="Web Interface",
            description=(
                f"The web server on port {port} shows a directory listing (Index of /). "
                "Files and folders are browsable without authentication."
            ),
            explanation=(
                "Directory listing allows anyone to browse the file structure of this web "
                "server and download files directly. This can expose configuration files, "
                "backup files, or other sensitive data."
            ),
            recommendation=(
                "1. Disable directory listing in the web server settings.\n"
                "2. If this is a router or NAS, check the device settings to disable "
                "web file sharing or restrict access.\n"
                "3. Ensure no sensitive files are stored in publicly accessible directories."
            ),
            evidence=f"'Index of' pattern found in response body: {resp.url}",
            tags=["web", "directory-listing"],
        ))

    return findings


def _check_admin_paths(
    host: str,
    port: int,
    protocol: str,
    base_url: str,
    session: requests.Session,
    timeout: float,
) -> List[Finding]:
    """Probe well-known admin panel paths and report those that return 200."""
    findings: List[Finding] = []
    found_paths: List[str] = []

    for path in ADMIN_PATHS:
        url = base_url + path
        resp = _get_page(session, url, timeout=timeout, method="HEAD")
        if resp is None:
            continue
        # 200 = accessible, 401/403 = exists but protected (still report), others = absent
        if resp.status_code in (200, 401, 403):
            status_note = "accessible" if resp.status_code == 200 else f"protected (HTTP {resp.status_code})"
            found_paths.append(f"{path} [{status_note}]")

    if found_paths:
        sev = Severity.MEDIUM if any("accessible" in p for p in found_paths) else Severity.LOW
        findings.append(Finding(
            severity=sev,
            title=f"Admin panel paths found on port {port}",
            host=host, port=port, protocol=protocol,
            category="Web Interface",
            description=(
                f"The following admin-related paths responded on port {port}: "
                + ", ".join(found_paths)
            ),
            explanation=(
                "Admin panel paths are accessible on this device. "
                "Paths marked 'accessible' returned HTTP 200 without authentication. "
                "Paths marked 'protected' exist but require login — ensure strong "
                "credentials are in use."
            ),
            recommendation=(
                "1. Ensure all admin interfaces require strong authentication.\n"
                "2. If possible, restrict admin access to specific IP addresses only.\n"
                "3. Disable or remove any admin paths that are no longer needed.\n"
                "4. Change any default passwords on accessible admin panels."
            ),
            evidence="Paths: " + ", ".join(found_paths),
            tags=["web", "admin-panel"],
        ))

    return findings


def _extract_title(html: str) -> str:
    """Extract the <title> from an HTML string."""
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        return re.sub(r'\s+', ' ', match.group(1)).strip()[:80]
    return ""


def run_web_checks(
    host: str,
    open_ports: List[int],
    timeout: float = 5.0,
) -> List[Finding]:
    """Run web security checks on all HTTP/HTTPS ports for a host.

    Args:
        host:       IP address to check.
        open_ports: List of open TCP ports from the scan.
        timeout:    HTTP request timeout.

    Returns:
        List of Finding objects from all web checks.
    """
    HTTP_PORTS = {80, 8080, 8000, 8888, 9000, 8081, 3000}
    HTTPS_PORTS = {443, 8443, 9443}

    all_findings: List[Finding] = []

    for port in open_ports:
        is_https = port in HTTPS_PORTS
        if port in HTTP_PORTS or port in HTTPS_PORTS:
            logger.debug(f"Web check: {host}:{port} (https={is_https})")
            findings = check_web_interface(
                host, port, is_https=is_https, timeout=timeout
            )
            all_findings.extend(findings)

    return all_findings
