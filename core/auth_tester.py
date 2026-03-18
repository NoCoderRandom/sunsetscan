"""
NetWatch Default Credentials Checker Module.

This module checks if devices are using default credentials.
WARNING: Only use on devices you own or have explicit permission to test.

Exports:
    AuthTester: Tests for default credentials on various services
    AuthTestResult: Result of authentication test
    AuthConfidence: Confidence level of a successful auth result

Example:
    from core.auth_tester import AuthTester
    tester = AuthTester()
    result = tester.test_http_basic("192.168.1.115", 80, "admin", "admin")
"""

import base64
import json
import logging
import re
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import urllib3
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from config.settings import Settings
from core.module_manager import ModuleManager

logger = logging.getLogger(__name__)

# Suppress InsecureRequestWarning for verify=False requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AuthConfidence(Enum):
    """Confidence level for a successful authentication result.

    CONFIRMED  — redirect to non-login page + new session cookie set
    LIKELY     — multiple success keywords found, no failure keywords
    SUSPECTED  — single weak indicator; manual verification recommended
    FAILED     — authentication clearly failed or could not be verified
    """
    CONFIRMED = "CONFIRMED"
    LIKELY    = "LIKELY"
    SUSPECTED = "SUSPECTED"
    FAILED    = "FAILED"


@dataclass
class AuthTestResult:
    """Result of an authentication test.

    Attributes:
        host: Target host
        port: Target port
        service: Service type (http, https, ssh, etc.)
        username: Username tested
        password: Password tested
        success: Whether authentication is considered successful
        method: Authentication method used (basic, digest, form, syno_api, asus_form)
        error: Error message if test could not complete
        confidence: How confident we are in a positive result
        notes: Human-readable details about how confidence was determined
    """
    host: str
    port: int
    service: str
    username: str
    password: str
    success: bool = False
    method: str = ""
    error: str = ""
    confidence: AuthConfidence = AuthConfidence.FAILED
    notes: str = ""


# ---------------------------------------------------------------------------
# Response analysis helpers
# ---------------------------------------------------------------------------

# Keywords whose presence in the response body strongly suggest the login
# succeeded and we are now inside an authenticated session.
_SUCCESS_KEYWORDS = [
    "logout", "log out", "sign out", "signout",
    "dashboard", "overview", "control panel", "admin panel",
    "welcome", "configuration", "settings", "status",
    "network map", "wireless", "firmware", "system info",
]

# Keywords whose presence in the response body strongly suggest the login
# page is still being shown (i.e., login failed).
_FAILURE_KEYWORDS = [
    "invalid password", "invalid username", "invalid credentials",
    "incorrect password", "login failed", "authentication failed",
    "wrong password", "bad credentials", "error", "failed",
    "please enter", "enter your password", "enter your username",
]

# Keywords that indicate a login form is still being displayed —
# even without an explicit error message.
_LOGIN_FORM_MARKERS = [
    'type="password"', "type='password'",
    'name="password"', "name='password'",
    'name="passwd"', "name='passwd'",
    "sign in", "log in", "login",
]


def _body_lower(text: str) -> str:
    return text.lower() if text else ""


def _has_success_keywords(body: str) -> bool:
    bl = _body_lower(body)
    return any(kw in bl for kw in _SUCCESS_KEYWORDS)


def _has_failure_keywords(body: str) -> bool:
    bl = _body_lower(body)
    return any(kw in bl for kw in _FAILURE_KEYWORDS)


def _has_login_form(body: str) -> bool:
    bl = _body_lower(body)
    return any(marker.lower() in bl for marker in _LOGIN_FORM_MARKERS)


def _bodies_similar(baseline_len: int, new_len: int, threshold: float = 0.10) -> bool:
    """Return True if the two response lengths are within *threshold* of each other."""
    if baseline_len == 0:
        return new_len == 0
    return abs(new_len - baseline_len) / baseline_len < threshold


def _new_cookies(baseline_cookies: dict, new_cookies: dict) -> dict:
    """Return cookies in new_cookies that were not present in baseline_cookies."""
    return {k: v for k, v in new_cookies.items() if k not in baseline_cookies}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AuthTester:
    """Tests for default credentials on network services.

    This class checks common services (HTTP, SSH, Telnet) for default
    or weak credentials. It uses a database of known default passwords
    for various device manufacturers.

    WARNING: Only use on devices you own or have explicit permission
    to test. Unauthorized access testing is illegal.

    Attributes:
        settings: Configuration settings
        credentials_db: Dictionary of default credentials by manufacturer
        enabled: Whether auth testing is enabled

    Example:
        tester = AuthTester(enabled=True)
        result = tester.test_http_basic("192.168.1.115", 80, "admin", "admin")
        if result.success and result.confidence in (AuthConfidence.CONFIRMED, AuthConfidence.LIKELY):
            print(f"WARNING: Default password in use!")
    """

    # Services that can be tested
    TESTABLE_SERVICES = {
        80:   "http",
        443:  "https",
        8080: "http-alt",
        8443: "https-alt",
        22:   "ssh",
        23:   "telnet",
        21:   "ftp",
        # Synology DSM default ports
        5000: "http",
        5001: "https",
    }

    def __init__(
        self,
        settings: Optional[Settings] = None,
        enabled: bool = False,
    ):
        """Initialize authentication tester.

        Args:
            settings: Configuration settings
            enabled: Whether to enable auth testing (default: False)
        """
        self.settings = settings or Settings()
        self.enabled = enabled
        self.module_manager = ModuleManager()
        self.credentials_db = self._load_credentials_db()

        if enabled:
            logger.warning("AuthTester initialized with testing ENABLED")
        else:
            logger.debug("AuthTester initialized (disabled by default)")

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def _load_credentials_db(self) -> Dict:
        """Load default credentials database."""
        db_path = Path(__file__).parent.parent / "data" / "default_credentials.json"

        if not db_path.exists():
            logger.warning(f"Credentials database not found: {db_path}")
            return {"credentials": {}}

        try:
            with open(db_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load credentials DB: {e}")
            return {"credentials": {}}

    def get_credentials_for_device(
        self,
        device_type: str,
    ) -> List[Tuple[str, str]]:
        """Get default credentials for a device type.

        Uses ModuleManager for vendor-aware credential selection:
        1. If vendor is known, get vendor-specific credentials first
        2. Then add generic/universal defaults
        3. Falls back to built-in credentials_db if no modules installed

        Args:
            device_type: Device manufacturer/type (e.g., "TP-Link", "ASUS", "Hikvision")

        Returns:
            List of (username, password) tuples
        """
        credentials = []
        seen = set()

        # Try ModuleManager first (external data sources)
        module_creds = self.module_manager.get_credentials(vendor=device_type)
        if module_creds:
            for entry in module_creds:
                pair = (entry.get("username", ""), entry.get("password", ""))
                if pair not in seen and (pair[0] or pair[1]):
                    seen.add(pair)
                    credentials.append(pair)
            logger.debug(
                f"ModuleManager returned {len(credentials)} credentials "
                f"for vendor={device_type!r}"
            )
            return credentials

        # Fallback to built-in credentials_db (data/default_credentials.json)
        if device_type in self.credentials_db.get("credentials", {}):
            creds = self.credentials_db["credentials"][device_type]
            username = creds.get("username", "admin")
            for password in creds.get("passwords", []):
                pair = (username, password)
                if pair not in seen:
                    seen.add(pair)
                    credentials.append(pair)

        generic = self.credentials_db.get("generic", {})
        for username in generic.get("common_usernames", ["admin"]):
            for password in generic.get("common_passwords", ["admin"]):
                pair = (username, password)
                if pair not in seen:
                    seen.add(pair)
                    credentials.append(pair)

        return credentials

    # ------------------------------------------------------------------
    # Internal request helpers
    # ------------------------------------------------------------------

    def _get_baseline(
        self,
        url: str,
        timeout: float = 5.0,
    ) -> Optional[requests.Response]:
        """Make an unauthenticated GET to establish a baseline.

        Returns the Response, or None if the request failed.
        """
        try:
            return requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
        except Exception as e:
            logger.debug(f"Baseline request failed for {url}: {e}")
            return None

    def _detect_device_type(self, body: str, headers: dict) -> str:
        """Heuristically detect the device type from the login page.

        Returns one of: 'asus', 'synology', 'generic'
        """
        bl = _body_lower(body)
        server = headers.get("Server", "").lower()

        asus_markers = ["asuswrt", "login_authorization", "aimesh", "appget.cgi", "main_login"]
        if any(m in bl for m in asus_markers) or "httpd/2.0" in server:
            return "asus"

        # Synology DSM port 80 shows a redirect page with hidden fields pointing
        # to port 5000/5001 — detect by those fields as well as explicit markers.
        synology_markers = ["synology", "syno_token", "synotoken", "dsm", "diskstation"]
        synology_redirect_markers = [
            'id="http"',  # <input type="hidden" id="http" value="5000">
            'id="https"', # <input type="hidden" id="https" value="5001">
        ]
        if (
            any(m in bl for m in synology_markers)
            or "synology" in server
            or all(m.lower() in bl for m in synology_redirect_markers)
        ):
            return "synology"

        return "generic"

    # ------------------------------------------------------------------
    # HTTP Basic Auth test
    # ------------------------------------------------------------------

    def test_http_basic(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_https: bool = False,
    ) -> AuthTestResult:
        """Test HTTP Basic authentication.

        Checks whether the server actually challenges with WWW-Authenticate: Basic
        before concluding that a 200 response means authentication succeeded.
        A server that returns 200 without any credentials does NOT use Basic Auth —
        treating that 200 as a login success is a false positive.

        Args:
            host: Target host
            port: Target port
            username: Username to test
            password: Password to test
            use_https: Use HTTPS instead of HTTP

        Returns:
            AuthTestResult with test outcome and confidence level
        """
        result = AuthTestResult(
            host=host,
            port=port,
            service="https" if (use_https or port in [443, 8443, 5001]) else "http",
            username=username,
            password=password,
            method="basic",
        )

        if not self.enabled:
            result.error = "Auth testing is disabled"
            return result

        protocol = "https" if (use_https or port in [443, 8443, 5001]) else "http"
        url = f"{protocol}://{host}:{port}/"

        # ---- Step 1: Baseline unauthenticated request -------------------------
        baseline = self._get_baseline(url)
        if baseline is None:
            result.error = "Could not connect to host"
            return result

        # If the server returns 200 without any credentials it does not use
        # HTTP Basic Auth. Any 200 from an authenticated request would be
        # meaningless — skip the test entirely.
        if baseline.status_code == 200:
            result.error = (
                "Server returns 200 without credentials — "
                "HTTP Basic Auth is not in use on this endpoint"
            )
            return result

        # Only proceed if the server challenged us with 401 + Basic scheme.
        if baseline.status_code != 401:
            result.error = f"Unexpected baseline status {baseline.status_code}; skipping Basic Auth test"
            return result

        www_auth = baseline.headers.get("WWW-Authenticate", "")
        if "basic" not in www_auth.lower():
            result.error = f"Server challenges with non-Basic auth ({www_auth!r}); skipping"
            return result

        # ---- Step 2: Authenticated request ------------------------------------
        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            result.error = str(e)
            return result

        if response.status_code == 200:
            # Server issued a 401 without credentials, so a 200 here is genuine.
            result.success = True
            result.confidence = AuthConfidence.CONFIRMED
            result.notes = "Server returned 401 without credentials, then 200 with Basic auth credentials"
            logger.warning(
                f"HTTP Basic Auth default credentials confirmed on {host}:{port} "
                f"— {username}/{password}"
            )
        elif response.status_code == 401:
            result.notes = "Server correctly rejected credentials (401)"
        else:
            result.error = f"Unexpected status after auth: {response.status_code}"

        return result

    # ------------------------------------------------------------------
    # HTTP Digest Auth test
    # ------------------------------------------------------------------

    def test_http_digest(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_https: bool = False,
    ) -> AuthTestResult:
        """Test HTTP Digest authentication.

        Same baseline-first logic as test_http_basic.
        """
        result = AuthTestResult(
            host=host,
            port=port,
            service="https" if (use_https or port in [443, 8443, 5001]) else "http",
            username=username,
            password=password,
            method="digest",
        )

        if not self.enabled:
            result.error = "Auth testing is disabled"
            return result

        protocol = "https" if (use_https or port in [443, 8443, 5001]) else "http"
        url = f"{protocol}://{host}:{port}/"

        # ---- Step 1: Baseline -------------------------------------------------
        baseline = self._get_baseline(url)
        if baseline is None:
            result.error = "Could not connect to host"
            return result

        if baseline.status_code == 200:
            result.error = (
                "Server returns 200 without credentials — "
                "HTTP Digest Auth is not in use on this endpoint"
            )
            return result

        if baseline.status_code != 401:
            result.error = f"Unexpected baseline status {baseline.status_code}; skipping Digest test"
            return result

        www_auth = baseline.headers.get("WWW-Authenticate", "")
        if "digest" not in www_auth.lower():
            result.error = f"Server challenges with non-Digest auth ({www_auth!r}); skipping"
            return result

        # ---- Step 2: Authenticated request ------------------------------------
        try:
            response = requests.get(
                url,
                auth=HTTPDigestAuth(username, password),
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            result.error = str(e)
            return result

        if response.status_code == 200:
            result.success = True
            result.confidence = AuthConfidence.CONFIRMED
            result.notes = "Server returned 401 without credentials, then 200 with Digest credentials"
            logger.warning(f"HTTP Digest default credentials confirmed on {host}:{port}")
        elif response.status_code == 401:
            result.notes = "Server correctly rejected digest credentials"
        else:
            result.error = f"Unexpected status after digest auth: {response.status_code}"

        return result

    # ------------------------------------------------------------------
    # ASUS router form login
    # ------------------------------------------------------------------

    def _test_asus_form(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_https: bool = False,
    ) -> AuthTestResult:
        """Test ASUS router form-based login.

        ASUS routers (stock and Merlin firmware) authenticate via a POST to
        /login.cgi with login_authorization = base64(username:password).
        On success the server returns JSON {"asus_token": "...", "error_status": ""}
        and sets a session cookie.  On failure error_status is non-empty.

        Args:
            host: Target host
            port: Target port
            username / password: Credentials to test
            use_https: Use HTTPS

        Returns:
            AuthTestResult with confidence level
        """
        protocol = "https" if use_https else "http"
        result = AuthTestResult(
            host=host, port=port,
            service=protocol, username=username, password=password,
            method="asus_form",
        )

        if not self.enabled:
            result.error = "Auth testing is disabled"
            return result

        login_url = f"{protocol}://{host}:{port}/login.cgi"
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()

        try:
            response = requests.post(
                login_url,
                data={"login_authorization": encoded},
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            result.error = str(e)
            return result

        body = response.text or ""

        # ASUS returns JSON on login.cgi
        try:
            data = response.json()
            token = data.get("asus_token", "")
            error_status = str(data.get("error_status", "")).strip()

            if token and not error_status:
                result.success = True
                result.confidence = AuthConfidence.CONFIRMED
                result.notes = f"ASUS login.cgi returned asus_token with no error_status"
                logger.warning(
                    f"ASUS default credentials confirmed on {host}:{port} "
                    f"— {username}/{password}"
                )
            else:
                result.notes = f"ASUS login rejected (error_status={error_status!r})"
        except ValueError:
            # Not JSON — check for redirect or cookie
            if response.status_code in (301, 302):
                location = response.headers.get("Location", "")
                login_words = ["login", "Main_Login", "signin"]
                if location and not any(w.lower() in location.lower() for w in login_words):
                    result.success = True
                    result.confidence = AuthConfidence.LIKELY
                    result.notes = f"ASUS form redirected to non-login URL: {location}"
                    logger.warning(f"ASUS credentials likely accepted on {host}:{port}")
                else:
                    result.notes = f"ASUS form redirected back to login: {location}"
            else:
                result.notes = f"ASUS login.cgi returned non-JSON status {response.status_code}"

        return result

    # ------------------------------------------------------------------
    # Synology NAS API login
    # ------------------------------------------------------------------

    def _test_synology_api(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_https: bool = False,
    ) -> AuthTestResult:
        """Test Synology DSM via its REST auth API.

        DSM exposes SYNO.API.Auth at /webapi/auth.cgi.  The response JSON
        contains "success": true/false which is unambiguous.

        Args:
            host: Target host
            port: DSM port (typically 5000 for HTTP or 5001 for HTTPS)
            username / password: Credentials to test
            use_https: Use HTTPS

        Returns:
            AuthTestResult with confidence level
        """
        protocol = "https" if use_https else "http"
        result = AuthTestResult(
            host=host, port=port,
            service=protocol, username=username, password=password,
            method="syno_api",
        )

        if not self.enabled:
            result.error = "Auth testing is disabled"
            return result

        auth_url = (
            f"{protocol}://{host}:{port}/webapi/auth.cgi"
            f"?api=SYNO.API.Auth&version=3&method=login"
            f"&account={requests.utils.quote(username)}"
            f"&passwd={requests.utils.quote(password)}"
            f"&format=cookie"
        )

        try:
            response = requests.get(
                auth_url,
                timeout=5,
                verify=False,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            result.error = str(e)
            return result

        try:
            data = response.json()
        except ValueError:
            result.error = "Synology API did not return JSON"
            return result

        if data.get("success") is True:
            result.success = True
            result.confidence = AuthConfidence.CONFIRMED
            result.notes = "Synology SYNO.API.Auth returned success:true"
            logger.warning(
                f"Synology default credentials confirmed on {host}:{port} "
                f"— {username}/{password}"
            )
        else:
            code = data.get("error", {}).get("code", "unknown")
            result.notes = f"Synology API rejected credentials (error code {code})"

        return result

    # ------------------------------------------------------------------
    # Generic form-based login
    # ------------------------------------------------------------------

    def test_http_form(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_https: bool = False,
    ) -> AuthTestResult:
        """Test form-based HTTP login with full response analysis.

        Steps:
        1. GET the login page (baseline length + cookies).
        2. Detect device type (ASUS, Synology, generic).
        3. Dispatch to device-specific handler if available.
        4. For generic devices: POST common field names to the login URL.
        5. Analyze the response for success/failure indicators.
        6. Return result with appropriate confidence level.

        Args:
            host: Target host
            port: Target port
            username / password: Credentials to test
            use_https: Use HTTPS

        Returns:
            AuthTestResult
        """
        protocol = "https" if (use_https or port in [443, 8443, 5001]) else "http"
        result = AuthTestResult(
            host=host, port=port,
            service=protocol, username=username, password=password,
            method="form",
        )

        if not self.enabled:
            result.error = "Auth testing is disabled"
            return result

        base_url = f"{protocol}://{host}:{port}"
        login_url = f"{base_url}/"

        # ---- Step 1: Baseline GET --------------------------------------------
        baseline = self._get_baseline(login_url)
        if baseline is None:
            result.error = "Could not connect to host"
            return result

        baseline_len = len(baseline.text or "")
        baseline_cookies = dict(baseline.cookies)

        # ---- Step 2: Detect device type --------------------------------------
        device_type = self._detect_device_type(
            baseline.text or "", dict(baseline.headers)
        )
        logger.debug(f"Detected device type for {host}:{port} — {device_type}")

        # ---- Step 3: Device-specific handlers --------------------------------
        if device_type == "asus":
            return self._test_asus_form(host, port, username, password, use_https)

        if device_type == "synology":
            # Try the dedicated Synology port if this is the redirect page (port 80)
            syno_port = 5001 if use_https else 5000
            return self._test_synology_api(host, syno_port, username, password, use_https)

        # ---- Step 4: Generic form POST ---------------------------------------
        # Try common form field name combinations
        field_sets = [
            {"username": username, "password": password},
            {"user": username, "pass": password},
            {"login": username, "password": password},
            {"email": username, "password": password},
            {"admin": username, "password": password},
        ]

        response = None
        for fields in field_sets:
            try:
                response = requests.post(
                    login_url,
                    data=fields,
                    timeout=5,
                    verify=False,
                    allow_redirects=True,
                    cookies=baseline_cookies,
                )
                break
            except requests.exceptions.RequestException as e:
                logger.debug(f"Form POST failed ({fields}): {e}")

        if response is None:
            result.error = "All form POST attempts failed"
            return result

        # ---- Step 5: Analyze response ----------------------------------------
        body = response.text or ""
        response_len = len(body)
        gained_cookies = _new_cookies(baseline_cookies, dict(response.cookies))

        indicators_found = []
        disqualifiers_found = []

        # A 405 Method Not Allowed means POST is not accepted → not a login endpoint
        if response.status_code == 405:
            result.notes = "POST method not allowed on this endpoint (405)"
            return result

        # Non-success HTTP status for a form POST is almost always a failure
        if response.status_code not in (200, 301, 302, 303):
            result.notes = f"Form POST returned HTTP {response.status_code}"
            return result

        # Check redirect destination
        if response.history:
            final_url = response.url
            login_words = ["login", "signin", "logon", "auth"]
            if not any(w in final_url.lower() for w in login_words):
                indicators_found.append(f"Redirected to non-login URL: {final_url}")

        # Success keywords in body (strong positive indicator)
        if _has_success_keywords(body):
            indicators_found.append("Success keywords found in response body")

        # Failure keywords → disqualify
        if _has_failure_keywords(body):
            disqualifiers_found.append("Failure/error keywords found in response body")

        # Login form still present → disqualify
        if _has_login_form(body):
            disqualifiers_found.append("Login form still present in response body")

        # New session cookie is a strong indicator
        session_cookie_names = ["session", "token", "auth", "sid", "sessionid", "phpsessid"]
        for name, value in gained_cookies.items():
            if any(s in name.lower() for s in session_cookie_names):
                indicators_found.append(f"New session cookie set: {name}")

        # Response length change is a SECONDARY indicator only — it is not counted
        # as a positive signal on its own because many responses legitimately differ
        # in size (redirects, error pages, etc.) without indicating auth success.
        # It only contributes when there is already at least one other positive signal.
        length_changed = not _bodies_similar(baseline_len, response_len)
        if length_changed and len(indicators_found) >= 1:
            indicators_found.append(
                f"Response length changed significantly "
                f"(baseline={baseline_len}, post={response_len})"
            )

        # ---- Step 6: Determine confidence ------------------------------------
        has_disqualifiers = len(disqualifiers_found) > 0

        if not has_disqualifiers:
            if len(indicators_found) >= 2:
                result.success = True
                result.confidence = AuthConfidence.LIKELY
                result.notes = (
                    f"Multiple success indicators: {'; '.join(indicators_found)}"
                )
                logger.warning(
                    f"Form credentials likely accepted on {host}:{port} "
                    f"— {username}/{password}"
                )
            elif len(indicators_found) == 1:
                result.success = True
                result.confidence = AuthConfidence.SUSPECTED
                result.notes = (
                    f"Single weak indicator (manual verification recommended): "
                    f"{indicators_found[0]}"
                )
                logger.info(
                    f"Suspected form credential match on {host}:{port} "
                    f"(unconfirmed) — {username}/{password}"
                )
            else:
                result.notes = "No success indicators found"
        else:
            result.notes = (
                f"Disqualified by: {'; '.join(disqualifiers_found)}. "
                + (f"Positive indicators present but overridden: {'; '.join(indicators_found)}" if indicators_found else "")
            )

        return result

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def test_device_defaults(
        self,
        host: str,
        port: int,
        device_type: str,
        test_method: str = "basic",
    ) -> List[AuthTestResult]:
        """Test all default credentials for a device type.

        Args:
            host: Target host
            port: Target port
            device_type: Device manufacturer (e.g., "TP-Link")
            test_method: Authentication method ('basic', 'digest', 'form')

        Returns:
            List of AuthTestResult for each credential tested
        """
        results = []

        if not self.enabled:
            logger.warning("Auth testing is disabled. Enable with enabled=True")
            return results

        credentials = self.get_credentials_for_device(device_type)
        logger.info(f"Testing {len(credentials)} credential combinations for {device_type}")

        for username, password in credentials:
            if test_method == "basic":
                result = self.test_http_basic(host, port, username, password)
            elif test_method == "digest":
                result = self.test_http_digest(host, port, username, password)
            elif test_method == "form":
                result = self.test_http_form(host, port, username, password)
            else:
                logger.error(f"Unknown test method: {test_method}")
                continue

            results.append(result)

            if result.success and result.confidence in (
                AuthConfidence.CONFIRMED, AuthConfidence.LIKELY
            ):
                break  # No point testing more credentials

        return results

    def check_all_services(
        self,
        host: str,
        open_ports: List[int],
        device_type: Optional[str] = None,
    ) -> Dict[int, List[AuthTestResult]]:
        """Check all open services for default credentials.

        For HTTP/HTTPS services, first tries HTTP Basic Auth (with baseline
        verification to avoid false positives), then HTTP Digest Auth, and
        finally form-based login.  A result is only flagged as successful if
        the confidence level is CONFIRMED or LIKELY.

        Args:
            host: Target host
            open_ports: List of open ports to test
            device_type: Detected device type (for targeted testing)

        Returns:
            Dictionary mapping port number to list of test results.
            Only non-trivial results (those with notes or success) are included.
        """
        all_results: Dict[int, List[AuthTestResult]] = {}

        if not self.enabled:
            logger.warning("Auth testing is disabled")
            return all_results

        for port in open_ports:
            if port not in self.TESTABLE_SERVICES:
                continue

            service = self.TESTABLE_SERVICES[port]

            if service in ("http", "https", "http-alt", "https-alt"):
                test_device = device_type or "generic"
                port_results: List[AuthTestResult] = []

                # 1. HTTP Basic Auth (with baseline check — prevents false positives)
                basic_results = self.test_device_defaults(
                    host, port, test_device, test_method="basic"
                )
                port_results.extend(basic_results)

                # If Basic confirmed success, stop here
                if any(
                    r.success and r.confidence in (AuthConfidence.CONFIRMED, AuthConfidence.LIKELY)
                    for r in basic_results
                ):
                    all_results[port] = port_results
                    continue

                # 2. HTTP Digest Auth (with baseline check)
                digest_results = self.test_device_defaults(
                    host, port, test_device, test_method="digest"
                )
                port_results.extend(digest_results)

                if any(
                    r.success and r.confidence in (AuthConfidence.CONFIRMED, AuthConfidence.LIKELY)
                    for r in digest_results
                ):
                    all_results[port] = port_results
                    continue

                # 3. Form-based login (handles ASUS, Synology, and generic web UIs)
                form_results = self.test_device_defaults(
                    host, port, test_device, test_method="form"
                )
                port_results.extend(form_results)

                if port_results:
                    all_results[port] = port_results

        return all_results

    def generate_report(
        self,
        results: Dict[int, List[AuthTestResult]],
    ) -> Dict[str, any]:
        """Generate a report of authentication test results.

        Only includes confirmed/likely findings in vulnerable_services.
        Suspected findings are included in suspected_services for lower-severity
        reporting.

        Args:
            results: Results from check_all_services

        Returns:
            Summary dictionary with findings split by confidence
        """
        report = {
            "services_tested": len(results),
            "vulnerable_services": [],    # CONFIRMED or LIKELY (deduplicated ports)
            "suspected_services": [],     # SUSPECTED — report as LOW (deduplicated ports)
            "total_attempts": 0,
            "successful_logins": [],
            "recommendations": [],
        }
        _vuln_ports_seen: set = set()
        _suspected_ports_seen: set = set()

        for port, port_results in results.items():
            report["total_attempts"] += len(port_results)

            for result in port_results:
                if not result.success:
                    continue

                entry = {
                    "port": port,
                    "service": result.service,
                    "username": result.username,
                    "password": "***",
                    "method": result.method,
                    "confidence": result.confidence.value,
                    "notes": result.notes,
                }

                if result.confidence in (AuthConfidence.CONFIRMED, AuthConfidence.LIKELY):
                    if port not in _vuln_ports_seen:
                        report["vulnerable_services"].append(port)
                        _vuln_ports_seen.add(port)
                    report["successful_logins"].append(entry)
                elif result.confidence == AuthConfidence.SUSPECTED:
                    if port not in _suspected_ports_seen:
                        report["suspected_services"].append(port)
                        _suspected_ports_seen.add(port)
                    report["successful_logins"].append(entry)

        if report["vulnerable_services"]:
            report["recommendations"].append(
                "CRITICAL: Default credentials detected! Change passwords immediately."
            )
        if report["suspected_services"]:
            report["recommendations"].append(
                "LOW: Possible default credentials (unconfirmed). Verify manually."
            )

        return report
