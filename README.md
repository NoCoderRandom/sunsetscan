# NetWatch

**Network security auditing for humans — powered by nmap, built for everyone.**

[![Version](https://img.shields.io/badge/version-v1.7.0-blue)]
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?logo=windows)](https://github.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Requires: nmap](https://img.shields.io/badge/requires-nmap-orange)](https://nmap.org)
[![CVE data: OSV.dev](https://img.shields.io/badge/CVE%20data-OSV.dev-blueviolet)](https://osv.dev)
[![EOL data: endoflife.date](https://img.shields.io/badge/EOL%20data-endoflife.date-yellow)](https://endoflife.date)

---

NetWatch is a local-network security auditing tool for **home network owners and IT staff** who want the depth of nmap without learning nmap syntax. Point it at your network and it finds every active device, fingerprints running software, checks against known vulnerability databases and end-of-life records, probes web interfaces for common weaknesses, tests for default credentials, and produces a clean HTML report with **plain-English explanations** and numbered steps to fix each finding. It is **entirely read-only and non-destructive** — nothing on your network is ever modified.

---

## Features

### Network Discovery
- Discovers all active hosts via fast ping sweep
- Resolves hostnames and detects MAC addresses with vendor/manufacturer lookup
- Flexible target input: CIDR, wildcard, IP range, comma-separated, or hostname
- Optional masscan integration for faster port discovery on large networks

### Port and Service Scanning
- Six scan profiles: QUICK, FULL, STEALTH, PING, IOT, SMB
- Concurrent banner grabbing across all open ports (50-thread pool)
- OS fingerprinting with confidence percentage
- NSE (Nmap Scripting Engine) integration for enhanced device detection
- HTTP fingerprinting to identify routers, cameras, NAS devices, printers, and IoT
- Automatic root-privilege fallback: FULL/STEALTH profiles gracefully degrade when run without sudo
- Parallel security analysis — all per-host checks (SSL, SSH, FTP, SMB, SNMP, Web) run concurrently across hosts and within each host using thread pools
- Phase 7 security analysis completes in under 10 seconds regardless of network size
- Pre-scan readiness check — warns if nmap is missing, CVE/EOL databases are empty, or default modules are not installed. Runs before every scan, does not block scanning.

### Security Checks
NetWatch runs 12 security checker modules during a full assessment:

| Checker | What it finds |
|---|---|
| **SSL/TLS** | Expired/self-signed certs, weak ciphers, TLS 1.0/1.1, SSL 2.0/3.0, small RSA keys |
| **SSH** | Weak key exchange, weak ciphers/MACs, SSHv1, small host keys, raw KEXINIT analysis |
| **SMB** | SMBv1, EternalBlue (MS17-010), anonymous shares, SMB signing disabled, NTLM disclosure |
| **FTP** | Anonymous login, cleartext credentials, missing STARTTLS |
| **SNMP** | Default community strings (public/private), SNMPv1, sysDescr extraction |
| **Web** | Missing security headers, login forms over HTTP, directory listing, exposed admin panels |
| **DNS** | DNS hijacking detection (compares against Cloudflare 1.1.1.1) |
| **UPnP** | SSDP discovery, WAN port-mapping exposure on routers |
| **mDNS** | Zeroconf/Bonjour device discovery, finds hosts that evade port scans |
| **ARP** | ARP spoofing detection, MAC address change tracking (requires root) |
| **Default credentials** | Factory-default passwords on routers, NAS, cameras, printers (opt-in) |
| **Insecure protocols** | Telnet, FTP, TFTP, rsh, rlogin, rexec flagged by severity |

### Vulnerability Intelligence
- **CVE correlation** — maps detected service versions to known CVEs using OSV.dev
- **EOL checking** — 150+ products checked against endoflife.date
- **JA3S TLS fingerprinting** — identifies server software from TLS handshake signatures
- Fully offline during scans — no external API calls are made during scanning. endoflife.date and OSV.dev are only contacted by `--setup` and `--update-cache`. Scans work without any internet connection as long as caches are populated.
- Weekly CVE refresh, monthly EOL refresh — controlled by you

### Modular Data System
NetWatch includes 7 downloadable data modules that extend detection capabilities:

| Module | Source | What it adds |
|---|---|---|
| `credentials-mini` | danielmiessler/SecLists | Top 50 default credentials (default) |
| `credentials-full` | ihebski/DefaultCreds-cheat-sheet | 2860+ vendor-specific credentials |
| `wappalyzer-mini` | enthec/webappanalyzer | Top 500 web technologies (default) |
| `wappalyzer-full` | enthec/webappanalyzer | All 7515 web technologies |
| `ja3-signatures` | salesforce/ja3 | TLS fingerprint database |
| `snmp-community` | danielmiessler/SecLists | Extended SNMP community strings |
| `camera-credentials` | many-passwords/many-passwords | IP camera/DVR/NVR default passwords |

```bash
netwatch --modules                # Show module status
netwatch --download all           # Download everything
netwatch --download ja3-signatures  # Download one module
```

### Rogue Device Detection
- Save a snapshot of your network as a trusted baseline
- Future scans automatically flag unknown MAC addresses not in the baseline
- Detects known devices on unexpected IP addresses

### Risk Scoring
Every device receives a risk score (0-100) based on the severity and count of findings:

| Score | Band |
|---|---|
| 0-10 | Minimal Risk |
| 11-30 | Low Risk |
| 31-60 | Medium Risk |
| 61-80 | High Risk |
| 81-100 | Critical Risk |

### Reporting
- **Professional HTML report** — severity dashboard, per-host sections, finding cards with plain-English explanations, prioritised recommendations
- **JSON export** — machine-readable structured output
- Reports are fully self-contained — one HTML file, no external dependencies
- All findings colour-coded: Critical, High, Medium, Low, Info

### Scan History and Diffing
- Every scan is automatically saved as a gzip-compressed JSON snapshot
- View past scans with `--history`
- Compare any two scans with `--diff` to see new hosts, closed ports, new/resolved findings
- Compare against a scan from N days ago with `--diff --since N`
- History retained for 90 days by default

### User Interface
- Guided **interactive mode** (`-i`) — multi-level menus for scanning, analysis, export, modules
- **Old-style menu** — launches when run with no arguments
- Direct CLI mode — scriptable and automation-friendly
- Rich colour terminal output with progress bars, spinners, and summary panels

---

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| **Python** | 3.9+ | 3.12 recommended |
| **nmap** | Any recent | Must be on system PATH |
| **masscan** | Any | Optional — faster port discovery. `sudo apt install masscan` |
| **git** | Any | Optional — used for `--setup` and `--update` |
| **OS** | Windows 10/11, Linux, macOS | Fully native on all three |
| **Privileges** | Standard user | Root/admin needed for FULL, STEALTH, SMB profiles and ARP detection |

---

## Installation

### Linux (Debian / Ubuntu / WSL)

```bash
sudo apt-get update
sudo apt-get install -y nmap git python3 python3-pip python3-venv

# Optional: faster port scanning
sudo apt-get install -y masscan

git clone https://github.com/NoCoderRandom/netwatch.git
cd netwatch

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python3 netwatch.py --setup
```

### Linux (RHEL / Fedora / CentOS)

```bash
sudo dnf install -y nmap git python3 python3-pip
git clone https://github.com/NoCoderRandom/netwatch.git
cd netwatch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 netwatch.py --setup
```

### Windows 11

1. Download and install nmap from [nmap.org/download.html](https://nmap.org/download.html). Check "Add nmap to PATH".
2. Clone and install:

```cmd
git clone https://github.com/NoCoderRandom/netwatch.git
cd netwatch
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python netwatch.py --setup
```

### macOS

```bash
brew install nmap
git clone https://github.com/NoCoderRandom/netwatch.git
cd netwatch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 netwatch.py --setup
```

---

## Quick Start

```bash
# Interactive mode (recommended for first-time users)
python3 netwatch.py -i

# Full security assessment with HTML report
python3 netwatch.py --full-assessment --target 192.168.1.0/24

# Quick scan of your network
python3 netwatch.py --target 192.168.1.0/24

# IoT device scan (cameras, routers, smart devices)
python3 netwatch.py --target 192.168.1.0/24 --profile IOT

# Download all data modules for extended detection
python3 netwatch.py --download all
```

---

## All CLI Flags

| Flag | Description | Root |
|---|---|---|
| `--target TARGET` | IP, CIDR range, hostname, or range to scan | No |
| `--profile PROFILE` | Scan profile: QUICK, FULL, STEALTH, PING, IOT, SMB (default: QUICK) | Varies |
| `-i`, `--interactive` | Launch guided interactive mode | No |
| `--full-assessment` | Complete assessment: all phases + auto HTML export | No |
| `--nse` | Enable Nmap Scripting Engine for enhanced detection | No |
| `--check-defaults` | Test for factory-default credentials (your own devices only) | No |
| `--save-baseline` | Save scan as trusted device baseline for rogue detection | No |
| `--setup` | First-time setup wizard (dependencies + cache download) | No |
| `--update-cache` | Manually refresh CVE and EOL data caches | No |
| `--cache-status` | Show cache age and entry counts, then exit | No |
| `--modules` | Show status of all downloadable data modules | No |
| `--download MODULE` | Download a data module (or "all") | No |
| `--db SIZE` | EOL database size for `--setup`: mini, normal, large (default: normal) | No |
| `--history` | Show scan history table and exit | No |
| `--diff` | Diff last two saved scans and exit | No |
| `--since DAYS` | With `--diff`: compare against scan at least N days old | No |
| `--check-version` | Check for newer NetWatch release on GitHub | No |
| `--update` | Pull latest code from GitHub and reinstall requirements | No |
| `--verbose` | Enable debug logging | No |
| `--no-color` | Disable colour output (useful for log files) | No |
| `--quiet` | Suppress progress bars (findings still shown) | No |
| `--version` | Show version number and exit | No |

---

## Scan Profiles

| Profile | nmap flags | Speed | Root | Best for |
|---|---|---|---|---|
| **PING** | `-sn` | ~30s | No | Finding active devices quickly |
| **QUICK** | `-T4 -F` | 1-3 min | No | First look at a network |
| **FULL** | `-T4 -A -sV -O --osscan-guess` | 5-15 min | Yes | Deep analysis of specific hosts |
| **STEALTH** | `-sS -T2 -sV` | 10-30 min | Yes | Low-noise scanning |
| **IOT** | `-T4 -sV -p 23,80,443,8080,8443,554,1900,5000,5001,7547,49152 --open` | 1-3 min | No | Cameras, routers, smart devices |
| **SMB** | `-T4 -sV -p 135,139,445,137,138 --script smb-security-mode,smb2-security-mode,smb-vuln-ms17-010 --open` | 1-3 min | Yes | Windows shares, EternalBlue check |

> **Tip:** FULL and STEALTH automatically fall back to non-root flags when run without sudo. OS detection will be unavailable but port scanning and service detection still work.

---

## Cache Management

NetWatch never calls external APIs during a scan. All data is read from local cache files in `data/cache/`.

| File | Contents | Refresh interval |
|---|---|---|
| `data/cache/cve_cache.json` | CVE data keyed by product:version | Every 7 days |
| `data/cache/eol_cache.json` | EOL dates for 150+ products | Every 30 days |
| `data/cache/cache_meta.json` | Timestamps of last updates | Automatic |

```bash
netwatch --cache-status     # See current cache state
netwatch --update-cache     # Refresh stale caches
```

Scans work normally with stale or missing cache — you just may have outdated CVE data.

---

## Rogue Device Detection

```bash
# Step 1: Save baseline when all known devices are present
python3 netwatch.py --target 192.168.1.0/24 --save-baseline

# Step 2: Future scans automatically compare against baseline
python3 netwatch.py --target 192.168.1.0/24
```

| Finding | Severity | Meaning |
|---|---|---|
| Unknown device detected | Medium | MAC not in baseline — new or unauthorised device |
| Device IP changed | Low | Known MAC on a different IP (usually normal DHCP) |
| Previously seen device offline | Info | Baseline device not responding |

> **Note:** Baseline requires root/sudo for MAC address detection via nmap.

---

## HTML Report

Every `--full-assessment` produces a self-contained HTML report with:

- **Severity dashboard** — badge counts (Critical/High/Medium/Low/Info), colour bar, summary statistics
- **Risk scores** — per-device 0-100 score with risk band label
- **All findings table** — every finding across all hosts, sorted by severity
- **Per-host sections** — collapsible section per device with finding cards, open ports table, EOL status
- **Finding cards** — severity badge, title, "What was found", "What this means" (plain English), "What to do" (numbered steps), evidence, CVE IDs
- **Recommendations** — prioritised action list

Reports open in any browser with no internet required.

---

## Severity Levels

| Level | Colour | CVSS range | What it means | When to act |
|---|---|---|---|---|
| **CRITICAL** | Red | >= 9.0 | Default credentials, exploitable CVE, SSL 2.0 | Today |
| **HIGH** | Orange | 7.0-8.9 | Telnet/FTP open, expired cert, TLS 1.0, EOL software | This week |
| **MEDIUM** | Yellow | 4.0-6.9 | Self-signed cert, UPnP exposure, rogue device, missing HSTS | Schedule fix |
| **LOW** | Blue | < 4.0 | EOL approaching, missing X-Frame-Options, device IP changed | Track and plan |
| **INFO** | Grey | - | Device identified, cert details, DNS check passed | No action |

---

## Project Structure

```
netwatch/
├── netwatch.py                    # Entry point — CLI, scan pipeline, setup wizard
├── requirements.txt               # Python dependencies
├── README.md                      # This file
│
├── config/
│   └── settings.py                # All constants, timeouts, scan profiles, menu options
│
├── core/
│   ├── scanner.py                 # nmap wrapper (ScanResult, HostInfo, PortInfo)
│   ├── port_scanner.py            # Masscan pipeline + PortScanOrchestrator
│   ├── banner_grabber.py          # Concurrent raw socket banner grabbing
│   ├── http_fingerprinter.py      # HTTP device/firmware fingerprinting
│   ├── nse_scanner.py             # Nmap Scripting Engine integration
│   ├── auth_tester.py             # Default credential testing (HTTP, device-specific)
│   ├── input_parser.py            # Flexible target format parsing
│   ├── network_utils.py           # Subnet detection, IP helpers, WSL detection
│   ├── findings.py                # Finding dataclass, Severity enum, FindingRegistry
│   ├── risk_scorer.py             # Per-device risk scoring (0-100)
│   ├── cache_manager.py           # Unified CVE + EOL cache (data/cache/)
│   ├── cve_checker.py             # CVE lookup + CVECacheBuilder (OSV.dev)
│   ├── ssl_checker.py             # TLS certificate, cipher suite, JA3S fingerprinting
│   ├── ssh_checker.py             # SSH version, algorithms, KEXINIT analysis
│   ├── smb_checker.py             # SMBv1, EternalBlue, shares, NTLM disclosure
│   ├── ftp_checker.py             # Anonymous FTP, STARTTLS
│   ├── snmp_checker.py            # SNMP community strings, sysDescr (pysnmp v4+v7)
│   ├── web_checker.py             # HTTP headers, admin panels, Wappalyzer
│   ├── dns_checker.py             # DNS hijack and rebinding detection
│   ├── upnp_checker.py            # SSDP discovery, UPnP risk assessment
│   ├── mdns_checker.py            # mDNS/Zeroconf device discovery
│   ├── arp_checker.py             # ARP spoofing detection
│   ├── baseline.py                # Rogue device baseline comparison
│   ├── scan_history.py            # Scan snapshot persistence and diffing
│   ├── module_manager.py          # Downloadable data module system
│   └── update_manager.py          # Version check and self-update
│
├── eol/
│   ├── checker.py                 # EOL API queries and version comparison
│   ├── cache.py                   # Per-product JSON cache
│   └── product_map.py             # 150+ software name -> endoflife.date slug mappings
│
├── ui/
│   ├── menu.py                    # Old-style numbered menu (no-args mode)
│   ├── display.py                 # Rich terminal tables, progress bars, banners
│   ├── export.py                  # JSON and HTML report generation
│   ├── interactive_controller.py  # Interactive mode (-i) with multi-level menus
│   └── templates/
│       └── report.html.j2         # Jinja2 HTML report template
│
└── data/
    ├── default_credentials.json   # Factory-default credentials database
    ├── baseline.json              # Saved device baseline (--save-baseline)
    ├── cache/
    │   ├── cve_cache.json         # CVE data keyed by product:version
    │   ├── eol_cache.json         # EOL data keyed by product slug
    │   └── cache_meta.json        # Cache update timestamps
    ├── history/                   # Gzip scan snapshots (auto-saved)
    └── modules/                   # Downloaded data modules
```

---

## Troubleshooting

**nmap not found**

```bash
# Linux
sudo apt-get install nmap

# macOS
brew install nmap

# Windows — download from nmap.org, ensure "Add to PATH" is checked
```

**Permission denied / OS detection not working**

FULL, STEALTH, and SMB profiles require elevated privileges. Without root, these profiles automatically fall back to non-root flags (OS detection and SYN scan disabled, but port/version scanning still works).

```bash
# For full capabilities:
sudo python3 netwatch.py --target 192.168.1.0/24 --profile FULL
```

**WSL suggests wrong network (172.x.x.x)**

On WSL, NetWatch detects the virtual adapter and falls back to `192.168.1.0/24`. If your home network uses a different subnet, specify it with `--target`:

```bash
python3 netwatch.py --target 192.168.0.0/24
```

**Cache warnings at scan start**

```
WARNING: CVE data is 12 days old — run: python netwatch.py --update-cache
```

Scans work fine with stale data. Run `--update-cache` to refresh.

**SNMP checks not working**

NetWatch supports both pysnmp v4 (synchronous) and v7 (async). If you see import errors, update pysnmp:

```bash
pip install --upgrade pysnmp
```

---

## Disclaimer — Authorised Use Only

> **NetWatch is a security auditing tool intended for use on networks and devices that you own or have explicit written permission to test.**

Running network scans against systems you do not own or have authorisation to test may be **illegal** regardless of intent. The authors accept no liability for misuse.

NetWatch is **entirely non-destructive and read-only**. It does not exploit vulnerabilities, deliver payloads, or modify any configuration on any scanned device. The `--check-defaults` credential testing uses common factory defaults and does not brute-force accounts.

---

## License

MIT License — Copyright 2024 NetWatch Contributors

---

## Acknowledgements

- [nmap](https://nmap.org) — scanning engine
- [python-nmap](https://pypi.org/project/python-nmap/) — Python nmap interface
- [endoflife.date](https://endoflife.date) — EOL data API
- [OSV.dev](https://osv.dev) — vulnerability database
- [Rich](https://rich.readthedocs.io) — terminal formatting
- [Jinja2](https://jinja.palletsprojects.com) — HTML report templating
- [cryptography](https://cryptography.io) — TLS certificate inspection
- [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) — credential and SNMP lists
- [ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) — vendor credentials
- [enthec/webappanalyzer](https://github.com/AliasIO/wappalyzer) — web technology detection
- [salesforce/ja3](https://github.com/salesforce/ja3) — TLS fingerprinting
- [many-passwords](https://github.com/many-passwords/many-passwords) — camera/DVR credentials
