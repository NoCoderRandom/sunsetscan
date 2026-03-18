# 🔍 NetWatch

**Network security auditing for humans — powered by nmap, built for everyone.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?logo=windows)](https://github.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Requires: nmap](https://img.shields.io/badge/requires-nmap-orange)](https://nmap.org)
[![CVE data: OSV.dev](https://img.shields.io/badge/CVE%20data-OSV.dev-blueviolet)](https://osv.dev)
[![EOL data: endoflife.date](https://img.shields.io/badge/EOL%20data-endoflife.date-yellow)](https://endoflife.date)

---

## What is NetWatch?

NetWatch is a local-network security auditing tool designed for **home network owners and IT staff** who want the depth of nmap without having to learn nmap's syntax.

You point it at your network. It finds every active device, fingerprints what software is running, checks it against known vulnerability databases and end-of-life records, probes web interfaces for common weaknesses, tests for default credentials, and produces a clean HTML report with **plain-English explanations** of every finding and numbered steps to fix each one.

It is **entirely read-only and non-destructive.** Nothing on your network is ever modified, restarted, or interfered with. It is safe to run on a live network during business hours.

---

## Features

### 🌐 Network Discovery
- Discovers all active hosts on the LAN using fast ping sweep
- Resolves hostnames and detects MAC addresses with vendor/manufacturer lookup
- Flexible target input: CIDR, wildcard, IP range, comma-separated, or hostname

### 🔎 Port & Service Scanning
- Four scan profiles — QUICK, FULL, STEALTH, PING — for different scenarios
- Concurrent banner grabbing across all open ports (50-thread pool)
- OS fingerprinting with confidence percentage
- NSE (Nmap Scripting Engine) integration for enhanced device detection
- HTTP fingerprinting to identify routers, cameras, NAS devices, printers, and IoT

### 🛡️ Security Checks
- **SSL/TLS analysis** — expired certificates, self-signed certs, TLS 1.0/1.1/SSL 3.0, weak cipher suites
- **Web interface checks** — missing security headers, login forms over plain HTTP, directory listing, exposed admin panels
- **Insecure protocol detection** — Telnet, FTP, TFTP, rsh, rlogin, rexec, SNMP v1/v2 flagged by severity
- **UPnP enumeration** — discovers all UPnP devices and flags routers with WAN port-mapping enabled
- **DNS hijack detection** — compares your DNS responses against Cloudflare 1.1.1.1 in real time
- **Default credential testing** — tests factory-default passwords on routers, NAS devices, cameras, and printers (opt-in only, requires `--check-defaults`)

### 🧬 Vulnerability Intelligence
- **CVE correlation** — maps detected service versions to known CVEs using OSV.dev
- **EOL checking** — 150+ products checked against endoflife.date for end-of-life and approaching-EOL dates
- Offline-safe: all data is cached locally; scans never require internet access
- Weekly CVE refresh, monthly EOL refresh — controlled by you

### 📋 Rogue Device Detection
- Save a snapshot of your network as a trusted baseline
- Future scans automatically flag unknown MAC addresses not in the baseline
- Detects known devices on unexpected IP addresses

### 📊 Reporting
- **Professional HTML report** — severity dashboard, per-host sections, plain-English finding cards, prioritised recommendations
- **JSON export** — machine-readable structured output for integration with other tools
- All findings colour-coded by severity: Critical, High, Medium, Low, Info
- Reports are fully self-contained — one HTML file, no external dependencies

### 🖥️ User Interface
- Guided **interactive mode** (`-i`) — ideal for first-time users and exploratory scanning
- Direct CLI mode — scriptable and automation-friendly
- Rich colour terminal output with progress bars, spinners, and summary panels
- Works cleanly on Windows 11 without requiring WSL

---

## Screenshots

> 📷 **Terminal — Interactive Mode**
>
> *(Screenshot placeholder: interactive host discovery and drill-down menu)*

---

> 📷 **Terminal — Direct Scan with Summary**
>
> *(Screenshot placeholder: colour-coded scan results table with EOL status and finding counts)*

---

> 📷 **HTML Report — Severity Dashboard**
>
> *(Screenshot placeholder: dashboard showing badge counts, severity bar, and scan metadata)*

---

> 📷 **HTML Report — Host Finding Card**
>
> *(Screenshot placeholder: CRITICAL finding card with "What this means" and "What to do" sections)*

---

## Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| **Python** | 3.9+ | 3.12 recommended |
| **nmap** | Any recent | Must be on system PATH |
| **git** | Any | Optional — used only for `--setup` dependency checks |
| **OS** | Windows 10/11, Linux, macOS | Fully native on all three |
| **Privileges** | Standard user | Root/admin needed for FULL and STEALTH profiles only |

---

## Installation

### Windows 11

**Step 1 — Install nmap**

Download the Windows installer from [nmap.org/download.html](https://nmap.org/download.html) and run it. When prompted, check "Add nmap to PATH". Restart your terminal after installation.

Verify: `nmap --version`

**Step 2 — Install NetWatch**

```cmd
git clone https://github.com/your-org/netwatch.git
cd netwatch

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

**Step 3 — First-time setup**

```cmd
python netwatch.py --setup
```

---

### Linux (Debian / Ubuntu)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y nmap git python3 python3-pip python3-venv

# Clone and install NetWatch
git clone https://github.com/your-org/netwatch.git
cd netwatch

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# First-time setup
python netwatch.py --setup
```

---

### Linux (RHEL / Fedora / CentOS)

```bash
sudo dnf install -y nmap git python3 python3-pip

git clone https://github.com/your-org/netwatch.git
cd netwatch

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python netwatch.py --setup
```

---

## First-Time Setup

Before your first scan, run the setup wizard once:

```bash
python netwatch.py --setup
```

The wizard does four things:

1. **Checks dependencies** — verifies Python version, nmap, and git are installed and working
2. **Installs Python packages** — runs `pip install -r requirements.txt` automatically
3. **Downloads EOL data** — queries endoflife.date for 150+ products and caches locally
4. **Downloads CVE data** — queries OSV.dev for ~50 commonly detected product:version combinations

Everything is stored in `data/cache/`. Scans never call any external API — they read only from this local cache.

```
NetWatch Setup Wizard
============================================================
Step 1/4: Checking system dependencies
  ✓ Python 3.12.10
  ✓ nmap: Nmap version 7.94 ( https://nmap.org )
  ✓ git: git version 2.43.0.windows.1

Step 2/4: Installing Python packages
  ✓ All packages installed

Step 3/4: Downloading EOL data
  Downloading EOL data ━━━━━━━━━━━━━━━━━━━━━━━━ 100%

Step 4/4: Downloading CVE data
  Downloading CVE data ━━━━━━━━━━━━━━━━━━━━━━━━ 100%

============================================================
Setup complete.
  EOL data:  152 products cached
  CVE data:  47 product:version pairs cached, 312 vulnerabilities

NetWatch is ready. Run:
  python netwatch.py -i
```

---

## Quick Start

### Interactive mode (recommended for new users)

```bash
python netwatch.py -i
```

Walks you through target entry, runs host discovery, then lets you choose what to do with each host — no command-line knowledge required.

### Scan your whole home network in one command

```bash
python netwatch.py --target 192.168.1.0/24
```

### Full security assessment with HTML report

```bash
python netwatch.py --full-assessment --target 192.168.1.0/24
```

Runs discovery, port scanning, banner grabbing, NSE detection, default credential testing, EOL checking, and all security checks — then automatically saves an HTML report to `reports/`.

### Scan a single device in depth

```bash
python netwatch.py --target 192.168.1.1 --profile FULL --nse --check-defaults
```

---

## All CLI Flags

```
python netwatch.py --help
```

| Flag | Description |
|---|---|
| `--target TARGET` | IP, CIDR range, hostname, or range to scan |
| `--profile PROFILE` | Scan profile: `QUICK`, `FULL`, `STEALTH`, `PING` (default: `QUICK`) |
| `-i`, `--interactive` | Launch guided interactive mode |
| `--full-assessment` | Complete assessment: discovery → scan → banners → NSE → auth tests → EOL → security checks → auto-export |
| `--nse` | Enable Nmap Scripting Engine for enhanced device identification |
| `--check-defaults` | Test for factory-default credentials *(your own devices only)* |
| `--save-baseline` | Save this scan as the trusted device baseline for rogue detection |
| `--setup` | First-time setup wizard (run once before first scan) |
| `--update-cache` | Manually refresh CVE and EOL data caches |
| `--cache-status` | Show cache age and entry counts, then exit |
| `--verbose` | Enable debug logging |
| `--no-color` | Disable colour output (useful for log files) |
| `--version` | Show version number and exit |

### Examples for every flag

```bash
# Scan and save result as trusted baseline
python netwatch.py --target 192.168.1.0/24 --save-baseline

# Check when caches were last updated
python netwatch.py --cache-status

# Force refresh all cached data
python netwatch.py --update-cache

# Full scan with OS detection (requires admin/root)
python netwatch.py --target 192.168.1.0/24 --profile FULL

# Enhance detection with NSE scripts
python netwatch.py --target 192.168.1.1 --nse

# Test a device for default passwords (only your own devices)
python netwatch.py --target 192.168.1.1 --check-defaults

# Disable colour for logging to file
python netwatch.py --target 192.168.1.0/24 --no-color > scan.log

# Verbose debug output
python netwatch.py --target 192.168.1.1 --verbose
```

---

## Target Formats

NetWatch accepts any of these target formats:

| Format | Example | Meaning |
|---|---|---|
| CIDR | `192.168.1.0/24` | Standard subnet notation |
| Wildcard | `192.168.1.*` | All 256 addresses in the subnet |
| Range | `192.168.1.1-100` | First 100 addresses |
| List | `192.168.1.1,5,10,20` | Specific addresses |
| Mixed | `192.168.1.1-50,100-150` | Multiple ranges combined |
| Hostname | `router.local` | Any resolvable hostname |
| Single IP | `192.168.1.1` | One device |

---

## Scan Profiles

| Profile | nmap flags | Speed | Ports | Root needed | Best for |
|---|---|---|---|---|---|
| **PING** | `-sn` | ~30s | None (hosts only) | No | Finding active devices quickly |
| **QUICK** | `-T4 -F` | 1–3 min | Top 100 | No | First look at a network |
| **FULL** | `-T4 -A -sV -O` | 5–15 min | All + OS detection | Yes | Deep analysis of specific hosts |
| **STEALTH** | `-sS -T2 -sV` | 10–30 min | All, slower timing | Yes | Low-noise scanning |

> **Tip:** Start with PING to find active hosts, then run FULL on devices that look interesting.

```bash
# Step 1: discover
python netwatch.py --target 192.168.1.0/24 --profile PING

# Step 2: go deep on one host
python netwatch.py --target 192.168.1.1 --profile FULL --nse
```

---

## Cache Management

NetWatch never calls external APIs during a scan. All vulnerability and EOL data is read from local cache files stored in `data/cache/`.

### Cache files

| File | Contents | Refresh interval |
|---|---|---|
| `data/cache/cve_cache.json` | CVE data keyed by `product:version` | Every 7 days |
| `data/cache/eol_cache.json` | EOL dates for 150+ products | Every 30 days |
| `data/cache/cache_meta.json` | Timestamps of last updates | Updated automatically |

### Cache workflow

```bash
# See current cache state
python netwatch.py --cache-status

# Example output:
# ┌──────────────────────────────────────────────────────────┐
# │ Dataset  │ Entries │ Age (days) │ Status                 │
# │ EOL Data │ 152     │ 3          │ Current                │
# │ CVE Data │ 47      │ 3          │ Current                │
# └──────────────────────────────────────────────────────────┘

# Refresh stale caches
python netwatch.py --update-cache
```

NetWatch will also print a non-blocking warning if cache data is stale:

```
WARNING: CVE data is 9 days old — run: python netwatch.py --update-cache
```

Scans continue and work normally even with stale or missing cache — it just means CVE data may be outdated.

**Recommended:** add `--update-cache` to a weekly scheduled task or cron job:

```bash
# Linux crontab — run every Monday at 03:00
0 3 * * 1 cd /path/to/netwatch && python netwatch.py --update-cache
```

```
# Windows Task Scheduler — weekly trigger
python C:\netwatch\netwatch.py --update-cache
```

---

## Rogue Device Detection

NetWatch can alert you when an unknown device joins your network.

### Step 1 — Save your baseline

After a scan on a day when all your known devices are present:

```bash
python netwatch.py --target 192.168.1.0/24 --save-baseline
```

This saves every device's MAC address, IP, hostname, and vendor to `data/baseline.json`.

### Step 2 — Compare future scans

Every subsequent scan automatically compares against the baseline. New MAC addresses not in the baseline produce a **Medium** finding:

```
[MEDIUM] Unknown device detected: FF:EE:DD:CC:BB:AA (Unknown vendor)
         IP: 192.168.1.203
         This device was not present when you saved your baseline.
```

### Baseline finding types

| Finding | Severity | Meaning |
|---|---|---|
| Unknown device detected | Medium | MAC not in baseline — new or unauthorised device |
| Device IP changed | Low | Known MAC now on a different IP (usually normal DHCP) |
| Previously seen device offline | Info | Baseline device not responding in this scan |

### Updating the baseline

When you add a new legitimate device, update the baseline:

```bash
python netwatch.py --target 192.168.1.0/24 --save-baseline
```

---

## HTML Report

Every scan can produce a professional self-contained HTML report. Run with `--full-assessment` for automatic export, or export manually from the interactive menu.

### Report sections

**Header & scan metadata** — network range, scan date, duration, profile, NetWatch version

**Severity dashboard** — five badge counters (Critical / High / Medium / Low / Info) with a colour-proportioned severity bar and summary statistics

**All findings table** — every finding across all hosts, sortable by severity, with one-click navigation to the relevant host section

**Per-host sections** — one collapsible section per discovered device, showing:
- IP address, hostname, MAC, vendor, OS guess
- Finding cards for every issue found on that device
- Open ports table with service versions and EOL status

**Each finding card contains:**
- Severity badge and title
- *What was found* — technical description
- *What this means* — plain English for non-technical readers
- *What to do* — numbered action steps to fix the issue
- Raw evidence string
- CVE identifiers and CVSS score (where applicable)

**Recommendations summary** — all Critical, High, and Medium findings listed in priority order with links back to the relevant host

**Footer** — generation timestamp, tool version, disclaimer

### Exporting

```bash
# Automatic — export with full assessment
python netwatch.py --full-assessment --target 192.168.1.0/24
# Report saved to: reports/netwatch_assessment_YYYYMMDD_HHMMSS.html

# Manual — from interactive mode, press 6 → Export Report → html
python netwatch.py -i
```

Reports are fully self-contained HTML files. No internet required to view them. Open in any browser.

---

## Severity Levels

Every finding in NetWatch is assigned one of five severity levels.

| Level | Colour | CVSS range | What it means |
|---|---|---|---|
| 🔴 **CRITICAL** | Red | ≥ 9.0 | Immediate risk. Default credentials accepted, exploitable CVE with public proof-of-concept, SSL 2.0. Act today. |
| 🟠 **HIGH** | Orange | 7.0 – 8.9 | Significant risk. Telnet/FTP open, expired certificate, TLS 1.0, end-of-life software, CVE with high CVSS. Fix within the week. |
| 🟡 **MEDIUM** | Yellow | 4.0 – 6.9 | Notable risk. Self-signed cert, UPnP IGD port mapping, directory listing, missing HSTS, rogue device. Schedule a fix. |
| 🔵 **LOW** | Blue | < 4.0 | Minor concern. EOL approaching in < 180 days, missing X-Frame-Options header, device IP changed. Track and plan. |
| ⚪ **INFO** | Grey | — | Informational only. Device identified, OS detected, TLS certificate details, DNS check passed. No action needed. |

### EOL severity mapping

| EOL status | Severity |
|---|---|
| Product has reached End-of-Life | High |
| EOL approaching within 180 days | Medium |
| Supported | Info (no finding) |

---

## Supported Products (EOL)

NetWatch checks End-of-Life dates for 150+ products across these categories:

| Category | Products |
|---|---|
| **SSH** | OpenSSH, Dropbear, libssh, PuTTY |
| **Web servers** | Apache httpd, nginx, IIS, Tomcat, Lighttpd, Caddy |
| **Databases** | MySQL, MariaDB, PostgreSQL, MongoDB, Redis, Elasticsearch |
| **Linux distros** | Ubuntu, Debian, CentOS, RHEL, Fedora, Alpine, openSUSE |
| **Windows** | Windows 10/11, Windows Server |
| **Runtimes** | Python, PHP, Node.js, Ruby, Java, Go, Rust |
| **Containers** | Docker Engine, Kubernetes |
| **Mail servers** | Postfix, Exim, Dovecot, Sendmail |
| **DNS** | BIND, PowerDNS |
| **VPN** | OpenVPN, WireGuard |
| **FTP** | vsftpd, ProFTPD, pure-ftpd |
| **Routers** | TP-Link, ASUS, Netgear, Linksys, D-Link, Ubiquiti, MikroTik, Cisco IOS, pfSense |
| **Monitoring** | Nagios, Zabbix, Prometheus, Grafana |
| **Other** | Samba, Squid, HAProxy, RabbitMQ, Jenkins, WordPress, Drupal |

EOL data is provided by [endoflife.date](https://endoflife.date) and cached locally.

---

## CVE Data Sources

| Source | How it's used | API key needed |
|---|---|---|
| **OSV.dev** (primary) | Batch queries during `--setup` and `--update-cache` | No |
| **NVD API** (fallback) | Only for specific CVE IDs not found in OSV | No (rate limited: 6s between requests) |

CVE data is stored in `data/cache/cve_cache.json` and refreshed weekly on demand. During scans, only the local cache is consulted — no external API calls are made.

---

## Project Structure

```
netwatch/
├── netwatch.py                    # Entry point — CLI, scan pipeline, setup wizard
├── requirements.txt               # Python dependencies
├── README.md                      # This file
│
├── config/
│   └── settings.py                # All constants, timeouts, scan profiles
│
├── core/
│   ├── scanner.py                 # nmap wrapper (ScanResult, HostInfo, PortInfo)
│   ├── banner_grabber.py          # Concurrent raw socket banner grabbing
│   ├── http_fingerprinter.py      # HTTP device/firmware fingerprinting
│   ├── nse_scanner.py             # Nmap Scripting Engine integration
│   ├── auth_tester.py             # Default credential testing
│   ├── input_parser.py            # Flexible target format parsing
│   ├── network_utils.py           # Subnet detection, IP helpers
│   ├── findings.py                # Finding dataclass, Severity enum, FindingRegistry
│   ├── cache_manager.py           # Unified CVE + EOL cache (data/cache/)
│   ├── cve_checker.py             # CVE lookup (cache-only) + CVECacheBuilder (OSV)
│   ├── ssl_checker.py             # TLS certificate and cipher suite analysis
│   ├── web_checker.py             # HTTP security headers, admin panels, directory listing
│   ├── dns_checker.py             # DNS hijack and rebinding detection
│   ├── upnp_checker.py            # SSDP discovery, UPnP risk assessment
│   └── baseline.py                # Rogue device baseline comparison
│
├── eol/
│   ├── checker.py                 # EOL API queries and version comparison
│   ├── cache.py                   # Per-product JSON cache (legacy, still used)
│   └── product_map.py             # 150+ software name → endoflife.date slug mappings
│
├── ui/
│   ├── menu.py                    # Interactive numbered menu
│   ├── display.py                 # Rich terminal tables, progress bars, banners
│   ├── export.py                  # JSON and HTML report generation
│   ├── interactive_controller.py  # Interactive mode state machine
│   └── templates/
│       └── report.html.j2         # Jinja2 HTML report template
│
└── data/
    ├── default_credentials.json   # Factory-default credentials database
    ├── baseline.json              # Saved device baseline (created by --save-baseline)
    └── cache/
        ├── cve_cache.json         # CVE data keyed by product:version
        ├── eol_cache.json         # EOL data keyed by product slug
        └── cache_meta.json        # Cache update timestamps
```

---

## Troubleshooting

**nmap not found**

```
# Linux
sudo apt-get install nmap

# macOS
brew install nmap

# Windows — download installer from nmap.org, ensure "Add to PATH" is checked
```

**Permission denied / OS detection not working**

FULL and STEALTH profiles require elevated privileges:

```bash
# Linux / macOS
sudo python netwatch.py --target 192.168.1.0/24 --profile FULL

# Windows — right-click your terminal and "Run as Administrator"
python netwatch.py --target 192.168.1.0/24 --profile FULL
```

**Cache warnings at scan start**

```
WARNING: CVE data is 12 days old — run: python netwatch.py --update-cache
```

Run `--update-cache` to refresh. Scans work fine with stale data — the warning is informational only.

**HTML report opens blank in browser**

The report is fully self-contained. If it appears blank, open it in a different browser. All content should load without internet access.

**Import errors after installation**

```bash
# Ensure your virtual environment is activated, then reinstall:
pip install -r requirements.txt

# Or re-run setup:
python netwatch.py --setup
```

**UPnP check finds nothing**

Normal if UPnP is disabled on your router (which is a good thing). The tool will report "No UPnP devices responded" as an informational finding.

---

## ⚠️ Disclaimer — Authorised Use Only

> **NetWatch is a security auditing tool intended for use on networks and devices that you own or have explicit written permission to test.**

Running network scans against systems you do not own or do not have authorisation to test may be **illegal** in your jurisdiction, regardless of intent. Unauthorised scanning may violate computer crime laws including (but not limited to) the Computer Fraud and Abuse Act (USA), the Computer Misuse Act (UK), and equivalent legislation in other countries.

The authors of NetWatch accept no liability for any misuse of this software. By using NetWatch, you confirm that:

- You own the network being scanned, or hold documented authorisation to test it
- You understand that active scanning generates network traffic that may be logged
- You will not use any information gathered to compromise systems you do not own
- You accept full responsibility for your use of this tool

NetWatch is designed to be **entirely non-destructive and read-only**. It does not exploit vulnerabilities, deliver payloads, or modify any configuration on any scanned device. The `--check-defaults` credential testing feature uses common factory defaults and does not attempt to brute-force any accounts.

---

## License

MIT License — Copyright © 2024 NetWatch Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Acknowledgements

- [nmap](https://nmap.org) — the scanning engine that powers everything
- [python-nmap](https://pypi.org/project/python-nmap/) — Python interface to nmap
- [endoflife.date](https://endoflife.date) — free, open EOL data API
- [OSV.dev](https://osv.dev) — Google's open-source vulnerability database
- [Rich](https://rich.readthedocs.io) — terminal formatting and progress bars
- [Jinja2](https://jinja.palletsprojects.com) — HTML report templating
- [cryptography](https://cryptography.io) — TLS certificate inspection

---

<div align="center">

Made with ☕ for network administrators who deserve better tools.

</div>
