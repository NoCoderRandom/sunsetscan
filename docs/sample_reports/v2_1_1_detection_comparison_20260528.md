# SunsetScan 2.1.1 Detection Comparison

Date: 2026-05-28

Target: sanitized lab Raspberry Pi (`192.0.2.212`)

## Setup

Both runs used the largest local data setup available at the time:

- `./sunsetscan --setup --db large`
- `./sunsetscan --download all`
- EOL cache: 86 products
- CVE cache: 60 product/version pairs
- Modules included `wappalyzer-full`, `hardware-eol-full`, JA3 signatures,
  SNMP communities, and full credential datasets.

## Result Delta

Before the 2.1.1 detector fixes:

- 1 Critical finding
- 7 High findings
- 19 Medium findings
- 5 Low findings
- 15 Info findings

After the 2.1.1 detector fixes:

- 1 Critical finding
- 12 High findings
- 39 Medium findings
- 17 Low findings
- 27 Info findings
- Software EOL summary: 5 Critical, 1 OK, 1 Unknown

## Former Misses Now Caught

- BusyBox/Telnet-like remote login on port 2323 is now flagged as an insecure
  Telnet-style service.
- Redis on port 5555 is now probed with `INFO server`, parsed as
  `redis 5.0.14`, and reported as EOL.
- Apache on port 8089 is normalized from `apache` to `apache-http-server` and
  now produces CVE findings for `2.4.49`.
- PHP on port 8090 is extracted from HTTP headers and now produces EOL findings
  for `php 7.2.34`.
- vsftpd on port 2121 now produces CVE findings because banner versions like
  `2.3.4)` are cleaned before CVE cache lookup.
- Web checks now run on HTTP-like services discovered on non-standard ports
  such as 8088 and 8090.

## Still Not CVE/EOL Findings

- OpenSSH 7.4 is detected, but the current local CVE cache has no findings for
  `openssh:7.4`, and OpenSSH is intentionally marked not tracked by
  endoflife.date.
- BusyBox 1.19.4 is detected, but the current local EOL/CVE data does not
  include an actionable BusyBox lifecycle or CVE cache entry.
- Redis 5.0.14 is detected as EOL; the current `redis:5.0` CVE cache entry has
  no vulnerabilities, so no Redis CVE finding is emitted.

## Interpretation

The earlier misses were detector and normalization problems, not a large-data
problem. The 2.1.1 changes move the fix into broad scan-time behavior:
service-hint probing, canonical product mapping, version cleanup/fallback, and
banner/header-derived product extraction.
