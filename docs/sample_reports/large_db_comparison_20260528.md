# SunsetScan Normal vs Large Data Comparison

Date: 2026-05-28

Target: sanitized lab Raspberry Pi (`192.0.2.212`)

## Data Setup

Normal-data report:

- EOL cache: 83 entries before the original scan
- CVE cache: 60 product/version pairs
- Modules: default/minimal modules plus `hardware-eol-home`

Large-data report:

- Command: `./sunsetscan --setup --db large`
- Command: `./sunsetscan --download all`
- EOL cache after setup/download: 86 entries
- CVE cache after setup/download: 60 product/version pairs
- Full modules installed: `credentials-full`, `wappalyzer-full`,
  `ja3-signatures`, `snmp-community`, `camera-credentials`, `hardware-eol`,
  and `hardware-eol-full`

## Result

The finding set did not change between the normal-data and large-data runs.
Both reports produced:

- 1 Critical finding
- 7 High findings
- 19 Medium findings
- 5 Low findings
- 15 Info findings
- 13 open ports on the target
- Device risk score: 100/100

## Trap Coverage

Detected with findings:

- Fake `vsftpd 2.3.4` on port 2121
- Fake `OpenSSH 7.4` on port 2222
- Fake TP-Link Archer C7 / nginx / PHP router page on port 8080
- Real `nginx:1.14.0-alpine` on port 8088

Detected only in inventory, not converted into useful vulnerability/EOL findings:

- Fake BusyBox/Telnet on port 2323, misclassified as `3d-nfsd`
- Fake Apache/TP-Link service on port 5000
- Real Redis on port 5555, detected as `redis key-value store` without version
- Real Apache `2.4.49` on port 8089
- Real `php:7.2-apache` on port 8090, mostly attributed as Apache `2.4.38`

## Interpretation

The larger module set did not improve this lab result. The remaining misses
look like detector/mapping issues rather than missing database entries:

- Telnet/BusyBox banner classification needs improvement.
- Apache version-to-CVE/EOL mapping is not firing.
- Redis version probing is not deep enough to produce CVE/EOL checks.
- PHP attribution should use the `X-Powered-By` or Wappalyzer evidence on the
  correct port.
