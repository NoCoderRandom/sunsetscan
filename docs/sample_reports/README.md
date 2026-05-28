# SunsetScan Sample Reports

These reports are sanitized outputs from an authorized local lab run. Private
lab addresses were replaced with documentation-only `192.0.2.0/24` addresses
and the lab MAC address was replaced with a placeholder value.

- `sunsetscan_lab_vulnerable_eol_sample_20260528.html`: FULL profile sample
  against a Raspberry Pi lab target running controlled test services plus an
  old `nginx:1.14.0-alpine` container, `httpd:2.4.49`, `php:7.2-apache`,
  and `redis:5.0.14-bullseye`. Demonstrates CVE, software EOL, hardware EOL,
  insecure protocol, web, SSH, and FTP findings, with Redis included in the
  detected service inventory.
- `sunsetscan_lab_vulnerable_eol_large_db_sample_20260528.html`: same lab
  target after installing the largest available data modules with
  `--setup --db large` and `--download all`.
- `sunsetscan_lab_vulnerable_eol_v2_1_1_sample_20260528.html`: same lab
  target after the 2.1.1 detection pipeline fixes. Demonstrates the formerly
  missed BusyBox/Telnet-like service, Redis EOL, PHP EOL, Apache CVEs, and
  vsftpd CVEs.
- `sunsetscan_lab_iot_eol_sample_20260528.html`: IOT profile sample against
  the same lab target. Demonstrates router/IoT HTTP fingerprinting and
  hardware lifecycle findings.
- `large_db_comparison_20260528.md`: short comparison between the normal-data
  and large-data FULL profile runs.
- `v2_1_1_detection_comparison_20260528.md`: short comparison between the
  large-data run before and after the 2.1.1 detection pipeline fixes.

Do not commit raw reports from real customer or home networks without
sanitizing hostnames, IP addresses, MAC addresses, and other local identifiers.
