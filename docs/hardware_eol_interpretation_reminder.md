# Hardware EOL Interpretation Reminder

Vendor lifecycle words are not interchangeable. Do not collapse every vendor
EOL/discontinued signal into "no longer receives security updates".

Keep two separate layers in the hardware EOL database:

1. Raw vendor meaning: the exact source term, date label, source URL, source
   type, and any original status text.
2. SunsetScan interpretation: the cautious normalized status SunsetScan uses for
   findings, including confidence, review requirements, and conflict notes.

Common vendor terms may mean different things:

- End of sale / discontinued: product is no longer sold or manufactured.
- EOL / end of life: vendor lifecycle flag; may or may not mean security
  updates have stopped.
- End of support / end of service: stronger support signal, but still confirm
  whether it means firmware, warranty, documentation, or vulnerability support.
- Security update period / vulnerability support: strongest signal for whether
  security updates continue.
- Recommended replacement: migration guidance, not automatically unsupported.

Policy direction:

- Only mark `receives_security_updates = false` when the source explicitly
  proves security, firmware, vulnerability, or support updates have ended.
- If a model is merely listed as EOL/discontinued, prefer a `lifecycle_review`
  style interpretation with lower severity.
- If official sources conflict, for example an EOL list exists but a newer
  firmware page shows security updates after that date, mark review/conflict
  rather than confirmed unsupported.
- Product-specific firmware pages with recent security releases should soften
  generic EOL-list claims.
- Third-party or reseller discontinued lists should be weak evidence unless
  backed by vendor support dates.

Known example:

- ASUS RT-AX92U appears on ASUS' official EOL networking list and in regional
  compliance data with `2025-02-28`.
- ASUS also publishes RT-AX92U firmware/security releases after that date.
- Therefore this model should be treated as "EOL-listed but lifecycle review
  required", not as confirmed "no longer receives security updates".

Local working areas:

- Raw vendor files copied from `nhedb-scraper/output/RawData` live under
  `data/hardware_eol/raw_vendor_sources/`.
- Current database backups live under `data/hardware_eol/local_backups/`.
- Experimental rewritten databases live under `data/hardware_eol/experiments/`.
- These folders are intentionally gitignored because raw vendor files must not
  be uploaded.
