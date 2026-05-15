# SunsetScan Hardware EOL Database

This repo builds a separate hardware end-of-life database for SunsetScan from the
downloaded vendor sources in `output/RawData/`.

The builder intentionally ignores `output/eol_database.json`.

## Build

```bash
python scripts/build_sunsetscan_hardware_eol_db.py
```

Generated files:

- `output/sunsetscan_hardware_eol/sunsetscan_hardware_eol.json` - full database.
- `output/sunsetscan_hardware_eol/sunsetscan_hardware_eol_lookup.json` - lookup
  indexes plus model summaries, without full record detail.
- `output/sunsetscan_hardware_eol/sunsetscan_hardware_eol_summary.json` - counts only.

If a generated file already exists, the builder copies it to a timestamped
`.bak.*` file before replacing it. Raw vendor files are never modified.

## Matching Model

Each record has:

- `vendor_slug`: normalized vendor key, for example `tplink`, `dlink`,
  `netgear`.
- `model`: base model when known.
- `part_number`: exact SKU or model/revision identifier.
- `hardware_version` and `region` when the vendor source provides them.
- `dates.end_of_security_updates`: the date SunsetScan should treat as the
  important risk date.
- `lifecycle.receives_security_updates`: `false`, `true`, or `null`.
- `lifecycle.status`: one of `unsupported`, `unsupported_status_only`,
  `support_ending_soon`, `lifecycle_review`, `end_of_sale`,
  `vendor_eol_but_supported`, `supported`, `supported_status_only`, or
  `unknown`.

## Canonical Fields

Vendor source files use different column names, so SunsetScan translates raw
headers into a stable record schema before building indexes:

| Canonical field | Examples of raw names translated into it |
| --- | --- |
| `vendor_slug` / `vendor` | manifest vendor slug and display name |
| `model` | `Product`, `Product Name`, `Model`, `Platform`, `Appliance`, `Device` |
| `part_number` | `Affected Product`, `Affected SKU`, `Arista SKU`, `Product Number`, `SKU`, `PID`, `EOS PID`, `Marketing Part Number`, `Part Number`, `Order Code` |
| `hardware_version` | `Version`, `Revision`, `Hardware Version` |
| `region` | `Region`, `Locale`, `Country` |
| `device_type` / `description` | `Description`, `Product Family`, `Category`, `Type` |
| `dates.announcement` | `Announcement`, `Notification`, `Announced` |
| `dates.last_sale` | `Last Sale` |
| `dates.end_of_sale` | `End of Sale`, `EOS`, `EOS Date`, `End of Availability`, `EOA` |
| `dates.end_of_life` | `End of Life`, `EOL`, `EOL Date`, `Retirement` |
| `dates.end_of_support` | `End of Support`, `End of Support Date`, `Support Until`, `End of SW Support`, `EOSM` |
| `dates.end_of_service` | `End of Service`, `EOSL`, `Service Life` |
| `replacement` | `Replacement`, `Replacement Products`, `Replacement Product #`, `Current Equivalent Model`, `Successor`, `Alternative`, `Migration` |
| `source.status_text` | `Status`, `Product Status`, `Lifecycle Phase` |

All matching and summary logic uses these canonical fields, not vendor-specific
raw column names.

Vendor-specific lifecycle definitions and non-English term translations are
tracked separately in `docs/hardware_eol_vendor_term_definitions.md`. That file
is an interpretation sidecar only and does not add fields to database records.

SunsetScan applies a cautious interpretation policy after the raw database is
built. For local review, this can still produce a monolithic JSON/GZip:

```bash
python3 tools/apply_hardware_eol_policy.py \
  --input output/sunsetscan_hardware_eol/sunsetscan_hardware_eol.json \
  --output-json /tmp/sunsetscan_hardware_eol_policy.json \
  --output-gz /tmp/sunsetscan_hardware_eol_policy.json.gz \
  --output-summary data/hardware_eol/sunsetscan_hardware_eol_summary.json
```

The policy preserves official vendor source data and imports manufacturer
EOL/discontinued/end-of-sale signals as vendor-declared lifecycle evidence.
When the source does not explicitly prove that security, firmware,
vulnerability, or support updates have stopped, the normalized status remains
`lifecycle_review`; lookup text can still call it vendor-declared EOL. This
avoids false hard warnings when a vendor EOL list conflicts with
product-specific firmware releases.

New raw vendor source folders can then be imported with the conservative
table importer:

```bash
python3 tools/ingest_raw_hardware_eol_sources.py \
  --input /tmp/sunsetscan_hardware_eol_policy.json.gz \
  --scraper-root /path/to/nhedb-scraper \
  --output /tmp/sunsetscan_hardware_eol_augmented.json \
  --report /tmp/sunsetscan_hardware_eol_raw_import_report.json \
  --as-of 2026-05-10
```

The importer reads `output/RawData/*/source_manifest.json` and normalizes CSV,
XLSX, HTML, and selected PDF rows with recognizable product/model fields plus
lifecycle date columns. It also has narrow context handlers for vendor pages
where products and milestone dates are split across tables, where an official
status-only EOL list should be imported as `lifecycle_review`, or where a
vendor-specific PDF layout can be parsed safely. Prose-only pages, blocked
portal shells, and unsupported PDFs remain raw evidence until a vendor-specific
parser is added.

The committed SunsetScan artifact is split after policy application:

```bash
python3 tools/split_hardware_eol_database.py \
  --input /tmp/sunsetscan_hardware_eol_augmented.json \
  --output-dir data/hardware_eol
```

Split files:

- `data/hardware_eol/sunsetscan_hardware_eol_index.json.gz` - metadata, summary,
  lookup indexes, model summaries, record shard metadata, and record-to-shard
  locations.
- `data/hardware_eol/records/network_infrastructure.json.gz` - routers,
  switches, access points, controllers, and modems.
- `data/hardware_eol/records/general_network_devices.json.gz` - generic
  network-device rows where the raw source did not expose a narrower device
  class.
- `data/hardware_eol/records/security_surveillance.json.gz` - firewalls,
  security appliances, cameras, and recorders.
- `data/hardware_eol/records/endpoints_peripherals.json.gz` - printers, NAS,
  adapters, powerline, and smart-home hardware.
- `data/hardware_eol/records/software_services_modules.json.gz` - software,
  services, modules, and accessories.

Recommended SunsetScan behavior:

1. Normalize detected vendor with `indexes.vendor_aliases`.
2. Normalize detected model by lowercasing and replacing non-alphanumeric runs
   with spaces.
3. Try `indexes.by_vendor_model_key["vendor|model"]`.
4. Try `indexes.by_part_key["vendor|model"]`.
5. Try `indexes.by_alias_key["vendor|model"]`.
6. If there are multiple hits, prefer exact `part_number`, then matching
   `hardware_version`/`region`, then use the matching `model_summary`.

## Minimal Lookup Example

```python
from core.hardware_eol import HardwareEOLDatabase


db = HardwareEOLDatabase()
match = db.lookup("TP-Link", "Archer AX10")
if match:
    print(match.finding_title)
```

For broad model matches where SunsetScan does not know the exact hardware
revision, use `model_summaries`. A summary with `overall_status: "mixed"` means
some revisions or regions are unsupported and SunsetScan should ask the user to
confirm the exact device revision before making a hard replacement call.

A summary with `overall_status: "lifecycle_review"` means the model appears in
vendor lifecycle data, but SunsetScan should emit a low-severity review finding
instead of saying security updates have definitely stopped.

## SunsetScan Distribution

SunsetScan distributes the database as smart-pack compressed modules:

- default source manifest artifact in the repo:
  `data/hardware_eol/manifest.json.gz`
- default source smart-pack indexes:
  `data/hardware_eol/indexes/*.json.gz`
- default source smart-pack record shards:
  `data/hardware_eol/records/<pack>/*.json.gz`
- installed cache manifest path:
  `data/cache/hardware_eol/manifest.json`
- installed smart-pack indexes:
  `data/cache/hardware_eol/indexes/*.json`
- installed smart-pack record shards:
  `data/cache/hardware_eol/records/<pack>/*.json`
- default module name: `hardware-eol-home`
- full smart-pack module name: `hardware-eol-full`
- legacy compatibility module name: `hardware-eol`
- license: CC BY-NC 4.0, see `data/hardware_eol/LICENSE.md`

The old monolithic `sunsetscan_hardware_eol.json.gz` artifact is obsolete and is
not published by current SunsetScan builds. Current default downloads use the
smart-pack manifest, selected compact indexes, and selected shard files above.
The legacy split index remains available through `hardware-eol` for
compatibility.

As of the 2026-05-15 promoted local smart-pack candidate, the canonical database
contains 64,245 records across 122 vendors and 51,452 model summaries. The
smart-pack record split is:

- `home`: 14,676 records
- `office`: 4,263 records
- `enterprise`: 39,466 records
- `industrial_ot`: 1,308 records
- `service_provider`: 4,532 records

The expanded JSON, local backups, raw vendor source copies, and validation
artifacts are local working files only and must not be committed.

Users install or refresh it through the existing module system:

```bash
python3 sunsetscan.py --download hardware-eol-home
python3 sunsetscan.py --download hardware-eol-full
python3 sunsetscan.py --setup
python3 sunsetscan.py --update-cache
```

The expanded full JSON is intentionally not committed. Scans read the installed
manifest and selected pack indexes, then lazily load only the record shard
needed for a matched model; scans do not contact GitHub.

## License

This database is licensed under the Creative Commons Attribution-NonCommercial
4.0 International License (CC BY-NC 4.0).

This license applies only to the SunsetScan hardware EOL database artifacts. The
SunsetScan repository and application code remain licensed under MIT.

License text: https://creativecommons.org/licenses/by-nc/4.0/
