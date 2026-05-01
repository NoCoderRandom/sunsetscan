# NetWatch Hardware EOL Database

This repo builds a separate hardware end-of-life database for NetWatch from the
downloaded vendor sources in `output/RawData/`.

The builder intentionally ignores `output/eol_database.json`.

## Build

```bash
python scripts/build_netwatch_hardware_eol_db.py
```

Generated files:

- `output/netwatch_hardware_eol/netwatch_hardware_eol.json` - full database.
- `output/netwatch_hardware_eol/netwatch_hardware_eol_lookup.json` - lookup
  indexes plus model summaries, without full record detail.
- `output/netwatch_hardware_eol/netwatch_hardware_eol_summary.json` - counts only.

If a generated file already exists, the builder copies it to a timestamped
`.bak.*` file before replacing it. Raw vendor files are never modified.

## Matching Model

Each record has:

- `vendor_slug`: normalized vendor key, for example `tplink`, `dlink`,
  `netgear`.
- `model`: base model when known.
- `part_number`: exact SKU or model/revision identifier.
- `hardware_version` and `region` when the vendor source provides them.
- `dates.end_of_security_updates`: the date NetWatch should treat as the
  important risk date.
- `lifecycle.receives_security_updates`: `false`, `true`, or `null`.
- `lifecycle.status`: one of `unsupported`, `unsupported_status_only`,
  `support_ending_soon`, `lifecycle_review`, `end_of_sale`,
  `vendor_eol_but_supported`, `supported`, `supported_status_only`, or
  `unknown`.

NetWatch applies a cautious interpretation policy after the raw database is
built:

```bash
python3 tools/apply_hardware_eol_policy.py \
  --input output/netwatch_hardware_eol/netwatch_hardware_eol.json \
  --output-json data/hardware_eol/netwatch_hardware_eol.json \
  --output-gz data/hardware_eol/netwatch_hardware_eol.json.gz \
  --output-summary data/hardware_eol/netwatch_hardware_eol_summary.json
```

The policy preserves official vendor source data but downgrades ambiguous
EOL/discontinued/end-of-sale signals to `lifecycle_review` unless the source
explicitly proves that security, firmware, vulnerability, or support updates
have stopped. This avoids false hard warnings when a vendor EOL list conflicts
with product-specific firmware releases.

Recommended NetWatch behavior:

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
import json
import re


def key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


db = json.load(open("output/netwatch_hardware_eol/netwatch_hardware_eol.json"))
vendor = db["indexes"]["vendor_aliases"].get(key("TP-Link"), key("TP-Link"))
model = key("Archer AX10")

ids = (
    db["indexes"]["by_vendor_model_key"].get(f"{vendor}|{model}")
    or db["indexes"]["by_part_key"].get(f"{vendor}|{model}")
    or db["indexes"]["by_alias_key"].get(f"{vendor}|{model}")
    or []
)

records_by_id = {record["id"]: record for record in db["records"]}
for record_id in ids:
    record = records_by_id[record_id]
    if record["lifecycle"]["receives_security_updates"] is False:
        print(record["netwatch"]["finding_title"])
```

For broad model matches where NetWatch does not know the exact hardware
revision, use `model_summaries`. A summary with `overall_status: "mixed"` means
some revisions or regions are unsupported and NetWatch should ask the user to
confirm the exact device revision before making a hard replacement call.

A summary with `overall_status: "lifecycle_review"` means the model appears in
vendor lifecycle data, but NetWatch should emit a low-severity review finding
instead of saying security updates have definitely stopped.

## NetWatch Distribution

NetWatch distributes the database as a compressed module:

- source artifact in the repo: `data/hardware_eol/netwatch_hardware_eol.json.gz`
- installed cache path: `data/cache/hardware_eol/netwatch_hardware_eol.json`
- module name: `hardware-eol`
- license: CC BY-NC 4.0, see `data/hardware_eol/LICENSE.md`

Users install or refresh it through the existing module system:

```bash
python3 netwatch.py --download hardware-eol
python3 netwatch.py --setup
python3 netwatch.py --update-cache
```

The expanded full JSON is intentionally not committed because it is larger than
GitHub's normal single-file limit. Scans read the installed cache file and do
not contact GitHub.

## License

This database is licensed under the Creative Commons Attribution-NonCommercial
4.0 International License (CC BY-NC 4.0).

This license applies only to the NetWatch hardware EOL database artifacts. The
NetWatch repository and application code remain licensed under MIT.

License text: https://creativecommons.org/licenses/by-nc/4.0/
