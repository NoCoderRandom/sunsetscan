# Future work priorities

## 1. Make reports clearer and more accurate

The report is currently too dense and hard to understand. Prioritize this before adding more scan features or data sources.

- Lead with a short plain-language summary: which devices need action, which need lifecycle review, and which have no known issue.
- Show each distinct finding once. State the affected device, the evidence, the practical impact, and one clear next step. Remove repetitive or low-value text.
- Keep port lists, raw scan details, and source evidence available in a secondary section so the main report stays short and auditable.
- Never turn an EOL, discontinued, or end-of-sale label into a claim that security updates stopped without vendor evidence. Keep uncertain cases as `lifecycle_review`.
- Review generated HTML against known lab devices and the router inventory. Check identity, support claims, false positives, duplicates, and readability before release.

## 2. Decide whether masscan earns a place in home-network scans

Masscan discovers open ports; Nmap and SunsetScan's fingerprinting provide the service, version, device, and lifecycle evidence. Earlier tests found masscan-related delays and load, but the project has no recorded controlled comparison proving a benefit for local networks. The current root QUICK path can run a full 65,535-port masscan sweep before its top-port Nmap scan.

In a future bounded test, compare Nmap-only and masscan-plus-Nmap on the same known devices and port scope. Record elapsed time, hosts and ports found, device identities, EOL findings, missed services, and network impact. Keep the Pi-hole host out of heavy tests. If masscan provides no clear coverage or speed benefit, use Nmap by default and reserve masscan for an explicit large-network option or remove it.
