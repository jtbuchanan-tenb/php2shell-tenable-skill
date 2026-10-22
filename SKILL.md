---
name: php2shell-tenable
description: PHP2Shell (CVE-2026-109618, CVE-2026-109619) exposure report from Tenable data via the Tenable Hexa AI MCP, written as HTML, PDF and CSV. Use when someone asks which assets are exposed to PHP2Shell, wants a PHP2Shell report, or asks about the PHP RCE plugins in Tenable VM or Web App Scanning.
---

# PHP2Shell Tenable Skill

Builds one exposure report for PHP2Shell. The data comes from the **Tenable Hexa AI MCP** and nothing else: every asset, version and finding in the report traces back to a Hexa tool call made during this run.

Source of truth for plugins, versions and mitigations: [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote).

## Plugins

| Plugin | Product | Name | Role |
|---|---|---|---|
| 115719 | WAS | PHP 8.5.x < 8.5.12 Multiple Vulnerabilities | vulnerable |
| 115720 | WAS | PHP 8.4.x < 8.4.27 Multiple Vulnerabilities | vulnerable |
| 115721 | WAS | PHP 8.3.x < 8.3.36 Multiple Vulnerabilities | vulnerable |
| 115722 | WAS | PHP 8.2.x < 8.2.35 Multiple Vulnerabilities | vulnerable |
| 48243 | VM (Nessus) | PHP Version Detection | inventory |
| 58987 | VM (Nessus) | PHP Unsupported Version Detection | inventory |
| 200476 | VM (Nessus) | PHP Scripting Language Installed (Windows) | inventory |
| 216936 | VM (Nessus) | PHP Scripting Language Installed (Unix) | inventory |

Inventory rows carry the PHP version; `render.py` turns the version into a status against the fixed releases (8.5.12, 8.4.27, 8.3.36, 8.2.35).

## Steps

1. **Preflight.** Look for the Hexa tools in your tool list, e.g. `mcp__tenable__workbenches_list_vulnerabilities` (the prefix follows whatever name the server was added under). If they are absent, stop and give the user this setup, then end the run:
   ```
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```
   Requirements: Tenable One Foundation or Advanced, **Enable Hexa AI MCP** turned on in Hexa AI settings, API keys from Settings > My Account > API Keys, and Standard User or higher. Restart Claude Code after adding the server.
   *Done when the Hexa tools are callable, or the user has the setup block.*

2. **Plugin list.** WebFetch the FAQ URL above and add any PHP2Shell plugin IDs it lists that the table lacks (Tenable is still publishing coverage). Print the final ID list with the product for each.
   *Done when the printed list holds every table ID plus any new ones.*

3. **Pull data.** Read each tool's schema before calling it. These routes work; back off and retry on HTTP 429.
   - **Which assets, and their state:** call `tenable_one_search_findings` with `filters` set to `[{"property":"finding_name","operator":"=","value":[<exact plugin names>]}]`. Match on names, because filtering on `finding_detection_id` returns nothing. Keep findings that are `ACTIVE` or `RESURFACED` and skip `FIXED`. Query the WAS names and the VM names separately, so each gets its own count.
   - **PHP version for VM plugins:** call `workbenches_get_vulnerability_outputs(plugin_id)`. It returns hosts with their plugin output, but it stops at about 10 outputs ("... and N more outputs") and has no paging. Repeat it with `age` set to 30, 90, 180 and 365, and merge the results by asset ID. When an output lists several versions, use the lowest one.
   - **Assets that still have no output:** call `workbenches_get_asset_info(asset_id)` for the hostname and IP, and write the row with a blank version. It renders as "Unknown – verify".
   *Done when every plugin ID has a recorded result count, and every active asset is a row. Zero counts as a result; an ID you never queried does not.*

4. **Write `findings.json`.** Create the run folder `~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>/` and write one row per asset × plugin, as a JSON list:
   `asset`, `ip`, `fqdn`, `source` (`VM` or `WAS`), `plugin_id`, `plugin_name`, `php_version`, `port`, `last_seen`, and `plugin_output` when `php_version` is blank.

5. **Render.** Run `python3 <this skill's directory>/render.py <run folder>/findings.json <run folder>`.
   *Done when `report.csv`, `report.html` and `report.pdf` exist and the printed `rows=` equals the number of rows you wrote.*

6. **Summarize.** Give the user:
   - asset counts by status, taken from the render output
   - the ten worst assets
   - each plugin ID with its result count
   - the three file paths
   - the interim mitigations: `memory_limit=-1`, `session.upload_progress.enabled=0`, and `fatal_error_backtraces=0` on PHP 8.5, then restart every PHP worker. These reduce exposure but do not fix it, so the patch is still required.
   - a link to the FAQ
