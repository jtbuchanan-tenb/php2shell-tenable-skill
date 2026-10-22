# PHP2Shell Tenable Skill

A Claude Code skill that reports exposure to PHP2Shell (CVE-2026-109618 and CVE-2026-109619, pre-authentication remote code execution in PHP) from your own Tenable data. It pulls findings through the [Tenable Hexa AI MCP](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm), works out each asset's status against the fixed PHP releases, and writes the result as an HTML page, a PDF and a CSV.

The plugin IDs, fixed versions and mitigations come from Tenable Research's [PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote).

## What it does

1. Checks that the Tenable Hexa AI MCP tools are loaded. If they are missing, it prints the setup command and stops.
2. Re-reads the Tenable Research FAQ for the current CVE list, fixed releases and mitigations, then asks Tenable's plugin database for every plugin covering those CVEs. That picks up Nessus and cloud or container plugins as Tenable publishes them.
3. Finds vulnerable findings by CVE, and reads PHP inventory from the detection plugins. At the time of writing the plugins are:

   | Plugin | Product | Name |
   |---|---|---|
   | 115719–115722 | Web App Scanning | PHP 8.5.x / 8.4.x / 8.3.x / 8.2.x Multiple Vulnerabilities |
   | 369483 | Vulnerability Management | PHP < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12 Multiple Vulnerabilities |
   | 369521 | Vulnerability Management | GLSA-202610-02 : PHP: Multiple Vulnerabilities |
   | 476454, 476508, 476511, 476512 | Cloud / container security | Echo and Alpine PHP package updates |
   | 48243 | Vulnerability Management | PHP Version Detection |
   | 58987 | Vulnerability Management | PHP Unsupported Version Detection |
   | 200476 | Vulnerability Management | PHP Scripting Language Installed (Windows) |
   | 216936 | Vulnerability Management | PHP Scripting Language Installed (Unix) |

4. Writes one row per asset and plugin to `findings.json`. The rows hold hostname, IP, PHP version, last seen date and plugin.
5. Runs `render.py`, which turns each row into a status and writes the report.
6. Summarizes the run in the chat: asset counts by status, the ten worst assets, the result count for each plugin, and the interim mitigations.

The skill only reads data. It never launches scans, creates tags or changes anything in Tenable.

## Prerequisites

- **Claude Code.**
- **Tenable One Foundation or Advanced.** Hexa AI MCP must be turned on under Settings > Hexa AI, and your role must be Standard User or higher. The Hexa MCP is not available in FedRAMP Moderate environments.
- **Tenable API keys**, generated under Settings > My Account > API Keys.
- **Python 3.** `render.py` uses only the standard library.
- **Google Chrome or Chromium** for the PDF. Without either, the HTML and CSV are still written and the PDF is skipped with a warning.

## Install

1. Add the Tenable Hexa AI MCP server to Claude Code, using your own keys:

   ```bash
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```

2. Clone this repository into your Claude Code skills directory:

   ```bash
   git clone https://github.com/securibee/php2shell-tenable-skill ~/.claude/skills/php2shell-tenable
   ```

3. Restart Claude Code so it loads both the MCP server and the skill.

## Usage

Run `/php2shell-tenable`, or ask Claude something like "run the PHP2Shell report" or "which of our assets are exposed to PHP2Shell?".

A run takes a few minutes. Most of that is Hexa calls, and the skill backs off if Tenable rate-limits it.

## Output

Each run writes to `~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>/`:

| File | Contents |
|---|---|
| `report.html` | A self-contained page with status tiles, interim mitigations and a sortable findings table. It has a PDF button and needs no network access to view. |
| `report.pdf` | A US Letter landscape version. Page 1 is the summary; the findings table starts on page 2. |
| `report.csv` | Every finding with all fields, plus `status` and `fixed_version`. |
| `findings.json` | The raw rows the report was built from. |

`render.py` gives each finding one of these statuses:

| Status | Meaning |
|---|---|
| Vulnerable – EOL | PHP 5.4–7.3. End of life, and the PHP project will not ship a fix. |
| Vulnerable – backport only | PHP 7.4–8.1. No official release; fixes come only as source or vendor backports. |
| Vulnerable – patch available | PHP 8.2–8.5 below 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or any finding Tenable matched to the CVEs. |
| Patched | At or above the fixed release for its branch. |
| Not affected | Below PHP 5.4. |
| Unknown – verify | Tenable reports PHP, but the skill could not read a version. |

You can re-render from saved findings without calling Tenable again:

```bash
python3 ~/.claude/skills/php2shell-tenable/render.py <run folder>/findings.json <run folder>
```

## Data flows

- **Tenable Hexa AI MCP** (`https://cloud.tenable.com/mcp`). The skill sends read-only queries with your API keys. It uses `plugins_search_plugins`, `tenable_one_search_findings`, `workbenches_get_vulnerability_outputs` and `workbenches_get_asset_info`.
- **Your LLM provider.** As with any MCP server, the asset data Hexa returns passes through Claude Code to the model you use.
- **tenable.com.** The skill fetches the Tenable Research FAQ once per run for the current CVEs, fixed releases and mitigations.
- **No network access from `render.py`.** It writes local files and runs a local headless Chrome against them. The font, logo and images are embedded in the HTML. The report's one external reference is a link to the FAQ, which only opens if you click it.

## Known limitations

- **Status comes from the PHP version alone.** Ubuntu, RHEL and other distributions often backport fixes without changing the version number, so OS-managed packages can show as vulnerable when they are patched. Check those against the vendor advisory.
- **Plugin output is limited to ten per call.** Hexa returns up to 10 distinct plugin outputs per call, with no next page, and hosts with identical output share one entry. The skill repeats the call across age windows from 7 to 365 days and merges the results. A host it still can't see is reported as "Unknown – verify".
- **Hosts with several PHP installs.** When a host's output lists more than one version, the skill uses the lowest version it can see. A very long output can be cut short, which can hide some installs.
- **Web App Scanning results need a scan after 21 October 2026.** The WAS plugins were published that day, so an earlier scan cannot report them.
- **Fixed findings are excluded.** Findings Tenable marks `FIXED` are left out of the report.

## Repository layout

```
SKILL.md            skill instructions Claude Code loads
render.py           findings.json -> report.csv, report.html, report.pdf
assets/report.html  report template (design tokens from the CyberAgents Exchange website)
assets/*            Work Sans font with its license (OFL.txt), Tenable logo and iris
```

## License

MIT, copyright Tenable, Inc. See [LICENSE](LICENSE).

The bundled Work Sans font is licensed separately under the SIL Open Font License 1.1 ([assets/OFL.txt](assets/OFL.txt)). The Tenable name, logo and iris mark are trademarks of Tenable, Inc. They are included only to brand the generated reports and are not licensed under MIT.
