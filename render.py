#!/usr/bin/env python3
"""Render a PHP2Shell exposure report (CSV, HTML, PDF) from findings.json.

Usage: python3 render.py findings.json <outdir>

findings.json is a list of rows with keys: asset, ip, fqdn, source (VM|WAS),
plugin_id, plugin_name, php_version, port, last_seen, and optionally
plugin_output (used to recover php_version when it is blank).
"""
import base64
import csv
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from string import Template

BLOG = ("https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-"
        "frequently-asked-questions-about-critical-php-remote")

# Fixed release per PHP branch, from the Tenable Research FAQ.
FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
BACKPORT_ONLY = {(7, 4), (8, 0), (8, 1)}
WAS_FIXED = {"115719": "8.5.12", "115720": "8.4.27", "115721": "8.3.36", "115722": "8.2.35"}

VULN_PATCH = "Vulnerable – patch available"
VULN_BACKPORT = "Vulnerable – backport only"
VULN_EOL = "Vulnerable – EOL"
PATCHED = "Patched"
NOT_AFFECTED = "Not affected"
UNKNOWN = "Unknown – verify"
# Worst first; drives per-asset rollup and tile order.
ORDER = [VULN_EOL, VULN_BACKPORT, VULN_PATCH, UNKNOWN, PATCHED, NOT_AFFECTED]
# Swatches follow Tenable's severity palette (critical, high, medium); the rest
# are cyberagents-exchange-website tokens (text-secondary, MCP blue, bg-tertiary).
COLORS = {VULN_EOL: "#91243E", VULN_BACKPORT: "#DD4B50", VULN_PATCH: "#F18C43",
          UNKNOWN: "#969696", PATCHED: "#4EA5FF", NOT_AFFECTED: "#44494B"}

FIELDS = ["asset", "ip", "fqdn", "source", "plugin_id", "plugin_name",
          "php_version", "port", "last_seen"]
LABELS = {"asset": "Asset", "ip": "IP", "fqdn": "FQDN", "source": "Source", "plugin_id": "Plugin",
          "plugin_name": "Plugin name", "php_version": "PHP", "port": "Port", "last_seen": "Last seen",
          "status": "Status", "fixed_version": "Fix"}
NOWRAP = {"ip", "source", "plugin_id", "php_version", "port", "last_seen", "fixed_version"}
ASSETS = Path(__file__).resolve().parent / "assets"
VERSION_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")


def parse_version(text):
    m = VERSION_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def status_for(row):
    """Return (status, fixed_version) for one finding row."""
    pid = str(row.get("plugin_id", "")).strip()
    if row.get("source", "").upper() == "WAS" and pid in WAS_FIXED:
        return VULN_PATCH, WAS_FIXED[pid]
    v = parse_version(row.get("php_version")) or parse_version(row.get("plugin_output"))
    if not v:
        return UNKNOWN, ""
    branch = v[:2]
    if branch in FIXED:
        fixed = FIXED[branch]
        return (PATCHED if v >= fixed else VULN_PATCH), ".".join(map(str, fixed))
    if branch in BACKPORT_ONLY:
        return VULN_BACKPORT, "vendor backport"
    if (5, 4) <= branch <= (7, 3):
        return VULN_EOL, "none (EOL)"
    if branch < (5, 4):
        return NOT_AFFECTED, ""
    return UNKNOWN, ""


def enrich(rows):
    out = []
    for r in rows:
        r = {k: ("" if r.get(k) is None else str(r.get(k))) for k in FIELDS + ["plugin_output"]}
        if not r["php_version"]:
            v = parse_version(r["plugin_output"])
            r["php_version"] = ".".join(map(str, v)) if v else ""
        r["status"], r["fixed_version"] = status_for(r)
        out.append(r)
    out.sort(key=lambda r: (ORDER.index(r["status"]), r["asset"]))
    return out


def asset_rollup(rows):
    """Worst status per asset."""
    worst = {}
    for r in rows:
        # Hostnames repeat across distinct assets, so the IP is part of the key.
        key = (r["asset"] or r["fqdn"], r["ip"])
        if key not in worst or ORDER.index(r["status"]) < ORDER.index(worst[key]):
            worst[key] = r["status"]
    return Counter(worst.values())


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS + ["status", "fixed_version"], extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_html(rows, path, generated):
    counts = asset_rollup(rows)
    tiles = "".join(
        f'<div class="tile clip-corner" style="--c:{COLORS[s]}"><b>{counts.get(s, 0)}</b>'
        f'<span class="caption">{html.escape(s)}</span></div>' for s in ORDER)
    # Columns no row fills (often FQDN, port) are dropped from the HTML; the CSV keeps them.
    cols = [c for c in FIELDS + ["status", "fixed_version"] if any(r[c] for r in rows)] or FIELDS + ["status"]
    thead = "".join(f"<th>{LABELS[c]}</th>" for c in cols)

    def cell(r, c):
        v = html.escape(r[c])
        if c == "status":
            return (f'<td><span class="status" style="--c:{COLORS[r[c]]}">'
                    f'<span class="swatch"></span>{v}</span></td>')
        if c == "plugin_name":
            return f'<td class="name">{v}</td>'
        return f'<td class="nowrap">{v}</td>' if c in NOWRAP else f"<td>{v}</td>"

    tbody = "".join("<tr>" + "".join(cell(r, c) for c in cols) + "</tr>" for r in rows) or (
        f'<tr><td class="empty" colspan="{len(cols)}">No findings returned for the PHP2Shell plugins.</td></tr>')
    lockup = (ASSETS / "tenable-lockup.svg").read_text()
    doc = Template((ASSETS / "report.html").read_text()).substitute(
        font=b64(ASSETS / "WorkSans-latin.woff2"),
        lockup_white=base64.b64encode(lockup.encode()).decode(),
        lockup_dark=base64.b64encode(lockup.replace("fill: #fff", "fill: #1E2426").encode()).decode(),
        iris=b64(ASSETS / "tenable-iris.png"),
        generated=generated, row_count=len(rows), asset_count=sum(counts.values()),
        plugins=html.escape(", ".join(sorted({r["plugin_id"] for r in rows if r["plugin_id"]}, key=lambda x: (len(x), x))) or "none"),
        tiles=tiles, thead=thead, tbody=tbody, blog=BLOG)
    path.write_text(doc, encoding="utf-8")


def b64(path):
    return base64.b64encode(path.read_bytes()).decode()


def find_chrome():
    mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if mac.exists():
        return str(mac)
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge"):
        if shutil.which(name):
            return shutil.which(name)
    return None


def write_pdf(html_path, pdf_path):
    chrome = find_chrome()
    if not chrome:
        print("WARN: no Chrome/Chromium found; PDF skipped. Print report.html to PDF manually.")
        return False
    profile = tempfile.mkdtemp(prefix=".chrome-", dir=pdf_path.parent)
    try:
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--user-data-dir={profile}", f"--print-to-pdf={pdf_path}",
                        html_path.resolve().as_uri()],
                       check=True, capture_output=True, timeout=120)
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    return pdf_path.exists()


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rows = enrich(json.loads(Path(sys.argv[1]).read_text()))
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    write_csv(rows, out / "report.csv")
    write_html(rows, out / "report.html", generated)
    pdf_ok = write_pdf(out / "report.html", out / "report.pdf")
    counts = asset_rollup(rows)
    print(f"rows={len(rows)} assets={sum(counts.values())}")
    for s in ORDER:
        print(f"  {s}: {counts.get(s, 0)} assets")
    for name in ("report.csv", "report.html") + (("report.pdf",) if pdf_ok else ()):
        print(out / name)


if __name__ == "__main__":
    main()
