#!/usr/bin/env python3
"""Writes docs/rules_catalog.xlsx: every rule the tool can run, with its details.

The list comes from the check results of one run folder (entra_checks.py writes them), so it always matches the code and the specs.
Entra recommendation rules (REC-*) are created per tenant and are left out.

    python src/export_rules_catalog.py [--run-dir runs/<company>/<run>] [--output docs/rules_catalog.xlsx]

Without --run-dir the newest run folder that has check results is used.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import paths

AREAS = ["Entra ID", "Intune", "Exchange Online", "Teams", "SharePoint and OneDrive", "Security and compliance", "Azure (identity)"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
COLUMNS = ["Rule ID", "References", "Framework", "Area", "Title", "Severity", "Licence needed", "NIST CSF 2.0", "Data sets", "Expected",
           "Description", "Remediation", "Links"]
WIDTHS = [20, 22, 26, 22, 70, 10, 22, 14, 30, 60, 80, 80, 60]


def newest_run_with_results() -> Path:
    found = sorted(paths.output_dir().glob("*/*/enriched/check_results.json"), key=lambda p: p.stat().st_mtime)
    if not found:
        sys.exit(f"no check results under {paths.output_dir()}: run entra_collect.py and entra_checks.py first, or pass --run-dir")
    return found[-1].parent.parent


def main(argv=None) -> int:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", help="run folder with enriched/check_results.json (default: the newest one)")
    ap.add_argument("--output", default=str(paths.ROOT / "docs" / "rules_catalog.xlsx"))
    args = ap.parse_args(argv)
    run_dir = Path(args.run_dir) if args.run_dir else newest_run_with_results()
    results_file = run_dir / "enriched" / "check_results.json"
    if not results_file.exists():
        sys.exit(f"{results_file} not found: run entra_checks.py for that run first")
    rules = [r for r in json.loads(results_file.read_text(encoding="utf-8"))["results"] if not r["rule_id"].startswith("REC-")]
    order = {a: i for i, a in enumerate(AREAS)}
    rules.sort(key=lambda r: (order.get(r.get("area"), 99), r.get("framework") or "", r["rule_id"]))

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    bold = Font(bold=True)
    ws.append(["Area", "Rules", *SEVERITIES])
    by_area = Counter(r["area"] for r in rules)
    by_area_sev = Counter((r["area"], r["severity"]) for r in rules)
    for a in AREAS:
        if by_area[a]:
            ws.append([a, by_area[a], *[by_area_sev[(a, s)] for s in SEVERITIES]])
    sev_total = Counter(r["severity"] for r in rules)
    ws.append(["Total", len(rules), *[sev_total[s] for s in SEVERITIES]])
    ws.append([])
    ws.append(["Framework", "Rules"])
    framework_header = ws.max_row
    for f, n in sorted(Counter(r["framework"] for r in rules).items()):
        ws.append([f, n])
    ws.append([])
    ws.append(["Note", "Entra recommendation rules (REC-*) are created per tenant, one per recommendation, and are not listed. "
                       "Descriptions, remediation text and links come from the rule specs and data/rule_details.json."])
    for cell in ws[1]:
        cell.font = bold
    for cell in ws[framework_header]:
        if cell.value:
            cell.font = bold
    ws.column_dimensions["A"].width = 34

    rs = wb.create_sheet("Rules")
    rs.append(COLUMNS)
    for r in rules:
        d = r.get("details") or {}
        links = "\n".join(f"{l.get('text', '')} - {l.get('url', '')}" for l in d.get("links") or [])
        rs.append([r["rule_id"], r.get("reference_id"), r.get("framework"), r.get("area"), r["title"], r["severity"], r.get("required_licence") or None,
                   r.get("nist") or None, r.get("dataset") or None, r.get("expected"), d.get("description"), d.get("remediation"), links or None])
    for cell in rs[1]:
        cell.font = bold
    for i, w in enumerate(WIDTHS):
        rs.column_dimensions[chr(65 + i)].width = w
    for row in rs.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    rs.freeze_panes = "A2"
    rs.auto_filter.ref = rs.dimensions

    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    wb.save(target)
    gaps = [r["rule_id"] for r in rules if not all((r.get("details") or {}).get(f) for f in ("description", "remediation", "links"))]
    print(f"Wrote {target} ({len(rules)} rules from {run_dir.name}); rules missing description, remediation or links: {len(gaps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
