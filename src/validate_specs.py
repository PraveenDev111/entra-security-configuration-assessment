#!/usr/bin/env python3
"""Checks the rule specs in specs/ for mistakes before a run: required fields, unique ids, valid modes and operators,
severity, area, framework, NIST subcategory format, and that every source is defined (or is an Entra data set / DNS_MailAuth).

    python validate_specs.py            # exit code 1 when there are errors
"""
from __future__ import annotations

import re
import sys

import workloads as wl

MODES = {"first", "all", "any", "none"}
OPS = {"eq", "ne", "in", "notin", "gt", "ge", "lt", "le", "exists", "notexists", "empty", "notempty", "contains", "notcontains", "regex",
       "startswith", "true", "false", "len_ge", "len_le"}
NO_VALUE = {"exists", "notexists", "empty", "notempty", "true", "false"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
AREAS = {"Entra ID", "Intune", "Exchange Online", "Teams", "SharePoint and OneDrive", "Security and compliance", "Azure (identity)"}
FRAMEWORKS = {"CISA SCuBA", "CIS Microsoft 365", "ORCA", "Zero Trust Assessment", "Jolera Extended Controls"}
NIST = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$")
REQUIRED = ("id", "reference", "framework", "area", "title", "severity", "source", "conditions")


def check_cond(c: dict, where: str, errors: list[str]) -> None:
    if "any" in c or "all" in c:
        for x in c.get("any", []) + c.get("all", []):
            check_cond(x, where, errors)
        return
    if "path" not in c or c.get("op") not in OPS:
        errors.append(f"{where}: bad condition {c}")
    elif c["op"] not in NO_VALUE and "value" not in c:
        errors.append(f"{where}: operator '{c['op']}' needs a value ({c['path']})")


def main() -> int:
    try:
        import entra_collect
        entra_sources = {d["name"] for d in entra_collect.DATASETS}
    except Exception:  # noqa: BLE001
        entra_sources = set()
    specs = wl.load_specs()
    defined = {"DNS_MailAuth"} | entra_sources
    for sp in specs:
        defined |= set((sp.get("sources") or {}).keys())
    errors: list[str] = []
    seen: dict[str, str] = {}
    total = 0
    for sp in specs:
        f = sp["_file"]
        for name, src in (sp.get("sources") or {}).items():
            t = src.get("type")
            if t not in ("graph", "exo", "teams", "arm"):
                errors.append(f"{f}: source {name}: unknown type {t}")
            elif t == "graph" and not (src.get("uri") and src.get("permission")):
                errors.append(f"{f}: source {name}: graph sources need uri and permission")
            elif t == "exo" and not re.fullmatch(r"Get-[A-Za-z0-9]+", src.get("cmdlet", "")):
                errors.append(f"{f}: source {name}: only Get-* cmdlets are allowed")
        for r in sp.get("rules", []):
            total += 1
            where = f"{f}:{r.get('id', '?')}"
            for k in REQUIRED:
                if not r.get(k) and k != "conditions":
                    errors.append(f"{where}: missing '{k}'")
            if "conditions" not in r:
                errors.append(f"{where}: missing 'conditions'")
            if r.get("id") in seen:
                errors.append(f"{where}: duplicate id (also in {seen[r['id']]})")
            seen[r.get("id")] = f
            if r.get("mode", "first") not in MODES:
                errors.append(f"{where}: bad mode {r.get('mode')}")
            if r.get("severity") not in SEVERITIES:
                errors.append(f"{where}: bad severity {r.get('severity')}")
            if r.get("area") not in AREAS:
                errors.append(f"{where}: bad area {r.get('area')}")
            if r.get("framework") not in FRAMEWORKS:
                errors.append(f"{where}: bad framework {r.get('framework')}")
            if r.get("nist") and not NIST.match(r["nist"]):
                errors.append(f"{where}: bad NIST id {r['nist']}")
            if not r.get("nist"):
                errors.append(f"{where}: no NIST subcategory")
            if r.get("source") not in defined:
                errors.append(f"{where}: source '{r.get('source')}' is not defined anywhere")
            for c in (r.get("conditions") or []) + (r.get("filter") or []):
                check_cond(c, where, errors)
            if not r.get("description") or not r.get("remediation"):
                errors.append(f"{where}: description and remediation are required")
    print(f"{len(specs)} spec files, {total} rules, {len(defined) - 1 - len(entra_sources)} spec sources")
    for e in errors:
        print("  ERROR", e)
    print("OK" if not errors else f"{len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
