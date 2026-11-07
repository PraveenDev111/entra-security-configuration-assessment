"""Generic evaluator for the rule specs in specs/*.json (Intune, Exchange Online, Teams, SharePoint, compliance, Defender, Azure and
extra Entra checks). A spec rule names a data set, an optional filter, and conditions; this module turns it into a result record.
The format is described in specs/README.md. Called by entra_checks.py:  run_specs(engine, entra_checks_module).
"""
from __future__ import annotations

import re
from typing import Any

import workloads as wl

# service plans that show a workload is licensed (and therefore used) in the tenant
USAGE_PLANS = {
    "Intune": {"INTUNE_A", "INTUNE_O365", "INTUNE_SMBIZ"},
    "Exchange Online": {"EXCHANGE_S_ENTERPRISE", "EXCHANGE_S_STANDARD", "EXCHANGE_S_DESKLESS", "EXCHANGE_S_FOUNDATION", "EXCHANGE_L_STANDARD"},
    "Teams": {"TEAMS1", "TEAMS_FREE", "MCO_TEAMS_IW"},
    "SharePoint and OneDrive": {"SHAREPOINTENTERPRISE", "SHAREPOINTSTANDARD", "SHAREPOINTWAIT", "SHAREPOINTDESKLESS", "ONEDRIVE_BASIC_P2"},
}
# licence label used in a spec -> service plans that provide it (any of them is enough)
LICENCE_PLANS = {
    "entra id p1": {"AAD_PREMIUM", "AAD_PREMIUM_P2"},
    "entra id p2": {"AAD_PREMIUM_P2"},
    "entra id governance": {"ENTRA_ID_GOVERNANCE", "AAD_GOVERNANCE", "AAD_PREMIUM_P2"},
    "intune": {"INTUNE_A", "INTUNE_O365", "INTUNE_SMBIZ"},
    "defender for office 365 plan 1": {"ATP_ENTERPRISE", "THREAT_INTELLIGENCE"},
    "defender for office 365 plan 2": {"THREAT_INTELLIGENCE"},
    "defender for endpoint": {"MDE_LITE", "WINDEFATP", "MDE_SMB"},
}
NAME_KEYS = ("displayName", "DisplayName", "Name", "Identity", "domain", "name", "id", "Id")


# ------------------------------------------------------------------------------ value lookup and operators
def _key(d: dict, k: str):
    if k in d:
        return True, d[k]
    low = k.lower()
    for kk, vv in d.items():
        if str(kk).lower() == low:
            return True, vv
    return False, None


def _resolve(it: dict, rest: str):
    """Longest key of `it` that starts `rest` (keys such as '@odata.type' contain a dot). Returns (value, remaining path) or None."""
    best = None
    for k in it:
        ks = str(k)
        if (rest.lower() == ks.lower() or rest.lower().startswith(ks.lower() + ".")) and (best is None or len(ks) > len(best)):
            best = ks
    if best is None:
        return None
    return it[best], rest[len(best) + 1:]


def get_values(row: Any, path: str) -> tuple[list, bool]:
    """Values at a dotted path; lists met on the way are expanded. Returns (values, found)."""
    cur = [(row, path)]
    out: list = []
    while cur:
        nxt = []
        for node, rest in cur:
            items = node if isinstance(node, list) else [node]
            for it in items:
                if not isinstance(it, dict):
                    continue
                r = _resolve(it, rest)
                if r is None:
                    continue
                val, remaining = r
                if remaining:
                    nxt.append((val, remaining))
                else:
                    out.append(val)
        cur = nxt
    return out, bool(out)


def _norm(v):
    if isinstance(v, str):
        t = v.strip().lower()
        if t in ("true", "false"):
            return t == "true"
        return t
    return v


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _eq(a, b) -> bool:
    a, b = _norm(a), _norm(b)
    if a == b:
        return True
    na, nb = _num(a), _num(b)
    return na is not None and nb is not None and na == nb and not isinstance(a, bool) and not isinstance(b, bool)


def _empty(v) -> bool:
    return v is None or v == "" or v == [] or v == {}


POSITIVE = {"eq", "in", "gt", "ge", "lt", "le", "contains", "regex", "startswith", "true", "false", "len_ge", "len_le", "exists", "notempty"}


def _one(op: str, v, target) -> bool:
    if op == "eq":
        return _eq(v, target)
    if op == "ne":
        return not _eq(v, target)
    if op == "in":
        return any(_eq(v, t) for t in (target or []))
    if op == "notin":
        return not any(_eq(v, t) for t in (target or []))
    if op in ("gt", "ge", "lt", "le"):
        a, b = _num(v), _num(target)
        if a is None or b is None:
            return False
        return {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}[op]
    if op in ("contains", "notcontains"):
        if isinstance(v, list):
            hit = any(_eq(x, target) for x in v)
        else:
            hit = str(target).lower() in str(v if v is not None else "").lower()
        return hit if op == "contains" else not hit
    if op == "regex":
        return re.search(str(target), str(v if v is not None else ""), re.I) is not None
    if op == "startswith":
        return str(v if v is not None else "").lower().startswith(str(target).lower())
    if op == "true":
        return _norm(v) is True
    if op == "false":
        return _norm(v) is False
    if op == "exists":
        return v is not None
    if op == "notexists":
        return v is None
    if op == "empty":
        return _empty(v)
    if op == "notempty":
        return not _empty(v)
    if op == "len_ge":
        return v is not None and len(v) >= target
    if op == "len_le":
        return v is not None and len(v) <= target
    raise ValueError(f"unknown operator '{op}'")


def eval_cond(row: dict, c: dict) -> bool:
    if "any" in c:
        return any(eval_cond(row, x) for x in c["any"])
    if "all" in c:
        return all(eval_cond(row, x) for x in c["all"])
    op = c["op"]
    vals, found = get_values(row, c["path"])
    if not found or not vals:
        return op not in POSITIVE   # a missing value satisfies only the negative operators
    if op in ("contains", "regex", "startswith"):   # over a list of values (path crosses a list): any element is enough
        return any(_one(op, v, c.get("value")) for v in vals)
    return all(_one(op, v, c.get("value")) for v in vals)


def _show(v) -> str:
    if v is None:
        return "not set"
    if isinstance(v, list):
        return ", ".join(map(str, v[:6])) + (" ..." if len(v) > 6 else "") if v else "empty"
    if isinstance(v, dict):
        return "{...}"
    return str(v)


def describe(row: dict, conds: list[dict]) -> str:
    parts = []
    for c in conds:
        if "path" not in c:
            parts.append("any/all of several settings")
            continue
        vals, _ = get_values(row, c["path"])
        parts.append(f"{c['path']} = {', '.join(_show(v) for v in vals) if vals else 'not set'}")
    return "; ".join(parts[:4])


def expected_text(rule: dict) -> str:
    if rule.get("expected"):
        return rule["expected"]
    sym = {"eq": "=", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<=", "in": "in", "notin": "not in", "true": "is true", "false": "is false",
           "exists": "is set", "notexists": "is not set", "empty": "is empty", "notempty": "is not empty", "contains": "contains", "notcontains": "does not contain",
           "regex": "matches", "startswith": "starts with", "len_ge": "has at least", "len_le": "has at most"}

    def one(c):
        if "any" in c:
            return "(" + " or ".join(one(x) for x in c["any"]) + ")"
        if "all" in c:
            return "(" + " and ".join(one(x) for x in c["all"]) + ")"
        v = c.get("value")
        return f"{c['path']} {sym.get(c['op'], c['op'])}" + (f" {v}" if c["op"] not in ("true", "false", "exists", "notexists", "empty", "notempty") else "")
    scope = {"all": "Every", "any": "At least one", "none": "No", "first": "The"}.get(rule.get("mode", "first"), "Every")
    return f"{scope} {rule.get('source', 'item')} entry: " + "; ".join(one(c) for c in rule.get("conditions", []))


def row_name(row: dict, rule: dict) -> str:
    for k in ([rule["name"]] if rule.get("name") else []) + list(NAME_KEYS):
        ok, v = _key(row, k)
        if ok and v not in (None, ""):
            return str(v)
    return "(unnamed)"


# ------------------------------------------------------------------------------ one rule
def evaluate(rule: dict, rows: list[dict]) -> dict:
    mode = rule.get("mode", "first")
    conds = rule.get("conditions") or []
    considered = [r for r in rows if isinstance(r, dict) and all(eval_cond(r, c) for c in rule.get("filter") or [])]
    if not considered:
        msg = rule.get("empty_message") or "No applicable objects found"
        if rule.get("fail_if_empty") or mode == "any":
            return {"pass": False, "actual": msg}
        return {"skip": msg, "kind": "not_applicable"}
    if mode == "first":
        row = considered[0]
        ok = all(eval_cond(row, c) for c in conds)
        return {"pass": ok, "actual": describe(row, conds), "affected": [] if ok else [row_name(row, rule)]}
    hits = [r for r in considered if all(eval_cond(r, c) for c in conds)]
    if mode == "all":
        bad = [r for r in considered if r not in hits]
        names = [row_name(r, rule) for r in bad]
        return {"pass": not bad, "affected": names,
                "actual": (f"All {len(considered)} meet the requirement" if not bad else f"{len(bad)} of {len(considered)} do not meet it: " + "; ".join(names[:25]))}
    if mode == "any":
        return {"pass": bool(hits), "actual": f"{len(hits)} of {len(considered)} meet the requirement" if hits else f"None of {len(considered)} meets the requirement"}
    if mode == "none":
        names = [row_name(r, rule) for r in hits]
        return {"pass": not hits, "affected": names, "actual": "None found" if not hits else f"{len(hits)} found: " + "; ".join(names[:25])}
    raise ValueError(f"unknown mode '{mode}'")


# ------------------------------------------------------------------------------ licences and workload use
def active_plans(e) -> set[str] | None:
    skus = e.ds("SubscribedSkus")
    if skus is None:
        return None
    return {sp.get("servicePlanName") for s in skus for sp in (s.get("servicePlans") or []) if sp.get("provisioningStatus") == "Success"}


def run_specs(e, lib) -> int:
    """Evaluates every spec rule of the workloads collected for this run. Returns how many rules ran."""
    enabled = (e.manifest or {}).get("workloads") or ["entra"]
    plans = active_plans(e)
    seen: set[str] = set()
    count = 0
    for sp in wl.load_specs():
        if sp["workload"] not in enabled:
            continue
        for rule in sp.get("rules", []):
            rid = rule["id"]
            if rid in seen:
                continue
            seen.add(rid)
            lib.SEVERITY[rid] = rule.get("severity", "Medium")
            details = {k: rule[k] for k in ("description", "remediation", "impact") if rule.get(k)}
            if rule.get("links"):
                details["links"] = rule["links"]
            meta = {"area": rule.get("area") or "Entra ID", "nist": rule.get("nist") or "", "required_licence": rule.get("licence") or "",
                    "details": details or None, "origin": rule.get("origin", "")}
            expected = expected_text(rule)
            area = meta["area"]
            title = rule["title"]

            if plans is not None and area in USAGE_PLANS and not (USAGE_PLANS[area] & plans):
                e.add(rid, rule["reference"], rule["framework"], title, "Skipped", expected, reason=f"{area} is not licensed or used in this tenant",
                      dataset=rule.get("source", ""), kind="not_applicable", **meta)
                count += 1
                continue
            need = LICENCE_PLANS.get(str(rule.get("licence") or "").lower())
            if plans is not None and need and not (need & plans):
                e.add(rid, rule["reference"], rule["framework"], title, "Skipped", expected, reason=f"Requires {rule['licence']}, which this tenant does not have",
                      dataset=rule.get("source", ""), kind="licensing", **meta)
                count += 1
                continue
            e.run(rid, rule["reference"], rule["framework"], title, expected,
                  (lambda r=rule: evaluate(r, (e.ds(r["source"]) or []))), needs=(rule["source"],), meta=meta)
            count += 1
    return count
