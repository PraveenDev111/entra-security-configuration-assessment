#!/usr/bin/env python3
"""Builds <output-dir>/dashboard_data.js: a compact summary of the newest runs per company (overview figures and check results).

For every company folder in the output directory it takes the newest runs, summarises the collected raw data for the
Overview page (users, risk, privileged roles, devices, applications, licences, ...) and adds the check results for the
Security assessment page. entra_checks.py calls this automatically after each run; you can also run it alone:

    python src/dashboard_data.py [output-dir] [--keep 3]

Writes <output-dir>/dashboard_data.js.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import paths
from typing import Any

MICROSOFT_TENANTS = {"72f988bf-86f1-41af-91ab-2d7cd011db47", "f8cdef31-a31e-4b4a-93e4-5f571e91255a"}
PHISH_RESISTANT = {"fido2SecurityKey", "passKeyDeviceBound", "passKeyDeviceBoundAuthenticator", "windowsHelloForBusiness"}
PASSWORDLESS = PHISH_RESISTANT | {"microsoftAuthenticatorPasswordless"}
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def lc(x: Any) -> str:
    return str(x if x is not None else "").lower()


def parse_dt(v: Any) -> dt.datetime | None:
    if not v:
        return None
    try:
        d = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


class Raw:
    """Lazy reader for one run's raw/*.json; remembers why a data set is missing."""

    def __init__(self, run_dir: Path, manifest: dict):
        self.dir, self.manifest, self.cache = run_dir / "raw", manifest, {}

    def get(self, name: str) -> list | None:
        if name not in self.cache:
            f = self.dir / f"{name}.json"
            try:
                self.cache[name] = json.loads(f.read_text(encoding="utf-8")) if f.exists() else None
            except (OSError, ValueError):
                self.cache[name] = None
        return self.cache[name]

    def why(self, name: str) -> str:
        for e in self.manifest.get("datasets", []):
            if e.get("dataset") == name:
                return "Not collected: " + str(e.get("error") or e.get("status"))
        return "Data set was not part of this run"


def section(raw: Raw, needs: tuple, fn) -> dict:
    """Runs fn(*datasets) and returns it as {"data": ...}, or {"unavailable": reason} when a data set is missing."""
    rows = [raw.get(n.lstrip("?")) for n in needs]
    for n, r in zip(needs, rows):
        if r is None and not n.startswith("?"):  # a name starting with "?" is optional and becomes an empty list
            return {"unavailable": raw.why(n)}
    rows = [r if r is not None else [] for r in rows]
    try:
        return {"data": fn(*rows)}
    except Exception as exc:  # noqa: BLE001 - one broken section must not stop the dashboard
        return {"unavailable": f"Could not summarise: {exc}"}


def count_by(rows, key, default="Unknown") -> dict:
    out: dict[str, int] = {}
    for r in rows:
        k = str(key(r) or default)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# ------------------------------------------------------------------------------ sections
def tenant(org, domains, skus):
    o = org[0] if org else {}
    default = next((d.get("id") for d in domains if d.get("isDefault")), None) or next((v.get("name") for v in o.get("verifiedDomains", []) if v.get("isDefault")), None)
    plans = {sp.get("servicePlanName") for s in skus for sp in s.get("servicePlans", []) if sp.get("provisioningStatus") == "Success"}
    plan = "Entra ID P2" if "AAD_PREMIUM_P2" in plans else "Entra ID P1" if "AAD_PREMIUM" in plans else "Entra ID Free"
    return {"name": o.get("displayName"), "id": o.get("id"), "default_domain": default, "plan": plan, "created": o.get("createdDateTime"),
            "synced": bool(o.get("onPremisesSyncEnabled")), "domains": len(domains),
            "federated_domains": sum(1 for d in domains if d.get("authenticationType") == "Federated")}


def users(rows):
    now = dt.datetime.now(dt.timezone.utc)
    guests = [u for u in rows if u.get("userType") == "Guest"]
    members = [u for u in rows if u.get("userType") != "Guest"]
    stale, known = 0, 0
    for u in members:
        if u.get("accountEnabled") is not True:
            continue
        last = parse_dt((u.get("signInActivity") or {}).get("lastSuccessfulSignInDateTime") or (u.get("signInActivity") or {}).get("lastSignInDateTime"))
        if last:
            known += 1
            if (now - last).days > 90:
                stale += 1
    return {"total": len(rows), "members": len(members), "guests": len(guests), "enabled": sum(1 for u in rows if u.get("accountEnabled") is True),
            "disabled": sum(1 for u in rows if u.get("accountEnabled") is False), "synced": sum(1 for u in members if u.get("onPremisesSyncEnabled") is True),
            "cloud_only": sum(1 for u in members if u.get("onPremisesSyncEnabled") is not True), "stale_90d": stale, "with_signin_data": known,
            "licensed": sum(1 for u in rows if u.get("assignedLicenses"))}


def groups(rows):
    return {"total": len(rows), "security": sum(1 for g in rows if g.get("securityEnabled") is True),
            "microsoft365": sum(1 for g in rows if "Unified" in (g.get("groupTypes") or [])),
            "dynamic": sum(1 for g in rows if "DynamicMembership" in (g.get("groupTypes") or [])),
            "role_assignable": sum(1 for g in rows if g.get("isAssignableToRole") is True)}


def mfa(rows):
    reg = sum(1 for u in rows if u.get("isMfaRegistered") and u.get("isMfaCapable") is not False)
    notcap = sum(1 for u in rows if u.get("isMfaRegistered") and u.get("isMfaCapable") is False)
    methods: dict[str, int] = {}
    for u in rows:
        for m in u.get("methodsRegistered") or []:
            methods[m] = methods.get(m, 0) + 1
    return {"total": len(rows), "registered": reg, "not_capable": notcap, "not_registered": len(rows) - reg - notcap,
            "passwordless": sum(1 for u in rows if PASSWORDLESS & set(u.get("methodsRegistered") or [])),
            "phishing_resistant": sum(1 for u in rows if PHISH_RESISTANT & set(u.get("methodsRegistered") or [])),
            "sspr_registered": sum(1 for u in rows if u.get("isSsprRegistered")),
            "methods": dict(sorted(methods.items(), key=lambda kv: -kv[1])[:8])}


def risk(users_, dets, sps):
    at = [u for u in users_ if lc(u.get("riskState")) in ("atrisk", "confirmedcompromised")]
    lv = {"high": 0, "medium": 0, "low": 0, "hidden": 0}
    for u in at:
        l = lc(u.get("riskLevel"))
        lv[l if l in lv else "hidden"] += 1
    open_ = [d for d in dets if lc(d.get("riskState")) == "atrisk"]
    items = sorted(dets, key=lambda d: str(d.get("detectedDateTime") or ""), reverse=True)[:6]
    return {"users_at_risk": len(at), "levels": lv, "detections_total": len(dets), "detections_open": len(open_),
            "workload_identities_at_risk": sum(1 for s in sps if lc(s.get("riskState")) == "atrisk"),
            "recent": [{"time": d.get("detectedDateTime"), "type": d.get("riskEventType"), "target": d.get("userPrincipalName") or d.get("userDisplayName"),
                        "level": lc(d.get("riskLevel")) or "unknown", "state": d.get("riskState")} for d in items]}


def privileged(defs, assigns, elig, sched, control_plane):
    roles = {r["id"]: r.get("displayName") or r["id"] for r in defs if r.get("isPrivileged") is True or r.get("id") in control_plane}
    if not roles:
        raise ValueError("no privileged roles identified in the role definitions")

    def principals(rows, flt=None):
        per_role: dict[str, set] = {}
        for a in rows:
            if a.get("roleDefinitionId") not in roles or (flt and not flt(a)):
                continue
            t = (a.get("principal") or {}).get("@odata.type")
            if t and t != "#microsoft.graph.user":
                continue
            per_role.setdefault(a["roleDefinitionId"], set()).add(a.get("principalId"))
        return per_role
    perm = principals(sched, lambda a: a.get("assignmentType") == "Assigned" and ((a.get("scheduleInfo") or {}).get("expiration") or {}).get("type") == "noExpiration") if sched else principals(assigns)
    el = principals(elig)
    rows = []
    for rid, name in roles.items():
        p, e = len(perm.get(rid, ())), len(el.get(rid, ()))
        if p or e:
            rows.append({"role": name, "permanent": p, "eligible": e})
    rows.sort(key=lambda r: -(r["permanent"] + r["eligible"]))
    allp = set().union(*perm.values()) if perm else set()
    alle = set().union(*el.values()) if el else set()
    return {"accounts": len(allp | alle), "permanent": len(allp), "eligible": len(alle), "roles": rows[:10]}


def global_admins(assigns, elig, sched):
    """Holders of the Global Administrator role (role template id is the same in every tenant). CISA recommends 2 to 8."""
    def split(rows, flt=None):
        users: set = set()
        sps: set = set()
        groups: set = set()
        for a in rows:
            if a.get("roleDefinitionId") != GLOBAL_ADMIN or (flt and not flt(a)):
                continue
            t = (a.get("principal") or {}).get("@odata.type") or "#microsoft.graph.user"
            (sps if t.endswith("servicePrincipal") else groups if t.endswith("group") else users).add(a.get("principalId"))
        return users, sps, groups
    permanent = (lambda a: a.get("assignmentType") == "Assigned" and ((a.get("scheduleInfo") or {}).get("expiration") or {}).get("type") == "noExpiration")
    pu, ps, pg = split(sched, permanent) if sched else split(assigns)
    eu, es, eg = split(elig)
    return {"count": len(pu | eu), "permanent": len(pu), "eligible": len(eu), "service_principals": len(ps | es), "groups": len(pg | eg),
            "recommended_min": 2, "recommended_max": 8}


def conditional_access(rows):
    def mfa_required(p):
        g = p.get("grantControls") or {}
        return "mfa" in (g.get("builtInControls") or []) or bool(g.get("authenticationStrength"))
    states = count_by(rows, lambda p: p.get("state"))
    enabled = [p for p in rows if p.get("state") == "enabled"]
    return {"total": len(rows), "enabled": len(enabled), "report_only": states.get("enabledForReportingButNotEnforced", 0), "disabled": states.get("disabled", 0),
            "require_mfa": sum(1 for p in enabled if mfa_required(p)), "block": sum(1 for p in enabled if "block" in ((p.get("grantControls") or {}).get("builtInControls") or [])),
            "policies": [{"name": p.get("displayName"), "state": p.get("state")} for p in sorted(rows, key=lambda p: str(p.get("displayName")))][:40]}


def devices(rows):
    trust = {"AzureAd": "Entra joined", "ServerAd": "Hybrid joined", "Workplace": "Entra registered"}
    return {"total": len(rows), "compliant": sum(1 for d in rows if d.get("isCompliant") is True), "non_compliant": sum(1 for d in rows if d.get("isCompliant") is False),
            "unknown": sum(1 for d in rows if d.get("isCompliant") is None), "managed": sum(1 for d in rows if d.get("isManaged") is True),
            "by_os": dict(list(count_by(rows, lambda d: d.get("operatingSystem")).items())[:6]),
            "by_join": count_by(rows, lambda d: trust.get(d.get("trustType"), d.get("trustType")), "Unknown")}


def applications(apps, sps):
    now = dt.datetime.now(dt.timezone.utc)
    multi = ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount")
    expiring, expired, with_secret = [], 0, 0
    for a in apps:
        if a.get("passwordCredentials"):
            with_secret += 1
        for kind, key in (("Secret", "passwordCredentials"), ("Certificate", "keyCredentials")):
            for c in a.get(key) or []:
                end = parse_dt(c.get("endDateTime"))
                if not end:
                    continue
                days = (end - now).days
                if days < 0:
                    expired += 1
                if days <= 30:
                    expiring.append({"app": a.get("displayName"), "type": kind, "days": days, "ends": c.get("endDateTime")})
    expiring.sort(key=lambda x: x["days"])
    ent = [s for s in sps if s.get("servicePrincipalType") == "Application" and s.get("appOwnerOrganizationId") not in MICROSOFT_TENANTS]
    return {"registrations": len(apps), "with_secrets": with_secret, "multitenant": sum(1 for a in apps if a.get("signInAudience") in multi),
            "no_owner": sum(1 for a in apps if not a.get("owners")), "credentials_expired": expired,
            "credentials_expiring_30d": sum(1 for x in expiring if x["days"] >= 0), "expiring": expiring[:8],
            "enterprise_apps": len(ent), "enterprise_no_assignment_required": sum(1 for s in ent if s.get("appRoleAssignmentRequired") is False),
            "enterprise_disabled": sum(1 for s in ent if s.get("accountEnabled") is False), "service_principals_total": len(sps),
            "managed_identities": sum(1 for s in sps if s.get("servicePrincipalType") == "ManagedIdentity"),
            "microsoft_apps": sum(1 for s in sps if s.get("appOwnerOrganizationId") in MICROSOFT_TENANTS)}


def licences(skus):
    out = []
    for s in skus:
        total = (s.get("prepaidUnits") or {}).get("enabled") or 0
        if total and total < 1_000_000:
            out.append({"sku": s.get("skuPartNumber"), "used": s.get("consumedUnits") or 0, "total": total})
    return sorted(out, key=lambda x: -x["total"])[:8]


def recommendations(rows):
    return {"total": len(rows), "by_status": count_by(rows, lambda r: r.get("status")), "high_priority_open": sum(1 for r in rows if r.get("priority") == "high" and r.get("status") in ("active", "postponed"))}


def overview(run_dir: Path, manifest: dict, control_plane: set[str]) -> dict:
    raw = Raw(run_dir, manifest)
    ov = {
        "tenant": section(raw, ("Organization", "Domains", "SubscribedSkus"), tenant),
        "users": section(raw, ("Users",), users),
        "groups": section(raw, ("Groups",), groups),
        "mfa": section(raw, ("MfaRegistration",), mfa),
        "risk": section(raw, ("RiskyUsers", "RiskDetections", "?RiskyServicePrincipals"), risk),
        "privileged": section(raw, ("RoleDefinitions", "RoleAssignments", "?RoleEligibility", "?RoleAssignmentSchedules"), lambda d, a, e, s: privileged(d, a, e, s, control_plane)),
        "global_admins": section(raw, ("RoleAssignments", "?RoleEligibility", "?RoleAssignmentSchedules"), global_admins),
        "conditional_access": section(raw, ("CA_Policies",), conditional_access),
        "devices": section(raw, ("Devices",), devices),
        "applications": section(raw, ("Applications", "ServicePrincipals"), applications),
        "licences": section(raw, ("SubscribedSkus",), licences),
        "recommendations": section(raw, ("Entra_Recommendations",), recommendations),
    }
    ds = manifest.get("datasets", [])
    ov["collection"] = {"ok": sum(1 for d in ds if d.get("status") == "OK"),
                        "failed": [{"dataset": d.get("dataset"), "error": d.get("error") or d.get("status")} for d in ds if d.get("status") != "OK"]}
    return ov


# ------------------------------------------------------------------------------ bundle
def build(output_dir: Path, keep: int = 3, control_plane: set[str] | None = None) -> Path:
    control_plane = control_plane or set()
    companies: dict[str, dict] = {}
    for mf in sorted(output_dir.glob("*/*/manifest.json")):
        try:
            manifest = json.loads(mf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        run_dir = mf.parent
        cid = manifest.get("company_id") or run_dir.parent.name
        c = companies.setdefault(cid, {"id": cid, "name": manifest.get("company_name") or cid, "runs": []})
        run = {"run_id": manifest.get("run_id") or run_dir.name, "collected": manifest.get("collected_at"), "tenant_id": manifest.get("tenant_id"),
               "tenant_name": manifest.get("tenant_name"), "app": manifest.get("app"), "_dir": run_dir, "_manifest": manifest}
        c["runs"].append(run)
    out = []
    for c in sorted(companies.values(), key=lambda x: x["name"].lower()):
        c["runs"].sort(key=lambda r: str(r.get("collected") or ""), reverse=True)
        runs = []
        for i, r in enumerate(c["runs"][:keep]):
            run_dir, manifest = r.pop("_dir"), r.pop("_manifest")
            r["overview"] = overview(run_dir, manifest, control_plane)
            rf, sf = run_dir / "enriched" / "check_results.json", run_dir / "enriched" / "check_summary.json"
            try:
                r["results"] = json.loads(rf.read_text(encoding="utf-8"))["results"] if rf.exists() else None
                r["summary"] = json.loads(sf.read_text(encoding="utf-8"))["summary"] if sf.exists() else None
                r["checked_at"] = json.loads(rf.read_text(encoding="utf-8")).get("checked_at") if rf.exists() else None
            except (OSError, ValueError, KeyError):
                r["results"] = r["summary"] = r["checked_at"] = None
            runs.append(r)
        out.append({"id": c["id"], "name": c["name"], "runs": runs})
    bundle = {"schema": 2, "generated": dt.datetime.now(dt.timezone.utc).isoformat(), "companies": out}
    target = output_dir / "dashboard_data.js"
    target.write_text("window.SECUREIT_DATA = " + json.dumps(bundle, ensure_ascii=True, separators=(",", ":")) + ";\n", encoding="utf-8")
    return target


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output_dir", nargs="?", default=None, help="folder with the company/run folders (default: runs in the project root, or SECUREIT_OUTPUT_DIR)")
    ap.add_argument("--keep", type=int, default=3, help="newest runs per company to include (default: 3)")
    args = ap.parse_args(argv)
    out = Path(args.output_dir) if args.output_dir else paths.output_dir()
    if not out.is_dir():
        sys.exit(f"{out} is not a folder")
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from entra_checks import CONTROL_PLANE_ROLES as cp  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        cp = set()
    target = build(out, args.keep, set(cp))
    print(f"Wrote {target} ({target.stat().st_size // 1024} KB). Summary data for the runs in {out.name} refreshed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
