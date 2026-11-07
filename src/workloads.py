"""Workload selection, spec-driven data sets and the non-Graph collectors used by entra_collect.py.

A company in companies.json can choose what is collected:
    "workloads": ["entra", "exchange"]          only these
    "exclude_workloads": ["intune"]             everything except these
    "domains": ["contoso.com", "contoso.ca"]    verified domains in scope for the DNS checks (default: all verified domains)
With neither key, every workload except "azure" is collected ("azure" needs --include-azure or an explicit "workloads" entry).

The data each workload needs is declared by the spec files in specs/ (see specs_loader). Nothing here changes the tenant: every
call is a read-only GET (Exchange cmdlets are limited to Get-*).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import paths

WORKLOADS = ["entra", "intune", "exchange", "teams", "sharepoint", "compliance", "defender", "azure"]
DEFAULT_WORKLOADS = [w for w in WORKLOADS if w != "azure"]
ALIASES = {"orca": "exchange", "purview": "compliance", "spo": "sharepoint"}
SPECS_DIR = paths.SPECS_DIR

EXO = "https://outlook.office365.com"
TEAMS_RESOURCE = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239"       # Skype and Teams Tenant Admin API
TEAMS_BASE = "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations"
ARM = "https://management.azure.com"
EXCHANGE_MANAGE_AS_APP = "Exchange.ManageAsApp"

# What each workload needs besides the Graph permissions that its specs declare. Shown by `entra_collect.py --permissions`.
EXTRA_REQUIREMENTS: dict[str, list[str]] = {
    "entra": [],
    "intune": [],
    "sharepoint": [],
    "exchange": ["Office 365 Exchange Online > Application permission Exchange.ManageAsApp (admin consent)",
                 "Entra role Global Reader (or Security Reader) assigned to the app's service principal"],
    "compliance": ["Same as exchange (audit and protection settings are read through Exchange Online)"],
    "teams": ["Entra role Global Reader (or Teams Administrator) assigned to the app's service principal (experimental: uses the Teams admin API, no Graph permission)"],
    "defender": [],
    "azure": ["Azure RBAC Reader at the tenant root scope (a Global Administrator may have to elevate access once to grant it)"],
}
# Graph application permissions every workload needs even when its specs declare none.
BASE_GRAPH = {"intune": ["DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All",
                         "DeviceManagementRBAC.Read.All", "DeviceManagementServiceConfig.Read.All"],
              "sharepoint": ["SharePointTenantSettings.Read.All"]}


class WorkloadError(Exception):
    pass


# service plans that show a workload is licensed in the tenant; data sets of an unlicensed workload are skipped, not "failed"
WORKLOAD_PLANS = {
    "exchange": {"EXCHANGE_S_ENTERPRISE", "EXCHANGE_S_STANDARD", "EXCHANGE_S_DESKLESS", "EXCHANGE_S_FOUNDATION", "EXCHANGE_L_STANDARD"},
    "compliance": {"EXCHANGE_S_ENTERPRISE", "EXCHANGE_S_STANDARD", "EXCHANGE_S_DESKLESS", "EXCHANGE_S_FOUNDATION", "EXCHANGE_L_STANDARD"},
    "intune": {"INTUNE_A", "INTUNE_O365", "INTUNE_SMBIZ"},
    "teams": {"TEAMS1", "TEAMS_FREE", "MCO_TEAMS_IW"},
    "sharepoint": {"SHAREPOINTENTERPRISE", "SHAREPOINTSTANDARD", "SHAREPOINTWAIT", "SHAREPOINTDESKLESS", "ONEDRIVE_BASIC_P2"},
}


def active_plans(skus: list[dict] | None) -> set[str] | None:
    if skus is None:
        return None
    return {sp.get("servicePlanName") for s_ in skus for sp in (s_.get("servicePlans") or []) if sp.get("provisioningStatus") == "Success"}


def unlicensed(workload: str, plans: set[str] | None) -> bool:
    need = WORKLOAD_PLANS.get(workload)
    return bool(need) and plans is not None and not (need & plans)


def token_roles(token: str) -> list[str]:
    import base64
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return list(json.loads(base64.urlsafe_b64decode(part)).get("roles", []))
    except Exception:  # noqa: BLE001
        return []


def normalize(name: str) -> str:
    n = str(name).strip().lower()
    return ALIASES.get(n, n)


def company_workloads(company: dict, include_azure: bool = False) -> list[str]:
    """The workloads to collect for one company entry of companies.json."""
    chosen = company.get("workloads")
    if chosen:
        enabled = [normalize(w) for w in chosen]
    else:
        enabled = list(DEFAULT_WORKLOADS)
        if include_azure:
            enabled.append("azure")
    enabled = [w for w in enabled if w not in {normalize(x) for x in company.get("exclude_workloads", [])}]
    if "entra" not in enabled and "entra" not in {normalize(x) for x in company.get("exclude_workloads", [])}:
        enabled.insert(0, "entra")   # the tenant data every other check needs
    return [w for w in WORKLOADS if w in enabled]


def validate_names(names: list[str], where: str) -> None:
    unknown = [n for n in names if normalize(n) not in WORKLOADS]
    if unknown:
        raise WorkloadError(f"{where}: unknown workload(s) {', '.join(unknown)}. Valid: {', '.join(WORKLOADS)}")


# ------------------------------------------------------------------------------ specs
def load_specs(specs_dir: Path | None = None) -> list[dict]:
    """Every spec file (a JSON object with a "workload" and "rules" and/or "sources")."""
    out = []
    for f in sorted((specs_dir or SPECS_DIR).glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise WorkloadError(f"{f.name} is not valid JSON: {exc}") from exc
        if isinstance(data, dict) and data.get("workload") and ("rules" in data or "sources" in data):
            data["_file"] = f.name
            data["workload"] = normalize(data["workload"])
            out.append(data)
    return out


def spec_datasets(specs: list[dict], enabled: list[str]) -> list[dict]:
    """Collector data set definitions (same shape as entra_collect.DATASETS) for the sources of the enabled workloads."""
    found: dict[str, dict] = {}
    for sp in specs:
        if sp["workload"] not in enabled:
            continue
        for name, src in (sp.get("sources") or {}).items():
            if name in found:
                continue
            t = src.get("type")
            d: dict[str, Any] = {"name": name, "workload": sp["workload"], "permission": src.get("permission")}
            if t == "graph":
                d.update(api=src.get("api", "v1.0"), uri=src["uri"])
            elif t == "exo":
                d.update(custom="exo", cmdlet=src["cmdlet"], params=src.get("params") or {}, uri=src["cmdlet"])
            elif t == "teams":
                d.update(custom="teams", config=src["config"], uri=src["config"])
            elif t == "arm":
                d.update(custom="arm", uri=src["uri"])
            else:
                continue
            found[name] = d
    return list(found.values())


def required_permissions(specs: list[dict], enabled: list[str]) -> dict[str, dict]:
    """{workload: {"graph": [permissions], "other": [text]}} for the enabled workloads."""
    out: dict[str, dict] = {}
    for w in enabled:
        graph = set(BASE_GRAPH.get(w, []))
        for sp in specs:
            if sp["workload"] == w:
                graph |= {s["permission"] for s in (sp.get("sources") or {}).values() if s.get("type") == "graph" and s.get("permission")}
        out[w] = {"graph": sorted(graph), "other": EXTRA_REQUIREMENTS.get(w, [])}
    return out


# ------------------------------------------------------------------------------ collectors
def collect_exo(client, tenant_id: str, d: dict) -> list[dict]:
    """Runs one read-only Get-* cmdlet through the Exchange Online admin REST endpoint (InvokeCommand)."""
    cmdlet = d["cmdlet"]
    if not re.fullmatch(r"Get-[A-Za-z0-9]+", cmdlet):
        raise WorkloadError(f"refusing to run '{cmdlet}': only Get-* cmdlets are allowed")
    roles = token_roles(client.token_provider(EXO))
    if EXCHANGE_MANAGE_AS_APP not in roles:
        raise WorkloadError("the Exchange token has no Exchange.ManageAsApp role. Add API permission Office 365 Exchange Online > Exchange.ManageAsApp "
                            "(application) to the app and grant admin consent; the Global Reader role alone is not enough")
    url = f"{EXO}/adminapi/beta/{tenant_id}/InvokeCommand"
    body = {"CmdletInput": {"CmdletName": cmdlet, "Parameters": d.get("params") or {}}}
    headers = {"X-AnchorMailbox": f"APP:SystemMailbox{{bb558c35-97f1-4cb9-8ff7-d53741dc928c}}@{tenant_id}", "X-ResponseFormat": "json",
               "X-ClientApplication": "ExoManagementModule", "Prefer": "odata.maxpagesize=1000"}
    rows: list[dict] = []
    while url:
        page = client.request("POST", url, resource=EXO, body=body, extra_headers=headers)
        rows.extend(page.get("value") or [])
        url = page.get("@odata.nextLink")
    return rows


def collect_teams(client, d: dict) -> list[dict]:
    page = client.request("GET", f"{TEAMS_BASE}/{d['config']}", resource=TEAMS_RESOURCE)
    if isinstance(page, list):
        return [x for x in page if isinstance(x, dict)]
    for key in ("Items", "items", "value"):
        if isinstance(page.get(key), list):
            return page[key]
    return [page] if page else []


def collect_arm(client, d: dict) -> list[dict]:
    page = client.request("GET", f"{ARM}/{d['uri'].lstrip('/')}", resource=ARM)
    return page.get("value") if isinstance(page.get("value"), list) else ([page] if page else [])


# ------------------------------------------------------------------------------ DNS (SPF, DKIM, DMARC)
def _txt(resolver, name: str) -> list[str]:
    try:
        return ["".join(part.decode() if isinstance(part, bytes) else str(part) for part in r.strings) for r in resolver.resolve(name, "TXT")]
    except Exception:  # noqa: BLE001 - NXDOMAIN, no answer, timeout: all mean "no record"
        return []


def _cname(resolver, name: str) -> str | None:
    try:
        return str(next(iter(resolver.resolve(name, "CNAME"))).target).rstrip(".")
    except Exception:  # noqa: BLE001
        return None


def _mx(resolver, name: str) -> list[str]:
    try:
        return sorted(str(r.exchange).rstrip(".").lower() for r in resolver.resolve(name, "MX"))
    except Exception:  # noqa: BLE001
        return []


def parse_spf(record: str | None) -> tuple[str | None, int]:
    if not record:
        return None, 0
    terms = record.lower().split()
    qualifier = next((t for t in terms if t in ("-all", "~all", "?all", "+all", "all")), None)
    lookups = sum(1 for t in terms if re.match(r"^[+\-~?]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", t))
    return ("+all" if qualifier == "all" else qualifier), lookups


def parse_dmarc(record: str | None) -> dict:
    tags = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100
    return {"policy": tags.get("p", "").lower() or None, "subdomain_policy": tags.get("sp", "").lower() or None, "pct": pct,
            "rua": tags.get("rua") or None, "ruf": tags.get("ruf") or None}


def collect_dns(domains: list[dict] | None, in_scope: list[str] | None = None, resolver=None) -> list[dict]:
    """One row per verified domain: MX, SPF, DMARC and the two DKIM selector CNAMEs. Uses the DNS resolver of the machine running the
    collector (public DNS), not Graph. `in_scope` limits it to the domains listed in companies.json."""
    if domains is None:
        raise WorkloadError("needs the Domains data set, which was not collected")
    if resolver is None:
        try:
            import dns.resolver  # dnspython
        except ImportError as exc:
            raise WorkloadError("the 'dnspython' package is not installed in this Python. Run: python -m pip install dnspython") from exc
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
    wanted = {d.lower() for d in in_scope or []}
    rows = []
    for dom in domains:
        name = str(dom.get("id") or "").lower()
        if not name or dom.get("isVerified") is False or (wanted and name not in wanted):
            continue
        spf = next((t for t in _txt(resolver, name) if t.lower().startswith("v=spf1")), None)
        dmarc_rec = next((t for t in _txt(resolver, f"_dmarc.{name}") if t.lower().startswith("v=dmarc1")), None)
        qualifier, lookups = parse_spf(spf)
        dm = parse_dmarc(dmarc_rec)
        rows.append({"domain": name, "is_initial": bool(dom.get("isInitial")), "is_default": bool(dom.get("isDefault")),
                     "authentication_type": dom.get("authenticationType"), "mx_records": _mx(resolver, name),
                     "spf_record": spf, "spf_all_qualifier": qualifier, "spf_lookup_count": lookups,
                     "dmarc_record": dmarc_rec, "dmarc_policy": dm["policy"], "dmarc_subdomain_policy": dm["subdomain_policy"], "dmarc_pct": dm["pct"],
                     "dmarc_rua": dm["rua"], "dmarc_ruf": dm["ruf"],
                     "dkim_selector1_cname": _cname(resolver, f"selector1._domainkey.{name}"),
                     "dkim_selector2_cname": _cname(resolver, f"selector2._domainkey.{name}")})
    return rows
