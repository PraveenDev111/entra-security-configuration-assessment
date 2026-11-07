#!/usr/bin/env python3
"""Pull Entra ID configuration data for one or more companies through Microsoft Graph and save it as raw JSON.

Read-only. Each company in companies.json gets its own run folder:

    <output-dir>/<company_id>/<run-id>/raw/<DataSet>.json        one file per data set
    <output-dir>/<company_id>/<run-id>/manifest.json             what was collected, what failed, company and tenant
    <output-dir>/last_run.json                                   the run folders of this batch (read by the other scripts)

config/companies.json (the app label is NOT a secret, the client id and secret are; see config/companies.example.json):

    {
      "companies": [
        {"company_name": "Contoso Ltd",  "company_id": "contoso",  "tenant_id": "<tenant id>", "app": "app-1",
         "emergency_access_ids": ["<break-glass user or group object id>"]},
        {"company_name": "Fabrikam Inc", "company_id": "fabrikam", "tenant_id": "<tenant id>", "app": "app-2", "enabled": false}
      ]
    }

"emergency_access_ids" (optional) are used by the break-glass checks; "enabled": false (optional) skips a company.

Credentials live in environment variables (or a .env file, see .env.example), one pair per app label:

    app-1  ->  ENTRA_APP_1_CLIENT_ID, ENTRA_APP_1_CLIENT_SECRET
    app-2  ->  ENTRA_APP_2_CLIENT_ID, ENTRA_APP_2_CLIENT_SECRET

Sign-in is a client secret (client-credentials flow). The app registration needs these Microsoft Graph application
permissions, with admin consent in the company's tenant:
  AuditLog.Read.All, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All,
  RoleEligibilitySchedule.Read.Directory, RoleManagementPolicy.Read.Directory, RoleManagementAlert.Read.Directory,
  OnPremDirectorySynchronization.Read.All, EntitlementManagement.Read.All, DirectoryRecommendations.Read.All
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable

import requests

import paths
import workloads as wl

TOOL_VERSION = "1.1"
GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"

REQUIRED_APP_ROLES = [
    "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All",
    "RoleManagement.Read.All", "RoleEligibilitySchedule.Read.Directory", "RoleManagementPolicy.Read.Directory",
    "RoleManagementAlert.Read.Directory", "OnPremDirectorySynchronization.Read.All", "EntitlementManagement.Read.All",
    "DirectoryRecommendations.Read.All", "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All",
    "IdentityRiskyServicePrincipal.Read.All",
]

PIM_ALERT = ("identityGovernance/roleManagementAlerts/alerts/DirectoryRole_{tenantId}_%s"
             "?$expand=alertDefinition,alertConfiguration,alertIncidents")

# Scope: Microsoft Entra identity only (no Intune, Exchange, Teams, Defender, networking or Azure workloads).
# name: file name. api: Graph version. uri: relative URL. large: skipped with --skip-large.
# fan_out: run one request per record of another data set ({id} in path). custom: handled by code.
DATASETS: list[dict[str, Any]] = [
    # Conditional Access
    {"name": "CA_Policies", "api": "beta", "uri": "identity/conditionalAccess/policies"},
    {"name": "CA_NamedLocations", "api": "beta", "uri": "identity/conditionalAccess/namedLocations"},
    {"name": "CA_AuthStrengths", "api": "beta", "uri": "policies/authenticationStrengthPolicies"},
    # Tenant policies
    {"name": "AuthorizationPolicy", "api": "beta", "uri": "policies/authorizationPolicy"},
    {"name": "AuthMethodsPolicy", "api": "beta", "uri": "policies/authenticationMethodsPolicy"},
    {"name": "AuthMethodConfigs", "api": "beta", "uri": "policies/authenticationMethodsPolicy?$expand=authenticationMethodConfigurations",
     "unwrap": "authenticationMethodConfigurations"},
    {"name": "AdminConsentPolicy", "api": "beta", "uri": "policies/adminConsentRequestPolicy"},
    {"name": "DeviceRegPolicy", "api": "beta", "uri": "policies/deviceRegistrationPolicy"},
    {"name": "CrossTenantDefault", "api": "beta", "uri": "policies/crossTenantAccessPolicy/default"},
    {"name": "DefaultAppMgmtPolicy", "api": "beta", "uri": "policies/defaultAppManagementPolicy"},
    {"name": "AuthFlowsPolicy", "api": "beta", "uri": "policies/authenticationFlowsPolicy"},
    {"name": "Legacy_Policies", "api": "beta", "uri": "legacy/policies"},
    {"name": "SecurityDefaults", "api": "v1.0", "uri": "policies/identitySecurityDefaultsEnforcementPolicy"},
    # Tenant / licensing
    {"name": "Organization", "api": "v1.0", "uri": "organization"},
    {"name": "Domains", "api": "v1.0", "uri": "domains"},
    {"name": "SubscribedSkus", "api": "v1.0", "uri": "subscribedSkus"},
    {"name": "DirectorySettings", "api": "beta", "uri": "settings"},
    {"name": "OnPremSync", "api": "beta", "uri": "directory/onPremisesSynchronization"},
    # Roles / PIM
    {"name": "RoleDefinitions", "api": "v1.0", "uri": "roleManagement/directory/roleDefinitions"},
    {"name": "RoleAssignments", "api": "beta", "uri": "roleManagement/directory/roleAssignments?$expand=principal"},
    {"name": "RoleEligibility", "api": "v1.0", "uri": "roleManagement/directory/roleEligibilitySchedules?$expand=principal"},
    {"name": "RoleAssignmentSchedules", "api": "v1.0", "uri": "roleManagement/directory/roleAssignmentSchedules?$expand=principal"},
    {"name": "RoleMgmtPolicies", "api": "v1.0",
     "uri": "policies/roleManagementPolicyAssignments?$filter=scopeId%20eq%20'/'%20and%20scopeType%20eq%20'DirectoryRole'&$expand=policy($expand=rules)"},
    {"name": "DirectoryRoles", "api": "v1.0", "uri": "directoryRoles"},
    {"name": "PIM_Alert_StaleSignIn", "api": "beta", "uri": PIM_ALERT % "StaleSignInAlert"},
    {"name": "PIM_Alert_Redundant", "api": "beta", "uri": PIM_ALERT % "RedundantAssignmentAlert"},
    {"name": "PIM_Alert_OutsidePim", "api": "beta", "uri": PIM_ALERT % "RolesAssignedOutsidePimAlert"},
    {"name": "PIM_Alert_TooManyGA", "api": "beta", "uri": PIM_ALERT % "TooManyGlobalAdminsAssignedToTenantAlert"},
    # Identity
    {"name": "MfaRegistration", "api": "beta", "uri": "reports/authenticationMethods/userRegistrationDetails", "large": True},
    {"name": "Users", "api": "beta", "large": True,
     "uri": "users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,"
            "assignedLicenses,signInActivity,lastPasswordChangeDateTime,mailNickname,onPremisesSamAccountName,"
            "onPremisesDistinguishedName&$top=999"},
    {"name": "Groups", "api": "v1.0", "large": True,
     "uri": "groups?$select=id,displayName,securityEnabled,groupTypes,membershipRule,isAssignableToRole,visibility,"
            "onPremisesSyncEnabled&$top=999"},
    {"name": "Applications", "api": "v1.0", "large": True,
     "uri": "applications?$select=id,displayName,appId,signInAudience,createdDateTime,passwordCredentials,keyCredentials,"
            "tags,web,spa,publicClient,servicePrincipalLockConfiguration"
            "&$expand=owners($select=id,displayName,userPrincipalName)"},
    {"name": "ServicePrincipals", "api": "v1.0", "large": True,
     "uri": "servicePrincipals?$select=id,displayName,appDisplayName,appId,servicePrincipalType,accountEnabled,"
            "appRoleAssignmentRequired,signInAudience,appOwnerOrganizationId,passwordCredentials,keyCredentials,replyUrls"
            "&$expand=owners($select=id,displayName,userPrincipalName)"},
    {"name": "SP_AppRoleAssignments", "api": "v1.0", "large": True, "fan_out": "ServicePrincipals",
     "path": "servicePrincipals/{id}/appRoleAssignments"},
    {"name": "SP_Oauth2Grants", "api": "v1.0", "large": True, "fan_out": "ServicePrincipals",
     "path": "servicePrincipals/{id}/oauth2PermissionGrants"},
    {"name": "Devices", "api": "v1.0", "large": True,
     "uri": "devices?$select=id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,isCompliant,"
            "isManaged,managementType,profileType,registrationDateTime,approximateLastSignInDateTime&$top=999"},
    {"name": "AppProxy_Apps", "api": "beta", "large": True, "fan_out": "Applications",
     "fan_filter": lambda a: "WindowsAzureActiveDirectoryOnPremApp" in (a.get("tags") or []),
     "path": "applications/{id}?$select=id,displayName,appId,onPremisesPublishing"},
    {"name": "Guest_Sponsors", "api": "v1.0", "large": True, "fan_out": "Users", "fan_filter": lambda u: u.get("userType") == "Guest",
     "path": "users/{id}/sponsors?$select=id"},
    # Identity Protection (Entra ID P2)
    # all levels and states; riskLevel is "hidden" when the tenant's licence does not show risk details
    {"name": "RiskyUsers", "api": "v1.0", "uri": "identityProtection/riskyUsers"},
    {"name": "RiskDetections", "api": "v1.0", "uri": "identityProtection/riskDetections"},
    {"name": "RiskyServicePrincipals", "api": "v1.0", "uri": "identityProtection/riskyServicePrincipals"},
    {"name": "SP_RiskDetections", "api": "beta", "uri": "identityProtection/servicePrincipalRiskDetections"},
    # Governance
    {"name": "EntMgmt_AccessPackages", "api": "beta", "uri": "identityGovernance/entitlementManagement/accessPackages"},
    {"name": "EntMgmt_Catalogs", "api": "beta", "uri": "identityGovernance/entitlementManagement/accessPackageCatalogs"},
    {"name": "EntMgmt_PoliciesV1", "api": "v1.0",
     "uri": "identityGovernance/entitlementManagement/assignmentPolicies?$expand=accessPackage($select=id,displayName)"},
    {"name": "EntMgmt_AssignmentPolicies", "api": "beta", "uri": "identityGovernance/entitlementManagement/accessPackageAssignmentPolicies"},
    {"name": "EntMgmt_CatalogResources", "api": "beta", "fan_out": "EntMgmt_Catalogs",
     "path": "identityGovernance/entitlementManagement/accessPackageCatalogs/{id}/accessPackageResources"},
    {"name": "EntMgmt_PackageRoleScopes", "api": "beta", "fan_out": "EntMgmt_AccessPackages",
     "path": "identityGovernance/entitlementManagement/accessPackages/{id}/accessPackageResourceRoleScopes?$expand=accessPackageResourceScope"},
    # Entra recommendations
    {"name": "Entra_Recommendations", "api": "beta", "uri": "directory/recommendations?$expand=impactedResources"},
    # Azure (only with --include-azure): where the Entra logs are sent
    {"name": "Azure_DiagCategories", "custom": "azure_diag", "kind": "categories", "azure": True,
     "uri": "providers/microsoft.aadiam/diagnosticSettingsCategories"},
    {"name": "Azure_DiagSettings", "custom": "azure_diag", "kind": "settings", "azure": True,
     "uri": "providers/microsoft.aadiam/diagnosticSettings"},
]


class GraphError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class ConfigError(Exception):
    pass


# ------------------------------------------------------------------------------ companies, apps and environment
def load_env_file(path: Path) -> int:
    """Reads KEY=VALUE lines into os.environ. Variables that are already set win. Returns how many were added."""
    added = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().removeprefix("export ").strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            added += 1
    return added


def app_env_names(app: str) -> tuple[str, str]:
    """'app-1' -> ('ENTRA_APP_1_CLIENT_ID', 'ENTRA_APP_1_CLIENT_SECRET')."""
    token = re.sub(r"[^A-Za-z0-9]+", "_", app.strip()).strip("_").upper()
    return f"ENTRA_{token}_CLIENT_ID", f"ENTRA_{token}_CLIENT_SECRET"


def app_credentials(app: str) -> tuple[str, str]:
    id_var, secret_var = app_env_names(app)
    client_id, secret = os.environ.get(id_var, "").strip(), os.environ.get(secret_var, "").strip()
    missing = [v for v, val in ((id_var, client_id), (secret_var, secret)) if not val]
    if missing:
        raise ConfigError(f"environment variable(s) not set for '{app}': {', '.join(missing)}")
    return client_id, secret


def load_companies(path: Path) -> list[dict]:
    if not path.exists():
        raise ConfigError(f"{path} not found (see the docstring of entra_collect.py for the format)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    items = data["companies"] if isinstance(data, dict) and "companies" in data else data
    if not isinstance(items, list) or not items:
        raise ConfigError(f'{path} must contain a non-empty "companies" list')
    companies, seen = [], set()
    for i, c in enumerate(items, 1):
        missing = [k for k in ("company_name", "company_id", "tenant_id", "app") if not str(c.get(k) or "").strip()]
        if missing:
            raise ConfigError(f"company #{i} in {path} is missing: {', '.join(missing)}")
        cid = str(c["company_id"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", cid):
            raise ConfigError(f"company_id '{cid}' may only contain letters, digits, '.', '_' and '-' (it names a folder)")
        if cid.lower() in seen:
            raise ConfigError(f"company_id '{cid}' is listed twice in {path}")
        seen.add(cid.lower())
        try:
            wl.validate_names(list(c.get("workloads") or []) + list(c.get("exclude_workloads") or []), f"company '{cid}' in {path}")
        except wl.WorkloadError as exc:
            raise ConfigError(str(exc)) from exc
        companies.append({"company_name": str(c["company_name"]).strip(), "company_id": cid,
                          "tenant_id": str(c["tenant_id"]).strip(), "app": str(c["app"]).strip(),
                          "enabled": c.get("enabled", True) is not False,
                          "workloads": [str(x).strip() for x in (c.get("workloads") or []) if str(x).strip()],
                          "exclude_workloads": [str(x).strip() for x in (c.get("exclude_workloads") or []) if str(x).strip()],
                          "domains": [str(x).strip().lower() for x in (c.get("domains") or []) if str(x).strip()],
                          "emergency_access_ids": [str(x).strip() for x in (c.get("emergency_access_ids") or []) if str(x).strip()]})
    return companies


def select_companies(companies: list[dict], wanted: str | None) -> list[dict]:
    if not wanted:
        return [c for c in companies if c["enabled"]]
    names = {w.strip().lower() for w in wanted.split(",") if w.strip()}
    chosen = [c for c in companies if c["company_id"].lower() in names or c["company_name"].lower() in names]
    unknown = names - {c["company_id"].lower() for c in chosen} - {c["company_name"].lower() for c in chosen}
    if unknown:
        raise ConfigError(f"not in the companies file: {', '.join(sorted(unknown))}")
    return chosen


# ------------------------------------------------------------------------------ authentication
def decode_jwt(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001
        return {}


class Auth:
    """Gets (and caches) client-credential tokens for Graph and Azure Resource Manager through msal."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        import msal  # imported here so the rest of the file can be tested without it

        self.app = msal.ConfidentialClientApplication(
            client_id, authority=f"https://login.microsoftonline.com/{tenant_id}", client_credential=client_secret)

    def token(self, resource: str = GRAPH) -> str:
        result = self.app.acquire_token_for_client(scopes=[f"{resource}/.default"])
        if "access_token" not in result:
            raise RuntimeError(f"Could not get a token for {resource}: {result.get('error')}: {result.get('error_description')}")
        return result["access_token"]


# ------------------------------------------------------------------------------ Graph client
class GraphClient:
    def __init__(self, token_provider: Callable[[str], str], session: requests.Session | None = None, verbose: bool = False):
        self.token_provider = token_provider
        self.http = session or requests.Session()
        self.verbose = verbose

    def request(self, method: str, url: str, *, resource: str = GRAPH, body: Any = None, retries: int = 5,
                extra_headers: dict | None = None) -> dict:
        refreshed = False
        for attempt in range(1, retries + 1):
            headers = {"Authorization": f"Bearer {self.token_provider(resource)}", "Accept": "application/json", **(extra_headers or {})}
            if body is not None:
                headers["Content-Type"] = "application/json"
            resp = self.http.request(method, url, headers=headers, data=json.dumps(body) if body is not None else None, timeout=120)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                if self.verbose:
                    print(f"  {resp.status_code} on {url[:90]}; retrying in {wait}s", file=sys.stderr)
                time.sleep(min(wait, 60))
                continue
            if resp.status_code == 401 and not refreshed:
                refreshed = True
                continue
            if resp.status_code >= 400:
                try:
                    err = resp.json().get("error", {})
                    message = err.get("message") or resp.text[:300]
                except ValueError:
                    message = resp.text[:300]
                if not message.isprintable() or not message.strip():   # some services answer with an empty or binary body
                    message = (resp.headers.get("x-ms-diagnostics") or resp.headers.get("WWW-Authenticate") or resp.reason or "no details")[:300]
                raise GraphError(resp.status_code, message)
            return resp.json() if resp.content else {}
        raise GraphError(0, "retries exhausted")

    def get_all(self, url: str, resource: str = GRAPH) -> list[dict]:
        """Follows @odata.nextLink. A single-object endpoint comes back as a one-item list."""
        items: list[dict] = []
        while url:
            page = self.request("GET", url, resource=resource)
            if isinstance(page.get("value"), list):
                items.extend(page["value"])
            else:
                items.append({k: v for k, v in page.items() if not k.startswith("@odata.context")})
            url = page.get("@odata.nextLink")
        return items

    def batch_for_each(self, api: str, parents: list[dict], path: str) -> list[tuple[dict, dict]]:
        """One GET per parent object, 20 at a time through $batch; retries throttled requests."""
        out: list[tuple[dict, dict]] = []
        pending = [p for p in parents if p.get("id")]
        errors = 0
        for attempt in range(1, 5):
            if not pending:
                break
            retry: list[dict] = []
            for i in range(0, len(pending), 20):
                chunk = pending[i:i + 20]
                requests_body = [{"id": str(j), "method": "GET", "url": "/" + path.replace("{id}", p["id"])}
                                 for j, p in enumerate(chunk)]
                resp = self.request("POST", f"{GRAPH}/{api}/$batch", body={"requests": requests_body})
                for r in resp.get("responses", []):
                    parent = chunk[int(r["id"])]
                    status = r.get("status")
                    if status == 200:
                        body = r.get("body", {})
                        if "value" in body:
                            for item in body["value"]:
                                out.append((parent, item))
                        else:  # a single object, not a collection
                            out.append((parent, {k: v for k, v in body.items() if not k.startswith("@odata.")}))
                        nxt = body.get("@odata.nextLink")
                        while nxt:  # more than one page for this parent
                            page = self.request("GET", nxt)
                            for item in page.get("value", []):
                                out.append((parent, item))
                            nxt = page.get("@odata.nextLink")
                    elif status in (429, 500, 502, 503, 504):
                        retry.append(parent)
                    else:
                        errors += 1
            pending = retry
            if pending:
                time.sleep(5 * attempt)
        if pending or errors:
            print(f"  warning: '{path}': {errors} request(s) returned an error and {len(pending)} stayed throttled; "
                  f"those objects are missing", file=sys.stderr)
        return out


# ------------------------------------------------------------------------------ custom data sets
def collect_azure_diag(client: GraphClient, kind: str) -> list[dict]:
    suffix = "diagnosticSettingsCategories" if kind == "categories" else "diagnosticSettings"
    url = f"{ARM}/providers/microsoft.aadiam/{suffix}?api-version=2017-04-01-preview"
    page = client.request("GET", url, resource=ARM)
    return page.get("value", [])


# ------------------------------------------------------------------------------ one company
def collect(client: GraphClient, tenant_id: str, run_dir: Path, *, skip_large: bool, include_azure: bool,
            only: set[str] | None = None, extra: list[dict] | None = None, domains: list[str] | None = None,
            dns_dataset: bool = False) -> list[dict]:
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    existing = {d["name"] for d in DATASETS}
    pool = DATASETS + [d for d in (extra or []) if d["name"] not in existing]
    if dns_dataset:
        pool.append({"name": "DNS_MailAuth", "custom": "dns", "uri": "DNS TXT/CNAME/MX lookups of the verified domains"})
    datasets = [d for d in pool
                if not (skip_large and d.get("large")) and not (d.get("azure") and not include_azure)
                and (not only or d["name"] in only)]
    collected: dict[str, list[dict]] = {}
    log: list[dict] = []
    for d in datasets:
        started = time.time()
        entry = {"dataset": d["name"], "workload": d.get("workload", "entra"), "endpoint": d.get("uri") or d.get("path"), "status": "OK", "rows": 0, "error": ""}
        print(f"  {d['name']:<28}", end="", flush=True)
        if wl.unlicensed(d.get("workload", "entra"), wl.active_plans(collected.get("SubscribedSkus"))):
            entry.update(status="SKIPPED", error=f"{d['workload']} is not licensed in this tenant (no matching service plan in the subscribed SKUs)")
            print("SKIPPED - not licensed")
            entry["duration_seconds"] = 0
            log.append(entry)
            continue
        try:
            if d.get("custom") == "azure_diag":
                rows = collect_azure_diag(client, d["kind"])
            elif d.get("custom") == "exo":
                rows = wl.collect_exo(client, tenant_id, d)
            elif d.get("custom") == "teams":
                rows = wl.collect_teams(client, d)
            elif d.get("custom") == "arm":
                rows = wl.collect_arm(client, d)
            elif d.get("custom") == "dns":
                rows = wl.collect_dns(collected.get("Domains"), domains)
            elif d.get("fan_out"):
                if d["fan_out"] not in collected:
                    raise RuntimeError(f"needs the '{d['fan_out']}' data set, which was not collected")
                rows = []
                parents = [x for x in collected[d["fan_out"]] if d.get("fan_filter", lambda _: True)(x)]
                for parent, item in client.batch_for_each(d["api"], parents, d["path"]):
                    row = {"parentId": parent.get("id"), "parentName": parent.get("displayName")}
                    if d["fan_out"] == "ServicePrincipals":
                        row.update(servicePrincipalId=parent.get("id"), servicePrincipalName=parent.get("displayName"),
                                   servicePrincipalAppId=parent.get("appId"))
                    row.update(item)
                    rows.append(row)
            else:
                url = f"{GRAPH}/{d['api']}/{d['uri']}".replace("{tenantId}", tenant_id)
                rows = client.get_all(url)
                if d.get("unwrap"):
                    rows = [x for r in rows for x in (r.get(d["unwrap"]) or [])]
            collected[d["name"]] = rows
            (raw_dir / f"{d['name']}.json").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
            entry["rows"] = len(rows)
            print(f"OK ({len(rows)})")
        except Exception as exc:  # noqa: BLE001 - one failed data set must not stop the run
            entry.update(status="FAILED", error=str(exc).splitlines()[0][:400])
            print(f"SKIPPED - {entry['error']}")
        entry["duration_seconds"] = round(time.time() - started, 2)
        log.append(entry)
    return log


def write_manifest(run_dir: Path, run_id: str, batch_id: str, company: dict, tenant_id: str, client_id: str,
                   started: dt.datetime, log: list[dict], missing_roles: list[str], enabled: list[str] | None = None) -> Path:
    finished = dt.datetime.now(dt.timezone.utc)
    org = None
    org_file = run_dir / "raw" / "Organization.json"
    if org_file.exists():
        data = json.loads(org_file.read_text(encoding="utf-8"))
        org = data[0].get("displayName") if data else None
    manifest = {
        "run_id": run_id, "batch_id": batch_id, "tool_version": TOOL_VERSION,
        "company_id": company["company_id"], "company_name": company["company_name"], "app": company["app"],
        "emergency_access_ids": company.get("emergency_access_ids", []),
        "tenant_id": tenant_id, "tenant_name": org, "client_id": client_id,
        "collection_started_at": started.isoformat(), "collected_at": finished.isoformat(),
        "workloads": enabled or ["entra"], "domains_in_scope": company.get("domains", []),
        "missing_app_roles": missing_roles, "datasets": log,
    }
    path = run_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def run_company(company: dict, args: argparse.Namespace, batch_id: str, *, auth_factory=Auth, session=None) -> dict:
    client_id, secret = app_credentials(company["app"])
    auth = auth_factory(company["tenant_id"], client_id, secret)
    started = dt.datetime.now(dt.timezone.utc)
    run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    run_dir = Path(args.output_dir) / company["company_id"] / run_id

    token = auth.token(GRAPH)  # fails here if the tenant, client id or secret is wrong
    claims = decode_jwt(token)
    tenant_id = claims.get("tid") or company["tenant_id"]
    configured = company["tenant_id"].lower()
    if re.fullmatch(r"[0-9a-f-]{36}", configured) and claims.get("tid") and claims["tid"].lower() != configured:
        raise ConfigError(f"the token is for tenant {claims['tid']}, but {company['company_id']} is configured with {company['tenant_id']}")
    have = set(claims.get("roles", []))
    enabled = wl.company_workloads(company, args.include_azure)
    specs = wl.load_specs()
    graph_needed = set(REQUIRED_APP_ROLES)
    for info in wl.required_permissions(specs, enabled).values():
        graph_needed |= set(info["graph"])
    missing = sorted(r for r in graph_needed if r not in have)
    print(f"  workloads: {', '.join(enabled)}")
    print(f"  signed in as app {claims.get('appid') or client_id} to tenant {tenant_id}")
    if missing:
        print("  warning: the token does not contain these application permissions (add them and grant admin consent): "
              + ", ".join(missing) + ". Data sets that need them will be skipped.", file=sys.stderr)
    client = GraphClient(auth.token, session=session, verbose=args.verbose)
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    log = collect(client, tenant_id, run_dir, skip_large=args.skip_large, include_azure="azure" in enabled, only=only,
                  extra=wl.spec_datasets(specs, enabled), domains=company.get("domains") or None, dns_dataset=True)
    write_manifest(run_dir, run_id, batch_id, company, tenant_id, client_id, started, log, missing, enabled)
    ok = sum(1 for e in log if e["status"] == "OK")
    return {"company_id": company["company_id"], "run_dir": str(run_dir), "status": "ok", "datasets_ok": ok,
            "datasets_failed": len(log) - ok, "missing_app_roles": missing}


# ------------------------------------------------------------------------------ command line
def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--companies", default=None, help="companies file (default: config/companies.json, or SECUREIT_COMPANIES)")
    p.add_argument("--company", help="only these companies: comma-separated company_id or company_name (default: all enabled)")
    p.add_argument("--env-file", help="file with the ENTRA_APP_n_CLIENT_ID / _CLIENT_SECRET variables (default: .env in the project root, or SECUREIT_ENV_FILE)")
    p.add_argument("--output-dir", default=None, help="parent folder for the run folders (default: runs in the project root, or SECUREIT_OUTPUT_DIR)")
    p.add_argument("--list", action="store_true", help="show the companies and whether their app credentials are set, then stop")
    p.add_argument("--skip-large", action="store_true", help="skip users, groups, apps, service principals, devices, MFA registration")
    p.add_argument("--include-azure", action="store_true", help="also read Entra diagnostic settings from Azure (needs Reader on /providers/microsoft.aadiam)")
    p.add_argument("--only", help="comma-separated data set names (for testing)")
    p.add_argument("--permissions", action="store_true", help="print the permissions each workload needs, then stop")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(list(argv) if argv is not None else None)
    args.output_dir = args.output_dir or str(paths.output_dir())
    return args


def print_permissions() -> int:
    """What to add to the app registration, per workload (Graph application permissions come from the specs)."""
    specs = wl.load_specs()
    req = wl.required_permissions(specs, wl.WORKLOADS)
    print("Microsoft Graph application permissions (admin consent in each client tenant)")
    print()
    print("  entra (always): " + ", ".join(REQUIRED_APP_ROLES))
    for w in wl.WORKLOADS:
        extra = [p for p in req[w]["graph"] if p not in REQUIRED_APP_ROLES]
        if extra:
            print(f"  {w}: " + ", ".join(extra))
    print()
    print("Other access (not Graph permissions)")
    print()
    for w in wl.WORKLOADS:
        for line in req[w]["other"]:
            print(f"  {w}: {line}")
    print()
    print('Choose per company in companies.json: "workloads": [...] or "exclude_workloads": [...]; workloads: ' + ", ".join(wl.WORKLOADS))
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.permissions:
        return print_permissions()
    try:
        env_file = Path(args.env_file) if args.env_file else paths.env_file()
        if args.env_file and not env_file.exists():
            raise ConfigError(f"env file {env_file} not found")
        if env_file.exists():
            load_env_file(env_file)
        companies = load_companies(Path(args.companies) if args.companies else paths.companies_file())
        selected = select_companies(companies, args.company)
    except ConfigError as exc:
        sys.exit(f"error: {exc}")

    if args.list:
        print(f"{'company_id':<20}{'company_name':<28}{'app':<10}{'enabled':<9}credentials")
        for c in companies:
            try:
                app_credentials(c["app"])
                cred = "set"
            except ConfigError as exc:
                cred = f"MISSING ({exc})"
            print(f"{c['company_id']:<20}{c['company_name']:<28}{c['app']:<10}{str(c['enabled']):<9}{cred}")
        return 0
    if not selected:
        sys.exit("error: no enabled companies to run")

    started = dt.datetime.now(dt.timezone.utc)
    batch_id = f"batch-{started.strftime('%Y%m%dT%H%M%SZ')}"
    runs: list[dict] = []
    for c in selected:
        print(f"\n== {c['company_name']} ({c['company_id']}) via {c['app']} ==")
        try:
            runs.append(run_company(c, args, batch_id))
        except Exception as exc:  # noqa: BLE001 - one company must not stop the others
            message = str(exc).splitlines()[0][:400] if str(exc) else type(exc).__name__
            print(f"  FAILED: {message}", file=sys.stderr)
            runs.append({"company_id": c["company_id"], "run_dir": None, "status": "failed", "error": message})
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "last_run.json").write_text(json.dumps({"batch_id": batch_id, "started_at": started.isoformat(), "runs": runs}, indent=2), encoding="utf-8")

    try:  # refresh the summary file for the newest collection
        import dashboard_data
        try:
            from entra_checks import CONTROL_PLANE_ROLES as control_plane
        except Exception:  # noqa: BLE001
            control_plane = set()
        print(f"\nSummary file updated: {dashboard_data.build(out, control_plane=set(control_plane))}")
    except Exception as exc:  # noqa: BLE001 - a convenience, never fail the collection over it
        print(f"\nSummary file not updated: {exc}", file=sys.stderr)

    print("\nSummary")
    for r in runs:
        if r["status"] == "ok":
            print(f"  {r['company_id']:<20}ok      {r['datasets_ok']} data sets, {r['datasets_failed']} skipped   {r['run_dir']}")
        else:
            print(f"  {r['company_id']:<20}FAILED  {r['error']}")
    failed = sum(1 for r in runs if r["status"] != "ok")
    print(f"\n{len(runs) - failed} of {len(runs)} companies collected. Run folders are listed in {out / 'last_run.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
