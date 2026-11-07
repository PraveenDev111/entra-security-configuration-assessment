"""Microsoft Zero Trust Assessment (Entra identity) checks that are not already covered by entra_checks.py.

Each check follows the criteria of the matching test in the open-source Zero Trust Assessment
(github.com/microsoft/zerotrustassessment), read from that project's test definitions. Checks whose logic lives in a
helper that is not public are marked "approximation" in their expected-value text.
`zta_coverage.json` lists all Zero Trust Assessment identity tests and how each one is handled here.

Called by entra_checks.py:  run_zta(engine, lib)  where lib is the entra_checks module (helpers and constants).
"""
from __future__ import annotations

import re
from typing import Any, Callable

FW_ZTA = "Zero Trust Assessment (Entra)"

PHISH_RESISTANT = {"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor", "certificateBasedAuthenticationPki"}
PHISH_RESISTANT_METHODS_USER = ("passKeyDeviceBound", "passKeyDeviceBoundAuthenticator", "windowsHelloForBusiness")
EXO, SPO = "00000002-0000-0ff1-ce00-000000000000", "00000003-0000-0ff1-ce00-000000000000"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
DIRSYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32"
AAD_JOIN_LOCAL_ADMIN_ROLE = "9f06204d-73c1-4d4c-880a-6edb90606fd8"
AZURE_AD_POWERSHELL_APP = "1b730954-1685-4b74-9bfd-dac224a7b894"
BANNED_PASSWORD_TEMPLATE = "5cf42378-d67d-4f36-ba46-e8b86229381d"
MICROSOFT_OWNER_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
URL_SHORTENERS = ("bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly")

# id, title, Microsoft risk level, data sets needed, minimum licence
REGISTRY: list[dict[str, Any]] = []


def zt(test_id: str, title: str, risk: str, needs: tuple = (), plan: str = "Any", expected: str = ""):
    def deco(fn):
        REGISTRY.append({"id": test_id, "title": title, "risk": risk, "needs": needs, "plan": plan, "expected": expected, "fn": fn})
        return fn
    return deco


def run_zta(e, lib) -> None:
    _CONTROL_PLANE.update(lib.CONTROL_PLANE_ROLES)
    for item in REGISTRY:
        rid = f"ZTA.{item['id']}"
        lib.SEVERITY[rid] = item["risk"]
        e.run(rid, f"ZTA {item['id']}", FW_ZTA, item["title"], item["expected"] or "As defined by the Zero Trust Assessment test",
              (lambda f=item["fn"]: f(e, lib)), needs=item["needs"], min_plan=item["plan"])


# ------------------------------------------------------------------------------ shared helpers
def _creds(app: dict, kind: str) -> list:
    return [c for c in (app.get(kind) or []) if isinstance(c, dict)]


def _name(o: dict) -> str:
    return str(o.get("displayName") or o.get("appId") or o.get("id"))


def _s(lib, v) -> str:
    return "not set" if v is None else lib.to_str(v)


def _dt(lib, value):
    return lib.parse_dt(value)


def _result(passed: bool, lib, found: list[str], ok_text: str, bad_text: str) -> dict:
    if passed:
        return {"pass": True, "actual": ok_text}
    return {"pass": False, "affected": found, "actual": f"{bad_text}: {lib.join_findings(found)}" if found else bad_text}


def _enabled_ca(e) -> list[dict]:
    return [p for p in (e.ds("CA_Policies") or []) if p.get("state") == "enabled"]


_CONTROL_PLANE: set[str] = set()


def _privileged_roles(e, built_in_only: bool = False) -> dict[str, str]:
    out = {}
    for r in e.ds("RoleDefinitions") or []:
        if (r.get("isPrivileged") is True or r.get("id") in _CONTROL_PLANE) and (not built_in_only or r.get("isBuiltIn") is True):
            out[r["id"]] = r.get("displayName") or r["id"]
    return out


def _assignments(e, role_ids=None, principal_types=None, include_eligible: bool = True) -> list[dict]:
    rows = list(e.ds("RoleAssignments") or []) + (list(e.ds("RoleEligibility") or []) if include_eligible else [])
    out = []
    for a in rows:
        if role_ids is not None and a.get("roleDefinitionId") not in role_ids:
            continue
        ptype = (a.get("principal") or {}).get("@odata.type")
        if principal_types is not None and ptype not in principal_types:
            continue
        out.append(a)
    return out


def _who(a: dict, roles: dict[str, str]) -> str:
    p = a.get("principal") or {}
    return f"{p.get('displayName') or a.get('principalId')} ({roles.get(a.get('roleDefinitionId'), a.get('roleDefinitionId'))})"


def _phish_strength_ids(e, strict: bool) -> set[str]:
    """Authentication strengths whose every allowed combination is phishing-resistant."""
    allowed = PHISH_RESISTANT if not strict else {"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"}
    ids = set()
    for s in e.ds("CA_AuthStrengths") or []:
        combos = [c for c in (s.get("allowedCombinations") or [])]
        if combos and all(all(part.strip() in allowed for part in str(c).split(",")) for c in combos):
            ids.add(s.get("id"))
    return ids


# ------------------------------------------------------------------------------ applications and secrets
@zt("21772", "Applications don't have client secrets configured", "High", ("Applications", "ServicePrincipals"),
    expected="No application registration or service principal has a client secret")
def _(e, lib):
    found = [f"App registration: {_name(a)}" for a in e.ds("Applications") if _creds(a, "passwordCredentials")]
    found += [f"Service principal: {_name(s)}" for s in e.ds("ServicePrincipals") if _creds(s, "passwordCredentials")]
    return _result(not found, lib, found, "No client secrets are configured", f"{len(found)} object(s) have client secrets")


@zt("21773", "Applications don't have certificates with expiration longer than 180 days", "Medium", ("Applications", "ServicePrincipals"),
    expected="No certificate expires more than 180 days from now")
def _(e, lib):
    limit = e.now + __import__("datetime").timedelta(days=180)
    found = []
    for label, rows in (("App registration", e.ds("Applications")), ("Service principal", e.ds("ServicePrincipals"))):
        for o in rows:
            if any((_dt(lib, c.get("endDateTime")) or e.now) > limit for c in _creds(o, "keyCredentials")):
                found.append(f"{label}: {_name(o)}")
    return _result(not found, lib, found, "No long-lived certificates", f"{len(found)} object(s) have certificates valid beyond 180 days")


@zt("21992", "Application certificates must be rotated on a regular basis", "Medium", ("Applications", "ServicePrincipals"),
    expected="No certificate was issued more than 180 days ago")
def _(e, lib):
    limit = e.now - __import__("datetime").timedelta(days=180)
    found = []
    for label, rows in (("App registration", e.ds("Applications")), ("Service principal", e.ds("ServicePrincipals"))):
        for o in rows:
            if any((_dt(lib, c.get("startDateTime")) or e.now) < limit for c in _creds(o, "keyCredentials")):
                found.append(f"{label}: {_name(o)}")
    return _result(not found, lib, found, "All certificates were issued within 180 days", f"{len(found)} object(s) have certificates older than 180 days")


@zt("21774", "Microsoft services applications don't have credentials configured", "High", ("ServicePrincipals",),
    expected="No Microsoft-owned service principal has a secret or certificate")
def _(e, lib):
    found = [_name(s) for s in e.ds("ServicePrincipals") if s.get("appOwnerOrganizationId") == MICROSOFT_OWNER_TENANT
             and (_creds(s, "passwordCredentials") or _creds(s, "keyCredentials"))]
    return _result(not found, lib, found, "No Microsoft service principal has credentials", f"{len(found)} Microsoft service principal(s) have credentials")


@zt("21896", "Service principals don't have certificates or credentials associated with them", "Medium", ("ServicePrincipals",),
    expected="No non-Microsoft service principal has a secret or certificate of its own")
def _(e, lib):
    found = [_name(s) for s in e.ds("ServicePrincipals") if s.get("appOwnerOrganizationId") != MICROSOFT_OWNER_TENANT
             and (_creds(s, "passwordCredentials") or _creds(s, "keyCredentials"))]
    return _result(not found, lib, found, "No service principal has its own credentials", f"{len(found)} service principal(s) have credentials")


@zt("21775", "Enforce standards for app secrets and certificates", "High", ("DefaultAppMgmtPolicy",),
    expected="The default app management policy is enabled and has at least one enabled credential restriction")
def _(e, lib):
    p = e.first("DefaultAppMgmtPolicy")
    if not p or p.get("isEnabled") is not True:
        return {"pass": False, "actual": "The default app management policy is missing or disabled"}
    active = [f"{scope}.{kind}: {r.get('restrictionType')}" for scope in ("applicationRestrictions", "servicePrincipalRestrictions")
              for kind in ("passwordCredentials", "keyCredentials") for r in ((p.get(scope) or {}).get(kind) or []) if r.get("state") == "enabled"]
    return {"pass": bool(active), "actual": ("Enabled restrictions: " + "; ".join(active)) if active else "The policy has no enabled restriction"}


@zt("21777", "App instance property lock is configured for all multitenant applications", "Medium", ("Applications",),
    expected="Every multitenant application has the service principal lock enabled")
def _(e, lib):
    multi = ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount")
    found = [_name(a) for a in e.ds("Applications") if a.get("signInAudience") in multi
             and (a.get("servicePrincipalLockConfiguration") is None or lib.g(a, "servicePrincipalLockConfiguration", "isEnabled") is False)]
    return _result(not found, lib, found, "All multitenant applications are locked", f"{len(found)} multitenant application(s) without the property lock")


@zt("21844", "Block legacy Azure AD PowerShell module", "Medium", ("ServicePrincipals",),
    expected="The Azure AD PowerShell service principal exists and is disabled")
def _(e, lib):
    sp = next((s for s in e.ds("ServicePrincipals") if lib.lc(s.get("appId")) == AZURE_AD_POWERSHELL_APP), None)
    if sp is None:
        return {"pass": False, "actual": "The service principal is not present in the tenant, so it cannot be blocked"}
    return {"pass": sp.get("accountEnabled") is False, "actual": f"accountEnabled = {_s(lib, sp.get('accountEnabled'))}; appRoleAssignmentRequired = {_s(lib, sp.get('appRoleAssignmentRequired'))}"}


def _unsafe_uri(uri: str, allow_localhost: bool) -> bool:
    u = uri.lower()
    return "*" in u or "azurewebsites.net" in u or any(s in u for s in URL_SHORTENERS) or (not allow_localhost and "localhost" in u)


@zt("21885", "App registrations use safe redirect URIs", "High", ("Applications",), plan="P1",
    expected="No redirect URI uses a wildcard, a URL shortener or *.azurewebsites.net (approximation of the assessment helper)")
def _(e, lib):
    found = []
    for a in e.ds("Applications"):
        uris = [u for key in ("web", "spa", "publicClient") for u in lib.as_list(lib.g(a, key, "redirectUris"))]
        bad = [u for u in uris if _unsafe_uri(str(u), allow_localhost=True)]
        if bad:
            found.append(f"{_name(a)}: {', '.join(map(str, bad[:3]))}")
    return _result(not found, lib, found, "All redirect URIs are safe", f"{len(found)} app registration(s) with unsafe redirect URIs")


@zt("23183", "Service principals use safe redirect URIs", "High", ("ServicePrincipals",), plan="P1",
    expected="No non-Microsoft service principal reply URL uses a wildcard, localhost, a URL shortener or *.azurewebsites.net (approximation)")
def _(e, lib):
    found = []
    for s in e.ds("ServicePrincipals"):
        if s.get("appOwnerOrganizationId") in lib.MICROSOFT_TENANTS:
            continue
        bad = [u for u in lib.as_list(s.get("replyUrls")) if _unsafe_uri(str(u), allow_localhost=False)]
        if bad:
            found.append(f"{_name(s)}: {', '.join(map(str, bad[:3]))}")
    return _result(not found, lib, found, "All reply URLs are safe", f"{len(found)} service principal(s) with unsafe reply URLs")


@zt("21867", "Enterprise applications with high privilege Microsoft Graph API permissions have owners", "High", ("ServicePrincipals", "SP_AppRoleAssignments"), plan="P1",
    expected="Every service principal holding a high-risk Graph permission has an owner (approximation: uses this tool's high-risk permission list)")
def _(e, lib):
    risky_ids = {lib.lc(p[0]) for p in lib.RISK_PERMISSIONS if p[2] == "Application"}
    holders = {g.get("servicePrincipalId") for g in e.ds("SP_AppRoleAssignments") if lib.lc(g.get("appRoleId")) in risky_ids}
    found = [_name(s) for s in e.ds("ServicePrincipals") if s.get("id") in holders and not lib.as_list(s.get("owners"))]
    return _result(not found, lib, found, "All high-privilege applications have owners", f"{len(found)} high-privilege application(s) without an owner")


@zt("24518", "Enterprise applications have owners", "Medium", ("ServicePrincipals",),
    expected="Every non-Microsoft enterprise application has at least two owners (approximation of the assessment helper)")
def _(e, lib):
    found = [_name(s) for s in e.ds("ServicePrincipals") if s.get("servicePrincipalType") == "Application"
             and s.get("appOwnerOrganizationId") not in lib.MICROSOFT_TENANTS and len(lib.as_list(s.get("owners"))) < 2]
    return _result(not found, lib, found, "All enterprise applications have two or more owners", f"{len(found)} enterprise application(s) with fewer than two owners")


@zt("21868", "Guests don't own apps in the tenant", "High", ("Applications", "ServicePrincipals", "Users"),
    expected="No guest user owns an application registration or service principal")
def _(e, lib):
    guests = {u.get("id") for u in (e.ds("Users") or []) if u.get("userType") == "Guest"}
    found = []
    for label, rows in (("App registration", e.ds("Applications")), ("Service principal", e.ds("ServicePrincipals"))):
        for o in rows:
            for owner in lib.as_list(o.get("owners")):
                if owner.get("id") in guests:
                    found.append(f"{label} {_name(o)}: {owner.get('userPrincipalName') or owner.get('displayName')}")
    return _result(not found, lib, found, "No guest owns an application", f"{len(found)} guest ownership(s)")


@zt("25401", "Application Proxy applications require preauthentication to block anonymous access", "High", ("AppProxy_Apps",), plan="P1",
    expected="Every Application Proxy application uses Microsoft Entra preauthentication")
def _(e, lib):
    apps = [a for a in e.ds("AppProxy_Apps") if a.get("onPremisesPublishing")]
    if not apps:
        return {"skip": "No Application Proxy applications in this tenant"}
    found = [_name(a) for a in apps if lib.g(a, "onPremisesPublishing", "externalAuthenticationType") != "aadPreAuthentication"]
    return _result(not found, lib, found, "All Application Proxy apps require preauthentication", f"{len(found)} application(s) allow passthrough authentication")


@zt("21884", "Conditional Access policies for workload identities based on known networks are configured", "Medium", ("ServicePrincipals", "CA_Policies", "Organization"), plan="P1",
    expected="Every tenant-owned service principal with credentials is covered by an enabled workload-identity policy with a location condition")
def _(e, lib):
    tenant = (e.first("Organization") or {}).get("id")
    sps = [s for s in e.ds("ServicePrincipals") if s.get("servicePrincipalType") == "Application" and s.get("appOwnerOrganizationId") == tenant
           and (_creds(s, "passwordCredentials") or _creds(s, "keyCredentials"))]
    if not sps:
        return {"pass": True, "actual": "No tenant-owned service principals with credentials"}
    pols = [p for p in _enabled_ca(e) if lib.g(p, "conditions", "clientApplications") and (lib.g(p, "conditions", "locations", "includeLocations") or lib.g(p, "conditions", "locations", "excludeLocations"))]
    global_ok = any(lib.has(lib.g(p, "conditions", "clientApplications", "includeServicePrincipals"), "ServicePrincipalsInMyTenant")
                    and not lib.g(p, "conditions", "clientApplications", "excludeServicePrincipals") for p in pols)
    if global_ok:
        return {"pass": True, "actual": "A tenant-wide workload-identity policy with a location condition exists"}
    named = {sid for p in pols for sid in lib.as_list(lib.g(p, "conditions", "clientApplications", "includeServicePrincipals"))}
    found = [_name(s) for s in sps if s.get("id") not in named]
    return _result(not found, lib, found, "All service principals are covered", f"{len(found)} service principal(s) without a network-based policy")


# ------------------------------------------------------------------------------ authentication methods and passwords
@zt("21889", "Reduce the user-visible password surface area", "Medium", ("AuthMethodConfigs",), plan="P1",
    expected="FIDO2 and Microsoft Authenticator are enabled with targets, and Authenticator allows passwordless (any or deviceBasedPush)")
def _(e, lib):
    cfg = {x.get("id"): x for x in e.ds("AuthMethodConfigs")}
    fido, auth = cfg.get("Fido2") or {}, cfg.get("MicrosoftAuthenticator") or {}
    fido_ok = fido.get("state") == "enabled" and bool(lib.as_list(fido.get("includeTargets")))
    modes = {t.get("authenticationMode") for t in lib.as_list(auth.get("includeTargets"))}
    auth_ok = auth.get("state") == "enabled" and bool(lib.as_list(auth.get("includeTargets"))) and bool(modes & {"any", "deviceBasedPush"})
    return {"pass": fido_ok and auth_ok, "actual": f"FIDO2 ok = {fido_ok}; Authenticator ok = {auth_ok} (modes: {', '.join(sorted(str(m) for m in modes if m)) or 'none'})"}


@zt("21845", "Temporary access pass is enabled", "Medium", ("AuthMethodConfigs", "CA_Policies", "CA_AuthStrengths"), plan="P1",
    expected="TAP is enabled for all users and an enabled policy secures security-info registration with an authentication strength that includes TAP")
def _(e, lib):
    tap = next((x for x in e.ds("AuthMethodConfigs") if x.get("id") == "TemporaryAccessPass"), None) or {}
    if tap.get("state") != "enabled":
        return {"pass": False, "actual": "Temporary Access Pass is not enabled"}
    if not any(t.get("id") == "all_users" for t in lib.as_list(tap.get("includeTargets"))):
        return {"pass": False, "actual": "TAP is not targeted at all users"}
    strengths = {s.get("id"): s for s in e.ds("CA_AuthStrengths")}
    for p in _enabled_ca(e):
        sid = lib.g(p, "grantControls", "authenticationStrength", "id")
        if lib.has(lib.g(p, "conditions", "applications", "includeUserActions"), "urn:user:registersecurityinfo") and sid in strengths:
            if any("temporaryaccesspass" in str(c).lower() for c in lib.as_list(strengths[sid].get("allowedCombinations"))):
                return {"pass": True, "actual": f"Policy '{p.get('displayName')}' requires a strength that includes TAP"}
    return {"pass": False, "actual": "No enabled policy secures security-info registration with a TAP-capable authentication strength"}


@zt("21829", "Use cloud authentication", "Medium", ("Domains",), plan="P1", expected="No federated domains")
def _(e, lib):
    found = [d["id"] for d in e.ds("Domains") if d.get("authenticationType") == "Federated"]
    return _result(not found, lib, found, "No federated domains", f"{len(found)} federated domain(s)")


# ------------------------------------------------------------------------------ Conditional Access
def _ca_pass(policies: list[dict], lib, ok_text: str, bad_text: str) -> dict:
    if policies:
        return {"pass": True, "actual": "Matching policies: " + lib.join_findings(lib.names(policies))}
    return {"pass": False, "actual": bad_text}


@zt("21783", "Privileged Microsoft Entra built-in roles are targeted with Conditional Access policies to enforce phishing-resistant methods", "High",
    ("CA_Policies", "CA_AuthStrengths", "RoleDefinitions"), plan="P1", expected="Every privileged built-in role is covered by a policy requiring a phishing-resistant authentication strength")
def _(e, lib):
    strong = _phish_strength_ids(e, strict=True)
    covered = {r for p in (e.ds("CA_Policies") or []) if lib.g(p, "grantControls", "authenticationStrength", "id") in strong
               for r in lib.as_list(lib.g(p, "conditions", "users", "includeRoles"))}
    missing = [n for rid, n in _privileged_roles(e, built_in_only=True).items() if rid not in covered]
    return _result(not missing, lib, missing, "All privileged roles are covered", f"{len(missing)} privileged role(s) not covered")


@zt("21784", "All user sign in activity uses phishing-resistant authentication methods", "High", ("CA_Policies", "CA_AuthStrengths"), plan="P1",
    expected="An enabled all-users policy requires a phishing-resistant authentication strength and has no excluded users")
def _(e, lib):
    strong = _phish_strength_ids(e, strict=False)
    rel = [p for p in _enabled_ca(e) if lib.has(lib.g(p, "conditions", "users", "includeUsers"), "All") and lib.g(p, "grantControls", "authenticationStrength", "id") in strong]
    clean = [p for p in rel if not lib.as_list(lib.g(p, "conditions", "users", "excludeUsers"))]
    if rel and len(clean) == len(rel):
        return {"pass": True, "actual": "Policies: " + lib.join_findings(lib.names(rel))}
    return {"pass": False, "affected": lib.names([p for p in rel if p not in clean]),
            "actual": "No all-users phishing-resistant policy" if not rel else "Policies with excluded users: " + lib.join_findings(lib.names([p for p in rel if p not in clean]))}


@zt("21790", "Outbound cross-tenant access settings are configured", "Medium", ("CrossTenantDefault",),
    expected="Default outbound B2B collaboration and direct connect block all users and all applications")
def _(e, lib):
    p = e.first("CrossTenantDefault") or {}
    bad = []
    for section in ("b2bCollaborationOutbound", "b2bDirectConnectOutbound"):
        s = p.get(section) or {}
        for part, target in (("usersAndGroups", "AllUsers"), ("applications", "AllApplications")):
            node = s.get(part) or {}
            tgts = [t.get("target") for t in lib.as_list(node.get("targets"))]
            if not (node.get("accessType") == "blocked" and target in tgts):
                bad.append(f"{section}.{part}")
    return {"pass": not bad, "affected": bad, "actual": ("Not blocked: " + ", ".join(bad)) if bad else "All outbound access is blocked by default"}


@zt("21793", "Tenant restrictions v2 policy is configured", "High", ("CrossTenantDefault",), plan="P1",
    expected="The default tenant restrictions block all users and all applications")
def _(e, lib):
    t = (e.first("CrossTenantDefault") or {}).get("tenantRestrictions") or {}
    ok = (lib.g(t, "usersAndGroups", "accessType") == "blocked" and "AllUsers" in [x.get("target") for x in lib.as_list(lib.g(t, "usersAndGroups", "targets"))]
          and lib.g(t, "applications", "accessType") == "blocked" and "AllApplications" in [x.get("target") for x in lib.as_list(lib.g(t, "applications", "targets"))])
    return {"pass": ok, "actual": "Tenant restrictions v2 block all users and applications" if ok else "Tenant restrictions v2 are not configured to block all users and applications"}


@zt("21806", "Secure the MFA registration (My Security Info) page", "High", ("CA_Policies",), plan="P1",
    expected="An enabled all-users policy targets the register-security-information user action")
def _(e, lib):
    hits = [p for p in _enabled_ca(e) if lib.has(lib.g(p, "conditions", "applications", "includeUserActions"), "urn:user:registersecurityinfo") and lib.has(lib.g(p, "conditions", "users", "includeUsers"), "All")]
    return _ca_pass(hits, lib, "", "No enabled all-users policy protects security-info registration")


@zt("21828", "Authentication transfer is blocked", "High", ("CA_Policies",), plan="P1",
    expected="An enabled all-users, all-apps policy blocks authentication transfer")
def _(e, lib):
    hits = [p for p in _enabled_ca(e) if "authenticationtransfer" in _s(lib, lib.g(p, "conditions", "authenticationFlows", "transferMethods")).lower()
            and lib.has(lib.g(p, "grantControls", "builtInControls"), "block") and lib.has(lib.g(p, "conditions", "users", "includeUsers"), "All")
            and lib.has(lib.g(p, "conditions", "applications", "includeApplications"), "All")]
    return _ca_pass(hits, lib, "", "No enabled policy blocks authentication transfer")


@zt("21824", "Guests don't have long lived sign-in sessions", "Medium", ("CA_Policies",), plan="P1",
    expected="Every guest policy sets sign-in frequency to 24 hours or less (or every time)")
def _(e, lib):
    pols = [p for p in (e.ds("CA_Policies") or []) if lib.g(p, "conditions", "users", "includeGuestsOrExternalUsers")
            and p.get("state") in ("enabled", "enabledForReportingButNotEnforced") and not lib.as_list(lib.g(p, "grantControls", "termsOfUse"))]

    def short(p):
        f = lib.g(p, "sessionControls", "signInFrequency") or {}
        if f.get("isEnabled") is not True:
            return False
        t, v = f.get("type"), f.get("value")
        return (t == "hours" and v is not None and v <= 24) or (t == "days" and v == 1) or (t is None and f.get("frequencyInterval") == "everyTime")
    bad = [p for p in pols if not short(p)]
    if pols and not bad:
        return {"pass": True, "actual": "Guest policies: " + lib.join_findings(lib.names(pols))}
    return {"pass": False, "affected": lib.names(bad), "actual": "No guest sign-in frequency policy" if not pols else "Policies with long sessions: " + lib.join_findings(lib.names(bad))}


@zt("21825", "Privileged users have short-lived sign-in sessions", "Medium", ("CA_Policies", "RoleDefinitions"), plan="P1",
    expected="Every privileged role is covered by an enabled policy with sign-in frequency of 4 hours (P2) or 24 hours (P1) or less")
def _(e, lib):
    roles = _privileged_roles(e)
    if not roles:
        return {"pass": False, "actual": "No privileged roles found"}
    limit = 4 if e.plan == "P2" else 24
    covered = set()
    for p in _enabled_ca(e):
        f = lib.g(p, "sessionControls", "signInFrequency") or {}
        if f.get("isEnabled") is True and f.get("type") == "hours" and f.get("value") is not None and f["value"] <= limit:
            covered |= set(lib.as_list(lib.g(p, "conditions", "users", "includeRoles")))
    missing = [n for r, n in roles.items() if r not in covered]
    return _result(not missing, lib, missing, f"All privileged roles have sessions of {limit} hours or less", f"{len(missing)} privileged role(s) without a short session policy")


@zt("21830", "Conditional Access policies for Privileged Access Workstations are configured", "High", ("CA_Policies", "RoleDefinitions"), plan="P1",
    expected="Policies require a compliant device for privileged roles and use a device filter exclusion")
def _(e, lib):
    roles = set(_privileged_roles(e))
    comp = [p for p in _enabled_ca(e) if roles & set(lib.as_list(lib.g(p, "conditions", "users", "includeRoles"))) and lib.has(lib.g(p, "grantControls", "builtInControls"), "compliantDevice")]
    filt = [p for p in _enabled_ca(e) if roles & set(lib.as_list(lib.g(p, "conditions", "users", "includeRoles"))) and lib.lc(lib.g(p, "conditions", "devices", "deviceFilter", "mode")) == "exclude"
            and (not lib.as_list(lib.g(p, "grantControls", "builtInControls")) or lib.has(lib.g(p, "grantControls", "builtInControls"), "block"))]
    return {"pass": bool(comp and filt), "actual": f"Compliant-device policies = {len(comp)}; device-filter policies = {len(filt)}"}


@zt("21865", "Named locations are configured", "Medium", ("CA_NamedLocations",), plan="P1", expected="At least one named location is marked trusted")
def _(e, lib):
    trusted = [l for l in e.ds("CA_NamedLocations") if l.get("isTrusted") is True]
    return {"pass": bool(trusted), "actual": f"{len(trusted)} trusted of {len(e.ds('CA_NamedLocations'))} named location(s)"}


@zt("21883", "Workload Identities are configured with risk-based policies", "Medium", ("CA_Policies",),
    expected="An enabled policy blocks workload identities")
def _(e, lib):
    hits = [p for p in _enabled_ca(e) if lib.has(lib.g(p, "grantControls", "builtInControls"), "block") and lib.g(p, "conditions", "clientApplications", "includeServicePrincipals")]
    return _ca_pass(hits, lib, "", "No enabled policy blocks workload identities")


@zt("21892", "All sign-in activity comes from managed devices", "High", ("CA_Policies",), plan="P1",
    expected="An enabled policy for all users and all apps requires a compliant or hybrid-joined device")
def _(e, lib):
    hits = [p for p in _enabled_ca(e) if (lib.has(lib.g(p, "grantControls", "builtInControls"), "compliantDevice") or lib.has(lib.g(p, "grantControls", "builtInControls"), "domainJoinedDevice"))
            and lib.has(lib.g(p, "conditions", "users", "includeUsers"), "All") and lib.has(lib.g(p, "conditions", "applications", "includeApplications"), "All")]
    return _ca_pass(hits, lib, "", "No enabled policy requires a managed device for all users and apps")


# ------------------------------------------------------------------------------ privileged access
@zt("21782", "Privileged accounts have phishing-resistant methods registered", "High", ("RoleAssignments", "RoleEligibility", "RoleDefinitions", "MfaRegistration"), plan="P1",
    expected="Every user holding a privileged role has a passkey or Windows Hello for Business registered (direct assignments)")
def _(e, lib):
    roles = _privileged_roles(e)
    methods = {m.get("id"): lib.as_list(m.get("methodsRegistered")) for m in e.ds("MfaRegistration")}
    found = []
    for a in _assignments(e, set(roles), {"#microsoft.graph.user"}):
        if not any(m in methods.get(a.get("principalId"), []) for m in PHISH_RESISTANT_METHODS_USER):
            found.append(_who(a, roles))
    return _result(not found, lib, found, "All privileged users have phishing-resistant methods", f"{len(found)} privileged assignment(s) without a phishing-resistant method")


@zt("21801", "Users have strong authentication methods configured", "High", ("Users", "MfaRegistration"), plan="P1",
    expected="Every enabled user has a passkey or Windows Hello for Business registered")
def _(e, lib):
    methods = {m.get("id"): lib.as_list(m.get("methodsRegistered")) for m in e.ds("MfaRegistration")}
    found = [str(u.get("userPrincipalName")) for u in e.ds("Users") if u.get("accountEnabled") is True
             and not any(m in methods.get(u.get("id"), []) for m in PHISH_RESISTANT_METHODS_USER)]
    return _result(not found, lib, found, "All enabled users have a phishing-resistant method", f"{len(found)} enabled user(s) without a phishing-resistant method")


@zt("21813", "High Global Administrator to privileged user ratio", "Medium", ("RoleAssignments", "RoleEligibility", "RoleDefinitions"),
    expected="Global Administrators are under 30% of users holding privileged roles")
def _(e, lib):
    roles = _privileged_roles(e)
    ga = {a.get("principalId") for a in _assignments(e, {GLOBAL_ADMIN}, {"#microsoft.graph.user"})}
    other = {a.get("principalId") for a in _assignments(e, set(roles) - {GLOBAL_ADMIN}, {"#microsoft.graph.user"})}
    total = len(ga) + len(other)
    if total == 0:
        return {"pass": True, "actual": "No privileged users"}
    pct = round(len(ga) * 100 / total, 2)
    return {"pass": pct < 30, "actual": f"{len(ga)} Global Administrators of {total} privileged users ({pct}%)"}


@zt("21814", "Privileged accounts are cloud native identities", "High", ("RoleAssignments", "RoleEligibility", "RoleDefinitions"),
    expected="No user holding a privileged role is synchronized from on-premises")
def _(e, lib):
    roles = _privileged_roles(e)
    synced = {u.get("id") for u in (e.ds("Users") or []) if u.get("onPremisesSyncEnabled") is True}
    found = sorted({_who(a, roles) for a in _assignments(e, set(roles), {"#microsoft.graph.user"})
                    if lib.g(a, "principal", "onPremisesSyncEnabled") is True or a.get("principalId") in synced})
    return _result(not found, lib, found, "All privileged accounts are cloud-only", f"{len(found)} synchronized privileged account(s)")


@zt("21815", "All privileged role assignments are activated just in time and not permanently active", "High", ("RoleAssignmentSchedules", "RoleDefinitions"), plan="P2",
    expected="No privileged role has a permanent active assignment (break-glass accounts excluded)")
def _(e, lib):
    roles = _privileged_roles(e)
    found = [_who(a, roles) for a in e.ds("RoleAssignmentSchedules") if a.get("roleDefinitionId") in roles and a.get("assignmentType") == "Assigned"
             and lib.g(a, "scheduleInfo", "expiration", "type") == "noExpiration" and a.get("principalId") not in e.emergency]
    return _result(not found, lib, found, "No permanent active privileged assignments", f"{len(found)} permanent active assignment(s)")


@zt("21836", "Workload Identities are not assigned privileged roles", "High", ("RoleAssignments", "RoleEligibility", "RoleDefinitions"), plan="P1",
    expected="No service principal or managed identity holds a privileged role")
def _(e, lib):
    roles = _privileged_roles(e)
    found = [_who(a, roles) for a in _assignments(e, set(roles), {"#microsoft.graph.servicePrincipal", "#microsoft.graph.managedIdentity"})]
    return _result(not found, lib, found, "No workload identity holds a privileged role", f"{len(found)} privileged assignment(s) held by workload identities")


@zt("22128", "Guests are not assigned high privileged directory roles", "High", ("RoleAssignments", "RoleEligibility", "RoleDefinitions"),
    expected="No guest user holds a privileged role")
def _(e, lib):
    roles = _privileged_roles(e)
    found = [_who(a, roles) for a in _assignments(e, set(roles), {"#microsoft.graph.user"}) if lib.g(a, "principal", "userType") == "Guest"]
    return _result(not found, lib, found, "No guest holds a privileged role", f"{len(found)} guest privileged assignment(s)")


@zt("24570", "Entra Connect Sync is configured with Service Principal Credentials", "High", ("Organization", "RoleAssignments"),
    expected="In a hybrid tenant, no enabled user account holds the Directory Synchronization Accounts role")
def _(e, lib):
    org = e.first("Organization") or {}
    if org.get("onPremisesSyncEnabled") in (None, False):
        return {"pass": True, "actual": "Directory synchronization is not enabled in this tenant"}
    found = [str(lib.g(a, "principal", "userPrincipalName") or a.get("principalId")) for a in _assignments(e, {DIRSYNC_ROLE}, {"#microsoft.graph.user"}, include_eligible=False)
             if lib.g(a, "principal", "accountEnabled") is not False]
    return _result(not found, lib, found, "Directory sync uses a service principal", f"{len(found)} enabled user account(s) in the Directory Synchronization role")


@zt("25383", "Administrative privileges are tightly limited to prevent compromise", "High", ("RoleAssignments", "RoleEligibility", "RoleDefinitions"), plan="P1",
    expected="Global Administrator and Global Secure Access Administrator are held only by enabled member users (at most five assignments)")
def _(e, lib):
    role_ids = {GLOBAL_ADMIN} | {r["id"] for r in e.ds("RoleDefinitions") if r.get("displayName") == "Global Secure Access Administrator"}
    rows = _assignments(e, role_ids)
    bad = []
    for a in rows:
        p = a.get("principal") or {}
        t = p.get("@odata.type")
        if t != "#microsoft.graph.user" or p.get("userType") == "Guest":
            bad.append(f"{p.get('displayName') or a.get('principalId')} ({str(t).split('.')[-1]}{', guest' if p.get('userType') == 'Guest' else ''})")
    if bad:
        return {"pass": False, "affected": bad, "actual": "Groups, service principals or guests hold these roles: " + lib.join_findings(bad)}
    note = []
    if any(lib.g(a, "principal", "accountEnabled") is False for a in rows):
        note.append("a disabled account holds a role")
    if len(rows) > 5:
        note.append(f"{len(rows)} assignments (more than 5)")
    return {"pass": True, "actual": ("Investigate: " + "; ".join(note)) if note else f"{len(rows)} assignment(s), all enabled member users"}


@zt("21955", "Manage the local administrators on Microsoft Entra joined devices", "Medium", ("RoleAssignments", "RoleEligibility"), plan="P1",
    expected="The Microsoft Entra Joined Device Local Administrator role has at least one assignment")
def _(e, lib):
    n = len(_assignments(e, {AAD_JOIN_LOCAL_ADMIN_ROLE}))
    return {"pass": n > 0, "actual": f"{n} assignment(s)"}


# ------------------------------------------------------------------------------ guests and external collaboration
@zt("21822", "Guest access is limited to approved tenants", "Medium", ("Legacy_Policies",), expected="An allow list of domains is configured for invitations")
def _(e, lib):
    allowed = _b2b_domains(e, lib)
    return {"pass": bool(allowed), "actual": f"Allowed domains: {len(allowed)}"}


@zt("21874", "Guest access is limited to approved tenants (collaboration allow list present)", "Medium", ("Legacy_Policies",), expected="AllowedDomains is configured")
def _(e, lib):
    allowed = _b2b_domains(e, lib)
    return {"pass": allowed is not None and len(allowed) > 0, "actual": f"Allowed domains: {len(allowed) if allowed is not None else 'not configured'}"}


def _b2b_domains(e, lib) -> list | None:
    import json as _json
    for pol in e.ds("Legacy_Policies"):
        if pol.get("type") != "B2BManagementPolicy":
            continue
        for d in lib.as_list(pol.get("definition")):
            try:
                doc = _json.loads(d) if isinstance(d, str) else d
            except ValueError:
                continue
            node = (doc.get("B2BManagementPolicy") or {}).get("InvitationsAllowedAndBlockedDomainsPolicy") or {}
            return node.get("AllowedDomains") or []
    return []


@zt("21823", "Guest self-service sign-up via user flow is disabled", "Medium", ("AuthFlowsPolicy",), expected="selfServiceSignUp.isEnabled is false")
def _(e, lib):
    v = lib.g(e.first("AuthFlowsPolicy") or {}, "selfServiceSignUp", "isEnabled")
    return {"pass": v is False, "actual": f"selfServiceSignUp.isEnabled = {_s(lib, v)}"}


@zt("21858", "Inactive guest identities are disabled or removed from the tenant", "Medium", ("Users",), plan="P1",
    expected="No enabled guest has been inactive for more than 90 days")
def _(e, lib):
    found = []
    for u in e.ds("Users"):
        if u.get("userType") != "Guest" or u.get("accountEnabled") is not True:
            continue
        last = _dt(lib, lib.g(u, "signInActivity", "lastSuccessfulSignInDateTime")) or _dt(lib, u.get("createdDateTime"))
        if last and (e.now - last).days > 90:
            found.append(f"{u.get('userPrincipalName')} ({(e.now - last).days} days)")
    return _result(not found, lib, found, "No inactive guests", f"{len(found)} enabled guest(s) inactive for more than 90 days")


@zt("21877", "All guests have a sponsor", "Medium", ("Users", "Guest_Sponsors"), expected="Every guest user has at least one sponsor")
def _(e, lib):
    sponsored = {s.get("parentId") for s in e.ds("Guest_Sponsors")}
    found = [str(u.get("userPrincipalName")) for u in e.ds("Users") if u.get("userType") == "Guest" and u.get("id") not in sponsored]
    return _result(not found, lib, found, "All guests have a sponsor", f"{len(found)} guest(s) without a sponsor")


def _external(policy: dict) -> bool:
    return str(policy.get("allowedTargetScope")) in ("specificConnectedOrganizationUsers", "allConfiguredConnectedOrganizationUsers", "allExternalUsers")


@zt("21875", "All entitlement management assignment policies that apply to external users require connected organizations", "Medium", ("EntMgmt_PoliciesV1",), plan="P2",
    expected="No policy lets all external users request access")
def _(e, lib):
    found = [str(p.get("displayName")) for p in e.ds("EntMgmt_PoliciesV1") if p.get("allowedTargetScope") == "allExternalUsers"]
    return _result(not found, lib, found, "External access is limited to connected organizations", f"{len(found)} policy(ies) open to all external users")


@zt("21878", "All entitlement management policies have an expiration date", "Medium", ("EntMgmt_PoliciesV1",), plan="P2",
    expected="Every assignment policy has an expiration (after a duration or on a date)")
def _(e, lib):
    found = []
    for p in e.ds("EntMgmt_PoliciesV1"):
        x = p.get("expiration") or {}
        if not ((x.get("duration") and x.get("type") == "afterDuration") or (x.get("endDateTime") and x.get("type") == "afterDateTime")):
            found.append(str(p.get("displayName")))
    return _result(not found, lib, found, "All policies expire", f"{len(found)} policy(ies) without an expiration")


@zt("21879", "All entitlement management assignment policies that apply to external users require approval", "Medium", ("EntMgmt_PoliciesV1",), plan="P2",
    expected="Policies that accept requests from external users require approval")
def _(e, lib):
    found = [str(p.get("displayName")) for p in e.ds("EntMgmt_PoliciesV1") if (p.get("requestorSettings") or {}).get("acceptRequests") is True
             and _external(p) and not bool(lib.g(p, "approvalSettings", "isApprovalRequired"))]
    return _result(not found, lib, found, "External requests require approval", f"{len(found)} external policy(ies) without approval")


@zt("21929", "All entitlement management packages that apply to guests have expirations or access reviews configured in their assignment policies", "Medium", ("EntMgmt_PoliciesV1",), plan="P2",
    expected="Policies for external users expire or have a recurring access review")
def _(e, lib):
    flags = ("enableTargetsToSelfAddAccess", "enableTargetsToSelfUpdateAccess", "enableTargetsToSelfRemoveAccess", "enableOnBehalfRequestorsToAddAccess",
             "enableOnBehalfRequestorsToUpdateAccess", "enableOnBehalfRequestorsToRemoveAccess")
    found = []
    for p in e.ds("EntMgmt_PoliciesV1"):
        rs = p.get("requestorSettings") or {}
        if not rs or not p.get("accessPackage") or not any(rs.get(f) is True for f in flags) or not _external(p):
            continue
        has_expiry = bool(p.get("expiration")) and lib.g(p, "expiration", "type") != "noExpiration"
        has_review = lib.g(p, "reviewSettings", "isEnabled") is True and bool(lib.g(p, "reviewSettings", "schedule", "recurrence", "pattern"))
        if not (has_expiry or has_review):
            found.append(str(p.get("displayName")))
    return _result(not found, lib, found, "Guest packages expire or are reviewed", f"{len(found)} policy(ies) without expiry or access review")


# ------------------------------------------------------------------------------ Identity Protection
def _high_unresolved(rows: list, lib) -> list | None:
    """High-risk, unresolved rows; None when every row's riskLevel is "hidden" (licence does not expose risk details)."""
    if rows and all(lib.lc(r.get("riskLevel")) == "hidden" for r in rows):
        return None
    return [r for r in rows if lib.lc(r.get("riskLevel")) == "high" and lib.lc(r.get("riskState")) == "atrisk"]


@zt("21861", "All high-risk users are triaged", "High", ("RiskyUsers",), plan="P2", expected="No user is at high risk and unresolved")
def _(e, lib):
    rows = _high_unresolved(e.ds("RiskyUsers"), lib)
    if rows is None:
        return {"skip": "Risk levels are hidden for this tenant's licence, so high-risk users cannot be identified"}
    found = [str(u.get("userPrincipalName") or u.get("id")) for u in rows]
    return _result(not found, lib, found, "No unresolved high-risk users", f"{len(found)} high-risk user(s) not triaged")


@zt("21862", "All risky workload identities are triaged", "High", ("RiskyServicePrincipals", "SP_RiskDetections"), plan="P2", expected="No risky service principal or open risk detection")
def _(e, lib):
    found = [f"Service principal: {s.get('displayName') or s.get('id')}" for s in e.ds("RiskyServicePrincipals") if s.get("riskState") == "atRisk"]
    found += [f"Detection: {d.get('servicePrincipalDisplayName') or d.get('id')}" for d in e.ds("SP_RiskDetections") if d.get("riskState") == "atRisk"]
    return _result(not found, lib, found, "No risky workload identities", f"{len(found)} untriaged item(s)")


@zt("21863", "All high-risk sign-ins are triaged", "High", ("RiskDetections",), plan="P2", expected="No high-risk detection is still at risk")
def _(e, lib):
    rows = _high_unresolved(e.ds("RiskDetections"), lib)
    if rows is None:
        return {"skip": "Risk levels are hidden for this tenant's licence, so high-risk detections cannot be identified"}
    found = [f"{d.get('userPrincipalName') or d.get('id')}: {d.get('riskEventType')}" for d in rows]
    return _result(not found, lib, found, "No untriaged high-risk sign-ins", f"{len(found)} high-risk detection(s) not triaged")


@zt("22659", "All risky workload identity sign-ins are triaged", "High", ("SP_RiskDetections",), plan="P2", expected="No sign-in risk detection for a workload identity is at risk")
def _(e, lib):
    found = [str(d.get("servicePrincipalDisplayName") or d.get("id")) for d in e.ds("SP_RiskDetections") if d.get("activity") == "signIn" and d.get("riskState") == "atRisk"]
    return _result(not found, lib, found, "No untriaged workload identity sign-in risks", f"{len(found)} detection(s) not triaged")


# ------------------------------------------------------------------------------ devices (Entra settings)
@zt("21837", "Limit the maximum number of devices per user to 10", "Medium", ("DeviceRegPolicy",), expected="userDeviceQuota is 10 or less")
def _(e, lib):
    q = (e.first("DeviceRegPolicy") or {}).get("userDeviceQuota")
    return {"pass": q is None or q <= 10, "actual": f"userDeviceQuota = {_s(lib, q)}"}


@zt("21953", "Local Admin Password Solution is deployed", "Medium", ("DeviceRegPolicy",), plan="P1", expected="Windows LAPS is enabled in the device settings")
def _(e, lib):
    v = lib.g(e.first("DeviceRegPolicy") or {}, "localAdminPassword", "isEnabled")
    return {"pass": v is True, "actual": f"localAdminPassword.isEnabled = {_s(lib, v)}"}


@zt("21954", "Restrict nonadministrator users from recovering the BitLocker keys for their owned devices", "Medium", ("AuthorizationPolicy",),
    expected="allowedToReadBitlockerKeysForOwnedDevice is false")
def _(e, lib):
    v = lib.g(e.first("AuthorizationPolicy") or {}, "defaultUserRolePermissions", "allowedToReadBitlockerKeysForOwnedDevice")
    return {"pass": v is False, "actual": f"allowedToReadBitlockerKeysForOwnedDevice = {_s(lib, v)}"}
