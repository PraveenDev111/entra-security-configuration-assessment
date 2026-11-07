# Check specs

Checks for Intune, Exchange Online, Teams, SharePoint, compliance, Azure and extra Entra controls are JSON files, not code.
Each file declares the **sources** the collector pulls and the **rules** the evaluator (`src/spec_engine.py`) runs on that data.
Run `python src/validate_specs.py` after any change.

```json
{
  "workload": "exchange",
  "sources": { "EXO_OrganizationConfig": { "type": "exo", "cmdlet": "Get-OrganizationConfig", "params": {} } },
  "rules":   [ { "...": "see below" } ],
  "not_ported": [ { "origin": "MS.EXO.5.1v1", "reason": "needs per-mailbox data" } ]
}
```

Other files in this folder: `nist_map.json` (rule id to one NIST CSF 2.0 subcategory), `required_licence.json` (rule id to licence) and
`reference_map.json` (rule id to extra benchmark references). They are not spec files.

## Sources (one data set = a JSON list of objects, saved as `runs/<company>/<run>/raw/<name>.json`)
| type | example | notes |
|---|---|---|
| `graph` | `{"type":"graph","api":"beta","uri":"deviceManagement/deviceCompliancePolicies","permission":"DeviceManagementConfiguration.Read.All"}` | GET only, paged automatically. Always set `permission` (it feeds `--permissions`). |
| `exo` | `{"type":"exo","cmdlet":"Get-AntiPhishPolicy","params":{}}` | Exchange Online REST `InvokeCommand`. Only `Get-*` cmdlets are accepted. |
| `teams` | `{"type":"teams","config":"TeamsMeetingPolicy"}` | Teams admin configuration (experimental). |
| `arm` | `{"type":"arm","uri":"providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"}` | Azure Resource Manager GET. |

Built in, no definition needed: `DNS_MailAuth` (one row per verified domain: `domain, is_initial, is_default, authentication_type, mx_records, spf_record,
spf_all_qualifier, spf_lookup_count, dmarc_record, dmarc_policy, dmarc_subdomain_policy, dmarc_pct, dmarc_rua, dmarc_ruf, dkim_selector1_cname,
dkim_selector2_cname`) and the Entra data sets listed in `DATASETS` in `src/entra_collect.py` (`CA_Policies`, `Users`, `Domains`, ...).

## Rules
```json
{
  "id": "EXO.CISA.1.1",            "reference": "MS.EXO.1.1v2",      "framework": "CISA SCuBA",
  "area": "Exchange Online",       "title": "Automatic forwarding to external domains is disabled",
  "severity": "High",              "licence": "",                    "nist": "PR.DS-02",
  "source": "EXO_HostedOutboundSpamFilterPolicy", "mode": "all",
  "filter": [], "conditions": [ { "path": "AutoForwardingMode", "op": "eq", "value": "Off" } ],
  "name": "Identity", "fail_if_empty": false, "empty_message": "No outbound spam policy found",
  "description": "...", "remediation": "...", "impact": "", "links": [ { "text": "...", "url": "https://learn.microsoft.com/..." } ],
  "origin": "source test name"
}
```
* `framework`: CISA SCuBA, CIS Microsoft 365, ORCA, Zero Trust Assessment or Jolera Extended Controls.
* `area`: Entra ID, Intune, Exchange Online, Teams, SharePoint and OneDrive, Security and compliance, Azure (identity).
* `severity`: Critical, High, Medium, Low or Info (`config/severity_overrides.json` can override any rule id).
* `mode`: `all` (every considered row must satisfy the conditions), `any` (at least one), `none` (no row may), `first` (singleton data set).
* `filter` limits the rows considered; `fail_if_empty` (and every `any` rule) fails when nothing is left, otherwise no rows means Not Applicable.
* condition = `{"path": "A.B", "op": "...", "value": ...}`; `{"any": [...]}` and `{"all": [...]}` nest.
  Operators: `eq ne in notin gt ge lt le exists notexists empty notempty contains notcontains regex startswith true false len_ge len_le`.

## How the evaluator reads a spec
* A path that crosses a list is expanded to every element. `eq`, `in`, `gt`, `true`, ... must hold for every element; `contains`, `regex` and `startswith` need any element to match.
* Keys containing a dot (for example `@odata.type`) are matched as a whole before the path is split. Key names are case-insensitive.
* Outcome per control: **Pass**, **Fail**, **Not Assessable** (licence, data not collected, permission refused) or **Not Applicable** (workload not licensed, nothing to evaluate).
* Controls that could not be expressed are listed in `not_ported` with the reason.
