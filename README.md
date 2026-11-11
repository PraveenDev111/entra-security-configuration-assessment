# Entra ID Security Configuration Assessment

A read-only assessment of a client's Microsoft 365 and Entra ID tenant. It collects configuration data, runs baseline checks and stores
the raw data and the results per company, ready to be pushed to Elasticsearch.

**What it covers**
- Entra ID: Conditional Access, authentication and MFA, privileged roles and PIM, guests, application consent and credentials, devices, governance, hybrid sync settings, logging
- Intune, Exchange Online, Teams, SharePoint and OneDrive, security and compliance settings, Azure (identity-related)
- Domains: SPF, DKIM and DMARC for each verified domain
- Benchmarks: CISA SCuBA, CIS Microsoft 365, ORCA, Zero Trust Assessment, EIDSCA and Jolera Extended Controls
- Every control ends as Pass, Fail, Not Assessable or Not Applicable, with severity (Critical to Low), area, NIST CSF 2.0 subcategory, licence needed, affected objects, description and remediation

## Layout
```
src/        the tool (run these scripts)
  entra_collect.py    1. collects data for each company into runs/
  entra_checks.py     2. runs the checks and writes the results next to the data
  push_to_elastic.py  3. pushes data and results to Elasticsearch (one index)
  workloads.py        workload selection, Exchange / Teams / Azure / DNS collection
  spec_engine.py      evaluator for the JSON rule specs
  zta_checks.py       Zero Trust Assessment checks for Entra
  dashboard_data.py   builds the data file for the example dashboard (run separately, optional)
  validate_specs.py   checks the spec files
  paths.py            where config, data, specs and runs live
config/     companies.example.json (copy to companies.json), severity_overrides.json
specs/      the rules for every workload and their data sources (see specs/README.md)
data/       rule_details.json (description, remediation and links of the Entra checks)
docs/       rules_catalog.xlsx (all rules), zta_coverage.xlsx (Zero Trust tests added or not)
runs/       created when you collect; one folder per company and run (not committed)
PERMISSIONS.md   what the app registration needs      NOTICE.md   third-party licences
```

## Quick start
```bash
python -m pip install -r requirements.txt
cp .env.example .env                                    # client id and secret per app label
cp config/companies.example.json config/companies.json  # one entry per company (see below)

python src/entra_collect.py --list                      # companies and whether their credentials are set
python src/entra_collect.py                             # collect every enabled company
python src/entra_checks.py --last-run runs              # run the checks for the latest collection (--excel writes a workbook)
python src/push_to_elastic.py --last-run runs --es-url https://... --api-key ...
```
Run them from anywhere: paths are resolved from the project root. Override with `SECUREIT_OUTPUT_DIR`, `SECUREIT_COMPANIES` and `SECUREIT_ENV_FILE`.

## Configuration
`config/companies.json` has one entry per company: `company_name`, `company_id` (folder name), `tenant_id`, `app` (a label such as `app-1`, not a secret).
Optional: `enabled`, `emergency_access_ids`, `workloads` or `exclude_workloads` (entra, intune, exchange, teams, sharepoint, compliance, defender, azure),
and `domains` (verified domains in scope for the DNS checks; default all). `app-1` reads `ENTRA_APP_1_CLIENT_ID` and `ENTRA_APP_1_CLIENT_SECRET`
from the environment or `.env`. Required access per workload: see [PERMISSIONS.md](PERMISSIONS.md) or run `python src/entra_collect.py --permissions`.

## Results and Elasticsearch
Each run is saved as `runs/<company_id>/<run_id>/` with `raw/*.json`, `manifest.json`, `enriched/check_results.json` and `check_summary.json`.
`push_to_elastic.py` writes two indices with the same mapping: `entra-raw` (`data_type` raw and meta: the pulled objects and the collection log) and `entra-sca` (`data_type` enriched: check results and summaries); change them with `--raw-index` and `--sca-index`. Documents carry `data_type`, `data_category` and `doc_type`
(`record`, `check_result`, `check_summary`, `area_summary`, `collection_log`). Every document carries `@timestamp` (collection time), `run_id`,
`batch_id`, `company_id`, `company_name` and `tenant_id`. Document ids are deterministic, so pushing a run twice overwrites it. Use `--dry-run file.ndjson` to inspect
the documents without connecting. The posture score per area is pass / (pass + fail).

## Changing the checks
Add or edit rules in `specs/*.json` and run `python src/validate_specs.py`. `config/severity_overrides.json` sets reviewed severities by rule id (for example Critical).
The Entra rules written as code are in `src/entra_checks.py` and `src/zta_checks.py`.

## Status
The calls to Exchange Online, Teams, Azure Resource Manager and several Intune, SharePoint and Forms Graph resources were written from Microsoft documentation and have
not all been run against a tenant. A call that is refused is reported as Not Assessable with the reason.

Never commit `.env`, `config/companies.json` or `runs/`: they hold secrets and client data (they are in `.gitignore`).
