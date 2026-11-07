# Access the assessment app needs (read-only)

One app registration per client tenant (or one multi-tenant app consented in each tenant). Everything is read-only: Microsoft Graph
`GET`, Exchange `Get-*` cmdlets and Azure Resource Manager `GET`. Nothing in the tenant is changed.
`python src/entra_collect.py --permissions` prints the current list from the check specs.

Choose what to collect for each client in `config/companies.json`: `"exclude_workloads": ["intune"]` (everything except Intune) or
`"workloads": ["entra", "exchange"]` (only these). Workloads: `entra`, `intune`, `exchange`, `teams`, `sharepoint`, `compliance`, `defender`, `azure`.
Only add the permissions of the workloads you collect. A permission that is missing never stops a run: the checks that need it are
reported as **Not Assessable** with the reason.

## 1. Microsoft Graph application permissions (admin consent in each tenant)

| Workload | Permissions |
|---|---|
| Entra ID (always) | AuditLog.Read.All, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All, RoleEligibilitySchedule.Read.Directory, RoleManagementPolicy.Read.Directory, RoleManagementAlert.Read.Directory, OnPremDirectorySynchronization.Read.All, EntitlementManagement.Read.All, DirectoryRecommendations.Read.All |
| Entra ID, risk checks (Entra ID P2) | IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, IdentityRiskyServicePrincipal.Read.All |
| Intune | DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementApps.Read.All, DeviceManagementRBAC.Read.All, DeviceManagementServiceConfig.Read.All, Organization.Read.All |
| SharePoint and OneDrive (also the Forms and third-party storage checks) | SharePointTenantSettings.Read.All, OrgSettings-Forms.Read.All, Application.Read.All |
| Teams, Exchange, compliance, Azure | none (see below) |

## 2. Exchange Online (workloads `exchange` and `compliance`)
1. API permissions > Add a permission > APIs my organization uses > **Office 365 Exchange Online** > Application permissions > **Exchange.ManageAsApp** > grant admin consent.
2. Entra ID > Roles and administrators > **Global Reader** (or Security Reader) > Add assignments > select the app's enterprise application.
Without step 2 Exchange refuses the cmdlets even though the permission is consented.

## 3. Teams (workload `teams`, experimental)
Assign the Entra role **Global Reader** (or Teams Administrator) to the app's service principal, as in Exchange step 2. The collector calls the Teams admin
configuration service directly; Microsoft does not document this service for application access, so these checks are reported as Not Assessable if the call is refused.

## 4. Azure, identity-related (workload `azure`, off by default; use `--include-azure` or list it in `workloads`)
Azure RBAC **Reader** for the app at the tenant root management group (`/`). A Global Administrator of the tenant may have to turn on "Access management for Azure resources" once to be able to grant it.

## 5. DNS (SPF, DKIM, DMARC per verified domain)
No permission. The collector reads public DNS from the machine it runs on. List the domains in scope in `config/companies.json` (`"domains": [...]`); with no list every verified domain is checked.

## 6. Removing access at the end of an engagement
1. Entra ID > Enterprise applications > the assessment app > Delete (this removes the consent and all permissions in that tenant).
2. If used: remove its Global Reader / Security Reader role assignment (removed with the enterprise application), and the Azure Reader role assignment at the root scope.
3. Delete the client secret you created for the client; rotate it if the app is shared.
4. Delete or archive the collected data according to the retention agreed with the client.

## Checked against documentation only
The calls below were written from Microsoft documentation and the source tests, not run against a tenant: Exchange `InvokeCommand`, the Teams admin service,
Azure Resource Manager (role assignments at root scope, Entra diagnostic settings), and these Graph resources: `deviceManagement/settings`, `managedDeviceCleanupRules`,
`operationApprovalPolicies`, `intuneBrandingProfiles`, `admin/sharepoint/settings`, `admin/forms/settings`. A refused call is shown on the Not Assessable control, so run one test tenant first.
