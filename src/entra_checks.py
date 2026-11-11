#!/usr/bin/env python3
"""Run the Entra ID baseline checks on data pulled by entra_collect.py.

Offline: makes no calls to Microsoft 365. Reads  <run-dir>/raw/*.json  and writes
  <run-dir>/enriched/check_results.json   one record per check (Passed / Failed / Skipped, expected, actual, reason)
  <run-dir>/enriched/check_summary.json   counts per framework
and, with --excel, <run-dir>/enriched/check_results.xlsx.
Give one or more run folders, or --last-run <output-dir> to check every company of the latest collection batch.

Statuses:  Passed  = the setting matches the baseline
           Failed  = it does not (see "actual")
           Skipped = the check does not apply (licence, feature not enabled) or its data was not collected

Rules: EIDSCA controls, Conditional Access baseline, session-hijack protection, applications and permissions,
identity settings, privileged access (PIM), hybrid sync, entitlement management, Entra recommendations and logging.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

import paths

# ------------------------------------------------------------------------------ constants (generated tables)
EIDSCA_RULES: list[dict[str, Any]] = [
    {'id': 'AF01', 'title': 'Authentication Method - FIDO2 security key - State', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Fido2', 'pre': [], 'value': ('path', 'state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AF02', 'title': 'Authentication Method - FIDO2 security key - Allow self-service set up', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Fido2', 'pre': ['authmethod:Fido2'], 'value': ('path', 'isSelfServiceRegistrationAllowed'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AF03', 'title': 'Authentication Method - FIDO2 security key - Enforce attestation', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Fido2', 'pre': ['authmethod:Fido2'], 'value': ('path', 'isAttestationEnforced'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AF04', 'title': 'Authentication Method - FIDO2 security key - Enforce key restrictions', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Fido2', 'pre': ['authmethod:Fido2'], 'value': ('path', 'keyRestrictions.isEnforced'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AF05', 'title': 'Authentication Method - FIDO2 security key - Restricted', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Fido2', 'pre': ['authmethod:Fido2', 'dep:AF04'], 'value': ('special', 'af05'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AF06', 'title': 'Authentication Method - FIDO2 security key - Restrict specific keys', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Fido2', 'pre': ['authmethod:Fido2', 'dep:AF04'], 'value': ('special', 'af06'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AG01', 'title': 'Authentication Method - General Settings - Manage migration', 'severity': 'High', 'sheet': 'AuthMethodsPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'policyMigrationState'), 'test': ('in', ['migrationComplete', '']), 'test_text': "-in @('migrationComplete', '')"},
    {'id': 'AG02', 'title': 'Authentication Method - General Settings - Report suspicious activity - State', 'severity': 'Medium', 'sheet': 'AuthMethodsPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'reportSuspiciousActivitySettings.state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AG03', 'title': 'Authentication Method - General Settings - Report suspicious activity - Included users/groups', 'severity': 'Medium', 'sheet': 'AuthMethodsPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'reportSuspiciousActivitySettings.includeTarget.id'), 'test': ('eq', 'all_users'), 'test_text': "-eq 'all_users'"},
    {'id': 'AM01', 'title': 'Authentication Method - Microsoft Authenticator - State', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': [], 'value': ('path', 'state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AM02', 'title': 'Authentication Method - Microsoft Authenticator - Allow use of Microsoft Authenticator OTP', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'isSoftwareOathEnabled'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AM03', 'title': 'Authentication Method - Microsoft Authenticator - Require number matching for push notifications', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'featureSettings.numberMatchingRequiredState.state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AM04', 'title': 'Authentication Method - Microsoft Authenticator - Included users/groups of number matching for push notifications', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'featureSettings.numberMatchingRequiredState.includeTarget.id'), 'test': ('eq', 'all_users'), 'test_text': "-eq 'all_users'"},
    {'id': 'AM06', 'title': 'Authentication Method - Microsoft Authenticator - Show application name in push and passwordless notifications', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'featureSettings.displayAppInformationRequiredState.state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AM07', 'title': 'Authentication Method - Microsoft Authenticator - Included users/groups to show application name in push and passwordless notifications', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'featureSettings.displayAppInformationRequiredState.includeTarget.id'), 'test': ('eq', 'all_users'), 'test_text': "-eq 'all_users'"},
    {'id': 'AM09', 'title': 'Authentication Method - Microsoft Authenticator - Show geographic location in push and passwordless notifications', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'featureSettings.displayLocationInformationRequiredState.state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AM10', 'title': 'Authentication Method - Microsoft Authenticator - Included users/groups to show geographic location in push and passwordless notifications', 'severity': 'Medium', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'MicrosoftAuthenticator', 'pre': ['authmethod:MicrosoftAuthenticator'], 'value': ('path', 'featureSettings.displayLocationInformationRequiredState.includeTarget.id'), 'test': ('eq', 'all_users'), 'test_text': "-eq 'all_users'"},
    {'id': 'AP01', 'title': 'Default Authorization Settings - Enabled Self service password reset for administrators', 'severity': 'High', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': ['prop:allowedToUseSSPR'], 'value': ('path', 'allowedToUseSSPR'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AP04', 'title': 'Default Authorization Settings - Guest invite restrictions', 'severity': 'Medium', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'allowInvitesFrom'), 'test': ('in', ['adminsAndGuestInviters', 'none']), 'test_text': "-in @('adminsAndGuestInviters','none')"},
    {'id': 'AP05', 'title': 'Default Authorization Settings - Sign-up for email based subscription', 'severity': 'Medium', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'allowedToSignUpEmailBasedSubscriptions'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AP06', 'title': 'Default Authorization Settings - User can join the tenant by email validation', 'severity': 'Medium', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'allowEmailVerifiedUsersToJoinOrganization'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AP07', 'title': 'Default Authorization Settings - Guest user access', 'severity': 'High', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'guestUserRoleId'), 'test': ('eq', '2af84b1e-32c8-42b7-82bc-daa82404023b'), 'test_text': "-eq '2af84b1e-32c8-42b7-82bc-daa82404023b'"},
    {'id': 'AP08', 'title': 'Default Authorization Settings - User consent policy assigned for applications', 'severity': 'Medium', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': ['ap08'], 'value': ('special', 'ap08'), 'test': ('eq', 'ManagePermissionGrantsForSelf.microsoft-user-default-low'), 'test_text': "-eq 'ManagePermissionGrantsForSelf.microsoft-user-default-low'"},
    {'id': 'AP09', 'title': 'Default Authorization Settings - Allow user consent on risk-based apps', 'severity': 'Medium', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'allowUserConsentForRiskyApps'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AP10', 'title': 'Default Authorization Settings - Default User Role Permissions - Allowed to create Apps', 'severity': 'High', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'defaultUserRolePermissions.allowedToCreateApps'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AP14', 'title': 'Default Authorization Settings - Default User Role Permissions - Allowed to read other users', 'severity': 'High', 'sheet': 'AuthorizationPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'defaultUserRolePermissions.allowedToReadOtherUsers'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AS04', 'title': 'Authentication Method - SMS - Use for sign-in', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Sms', 'pre': ['authmethod:Sms'], 'value': ('special', 'as04'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'AT01', 'title': 'Authentication Method - Temporary Access Pass - State', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'TemporaryAccessPass', 'pre': [], 'value': ('path', 'state'), 'test': ('eq', 'enabled'), 'test_text': "-eq 'enabled'"},
    {'id': 'AT02', 'title': 'Authentication Method - Temporary Access Pass - One-time', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'TemporaryAccessPass', 'pre': ['authmethod:TemporaryAccessPass'], 'value': ('path', 'isUsableOnce'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'AV01', 'title': 'Authentication Method - Voice call - State', 'severity': 'High', 'sheet': 'AuthMethodConfigs', 'mode': 'filter', 'filter': 'Voice', 'pre': [], 'value': ('path', 'state'), 'test': ('eq', 'disabled'), 'test_text': "-eq 'disabled'"},
    {'id': 'CP01', 'title': 'Default Settings - Consent Policy Settings - Group owner consent for apps accessing data', 'severity': 'High', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': ['setting:EnableGroupSpecificConsent'], 'value': ('setting', 'EnableGroupSpecificConsent'), 'test': ('eq', 'False'), 'test_text': "-eq 'False'"},
    {'id': 'CP03', 'title': 'Default Settings - Consent Policy Settings - Block user consent for risky apps', 'severity': 'High', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': [], 'value': ('setting', 'BlockUserConsentForRiskyApps'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'CP04', 'title': 'Default Settings - Consent Policy Settings - Users can request admin consent to apps they are unable to consent to', 'severity': 'Medium', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': [], 'value': ('setting', 'EnableAdminConsentRequests'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'CR01', 'title': 'Consent Framework - Admin Consent Request - Policy to enable or disable admin consent request feature', 'severity': 'High', 'sheet': 'AdminConsentPolicy', 'mode': 'first', 'filter': '', 'pre': [], 'value': ('path', 'isEnabled'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'CR02', 'title': 'Consent Framework - Admin Consent Request - Reviewers will receive email notifications for requests', 'severity': 'Medium', 'sheet': 'AdminConsentPolicy', 'mode': 'first', 'filter': '', 'pre': ['adminconsent'], 'value': ('path', 'notifyReviewers'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'CR03', 'title': 'Consent Framework - Admin Consent Request - Reviewers will receive email notifications when admin consent requests are about to expire', 'severity': 'Medium', 'sheet': 'AdminConsentPolicy', 'mode': 'first', 'filter': '', 'pre': ['adminconsent'], 'value': ('path', 'remindersEnabled'), 'test': ('eq', 'true'), 'test_text': "-eq 'true'"},
    {'id': 'CR04', 'title': 'Consent Framework - Admin Consent Request - Consent request duration (days)', 'severity': 'High', 'sheet': 'AdminConsentPolicy', 'mode': 'first', 'filter': '', 'pre': ['adminconsent'], 'value': ('path', 'requestDurationInDays'), 'test': ('le', 30), 'test_text': '-le 30'},
    {'id': 'PR01', 'title': 'Default Settings - Password Rule Settings - Password Protection - Mode', 'severity': 'High', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': ['plan'], 'value': ('setting', 'BannedPasswordCheckOnPremisesMode'), 'test': ('eq', 'Enforce'), 'test_text': "-eq 'Enforce'"},
    {'id': 'PR02', 'title': 'Default Settings - Password Rule Settings - Password Protection - Enable password protection on Windows Server Active Directory', 'severity': 'High', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': ['plan'], 'value': ('setting', 'EnableBannedPasswordCheckOnPremises'), 'test': ('eq', 'True'), 'test_text': "-eq 'True'"},
    {'id': 'PR03', 'title': 'Default Settings - Password Rule Settings - Enforce custom list', 'severity': 'Medium', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': ['plan'], 'value': ('setting', 'EnableBannedPasswordCheck'), 'test': ('eq', 'True'), 'test_text': "-eq 'True'"},
    {'id': 'PR05', 'title': 'Default Settings - Password Rule Settings - Smart Lockout - Lockout duration in seconds', 'severity': 'Medium', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': ['plan'], 'value': ('setting', 'LockoutDurationInSeconds'), 'test': ('ge', 60), 'test_text': '-ge 60'},
    {'id': 'PR06', 'title': 'Default Settings - Password Rule Settings - Smart Lockout - Lockout threshold', 'severity': 'Medium', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': ['plan'], 'value': ('setting', 'LockoutThreshold'), 'test': ('le', 10), 'test_text': '-le 10'},
    {'id': 'ST08', 'title': 'Default Settings - Classification and M365 Groups - M365 groups - Allow Guests to become Group Owner', 'severity': 'Medium', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': [], 'value': ('setting', 'AllowGuestsToBeGroupOwner'), 'test': ('eq', 'false'), 'test_text': "-eq 'false'"},
    {'id': 'ST09', 'title': 'Default Settings - Classification and M365 Groups - M365 groups - Allow Guests to have access to groups content', 'severity': 'Medium', 'sheet': 'DirectorySettings', 'mode': 'all', 'filter': '', 'pre': [], 'value': ('setting', 'AllowGuestsToAccessGroups'), 'test': ('eq', 'True'), 'test_text': "-eq 'True'"},
]

SEVERITY: dict[str, str] = {
    "APP-01": "Medium",
    "APP-02": "Medium",
    "APP-03": "Medium",
    "APP-04": "High",
    "APP-05": "Medium",
    "APP-06": "High",
    "APP-07": "High",
    "APP-08": "High",
    "APP-09": "High",
    "APP-10": "High",
    "APP-11": "Medium",
    "CA-01": "Medium",
    "CA-02": "High",
    "CA-03": "High",
    "CA-04": "High",
    "CA-05": "High",
    "CA-06": "High",
    "CA-07": "High",
    "CA-08": "Medium",
    "CA-09": "Medium",
    "CA-10": "Medium",
    "CA-11": "Medium",
    "CA-12": "Medium",
    "CA-13": "High",
    "CA-14": "High",
    "CA-15": "High",
    "CA-16": "High",
    "CA-17": "Medium",
    "CA-18": "Medium",
    "CA-19": "Medium",
    "CISA.MS.AAD.7.1": "High",
    "EM-01": "Medium",
    "EM-02": "Medium",
    "EM-03": "Medium",
    "EM-04": "Medium",
    "EM-05": "Medium",
    "HY-01": "Medium",
    "HY-02": "Medium",
    "HY-03": "High",
    "ID-01": "High",
    "ID-02": "Medium",
    "ID-03": "High",
    "ID-04": "Medium",
    "ID-05": "High",
    "ID-06": "Medium",
    "ID-07": "Medium",
    "ID-08": "Medium",
    "ID-09": "Low",
    "ID-10": "Medium",
    "ID-11": "High",
    "ID-12": "High",
    "ID-13": "Medium",
    "ID-14": "Medium",
    "ID-15": "Medium",
    "LG-01": "High",
    "PA-01": "High",
    "PA-02": "High",
    "PA-03": "High",
    "PA-04": "High",
    "PA-05": "High",
    "PA-06": "High",
    "PA-07": "High",
    "PA-08": "High",
    "PA-09": "High",
    "PA-10": "High",
    "PA-11": "High",
    "PA-12": "High",
    "PA-13": "High",
    "PA-14": "High",
    "PA-15": "High",
    "PA-16": "High",
    "SH-01": "High",
    "SH-02": "High",
    "SH-03": "Medium",
    "SH-04": "High",
    "SH-05": "High",
}

CONTROL_PLANE_ROLES = {
    "0526716b-113d-4c15-b2c8-68e3c22b9f80",
    "0b00bede-4072-4d22-b441-e7df02a1ef63",
    "0f971eea-41eb-4569-a71e-57bb8a3eff1e",
    "11451d60-acb2-45eb-a7d6-43d0f0125c13",
    "158c047a-c907-4556-b7ef-446551a6b5f7",
    "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "1981f584-96e9-4a6f-95b0-f522373f8fae",
    "1d336d2c-4ae8-42ef-9711-b3604ce3fc2c",
    "1fe13547-53f6-408d-ac04-7f8eed167b38",
    "25a516ed-2fa0-40ea-a2d0-12923a21473a",
    "2b499bcd-da44-4968-8aec-78e1674fa64d",
    "2ea5ce4c-b2d8-4668-bd81-3680bd2d227a",
    "32696413-001a-46ae-978c-ce0f6b3620d2",
    "3a2c62db-5318-420d-8d74-23affee5d9d5",
    "3edaf663-341e-4475-9f94-5c398ef6c070",
    "422218e4-db15-4ef9-bbe0-8afb41546d79",
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e",
    "4ba39ca4-527c-499a-b93d-d9b492c50246",
    "4d6ac14f-3453-41d0-bef9-a3e0c569773a",
    "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d",
    "58f930cc-fcf4-4152-852c-1d7dbf502139",
    "59d46f88-662b-457b-bceb-5c3809e5908f",
    "5b784334-f94b-471a-a387-e7219fc49ca2",
    "5d6b6bb7-de71-4623-b4af-96380a352509",
    "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",
    "62e90394-69f5-4237-9190-012177145e10",
    "6b942400-691f-4bf0-9d12-d8a254a2baf5",
    "6e591065-9bad-43ed-90f3-e9424366d2f0",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "744ec460-397e-42ad-a462-8b3f9747a02c",
    "7698a772-787b-4ac8-901f-60d6b08affd2",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
    "8329153b-31d0-4727-b945-745eb3bc5f31",
    "8424c6f0-a189-499e-bbd0-26c1753c96d4",
    "892c5842-a9a6-463a-8041-72aa08ca3cf6",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
    "92ed04bf-c94a-4b82-9729-b799a7a4c178",
    "9360feb5-f418-4baa-8175-e2a00bac4301",
    "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
    "9f06204d-73c1-4d4c-880a-6edb90606fd8",
    "a92aed5d-d78a-4d16-b381-09adb37eb3b0",
    "aaf43236-0c0d-4d5f-883a-6955382ac081",
    "ac434307-12b9-4fa1-a708-88bf58caabc1",
    "adb2368d-a9be-41b5-8667-d96778e081b0",
    "af78dc32-cf4d-46f9-ba4e-4428526346b5",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
    "b5a8dcf3-09d5-43a9-a639-8e29ef291470",
    "b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb",
    "b8e31d83-1534-480f-9b10-0338ded51b7e",
    "be2f45a1-457d-42af-a067-6ec1fa63bc45",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "d2562ede-74db-457e-a7b6-544e236ebb61",
    "d29b2b05-8046-44ba-8758-1e26182fcf32",
    "d35481f7-cda1-4fa2-8344-5a21f7f3724d",
    "db506228-d27e-4b7d-95e5-295956d6615f",
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
    "e6d1a23a-da11-4be4-9570-befc86d067a7",
    "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe",
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "f42252d9-5400-4d7b-b9ef-cc582dbb8577",
    "fc8ad4e2-40e4-4724-8317-bcda7503ecbf",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c",
    "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "ffd52fa5-98dc-465c-991d-fc073eb59f8f",
}

RISK_PERMISSIONS = [  # (permission id or name, name, type, attack path)
    ("2f6817f8-7b12-4f0f-bc18-eeaf60705a9e", "PrivilegedAccess.ReadWrite.AzureADGroup", "Application", "Direct"),
    ("32531c59-1f32-461f-b8df-6f8a3b89f73b", "PrivilegedAccess.ReadWrite.AzureADGroup", "Delegated", "Direct"),
    ("41202f2c-f7ab-45be-b001-85c9728b9d69", "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup", "Application", "Direct"),
    ("06dbc45d-6708-4ef0-a797-f797ee68bf4b", "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup", "Delegated", "Direct"),
    ("dd199f4a-f148-40a4-a2ec-f0069cc799ec", "RoleAssignmentSchedule.ReadWrite.Directory", "Application", "Direct"),
    ("8c026be3-8e26-4774-9372-8d5d6f21daff", "RoleAssignmentSchedule.ReadWrite.Directory", "Delegated", "Direct"),
    ("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", "RoleManagement.ReadWrite.Directory", "Application", "Direct"),
    ("d01b97e9-cbc0-49fe-810a-750afd5527a3", "RoleManagement.ReadWrite.Directory", "Delegated", "Direct"),
    ("eccc023d-eccf-4e7b-9683-8813ab36cecc", "User.DeleteRestore.All", "Application", "Direct"),
    ("4bb440cd-2cf2-4f90-8004-aa2acd2537c5", "User.DeleteRestore.All", "Delegated", "Direct"),
    ("3011c876-62b7-4ada-afa2-506cbbecc68c", "User.EnableDisableAccount.All", "Application", "Direct"),
    ("f92e74e7-2563-467f-9dd0-902688cb5863", "User.EnableDisableAccount.All", "Delegated", "Direct"),
    ("50483e42-d915-4231-9639-7fdb7fd190e5", "UserAuthenticationMethod.ReadWrite.All", "Application", "Direct"),
    ("b7887744-6746-4312-813d-72daeaee7e2d", "UserAuthenticationMethod.ReadWrite.All", "Delegated", "Direct"),
    ("5eb59dd3-1da2-4329-8733-9dabdc435916", "AdministrativeUnit.ReadWrite.All", "Application", "Indirect"),
    ("7b8a2d34-6b3f-4542-a343-54651608ad81", "AdministrativeUnit.ReadWrite.All", "Delegated", "Indirect"),
    ("1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", "Application.ReadWrite.All", "Application", "Indirect"),
    ("bdfbf15f-ee85-4955-8675-146e8e5296b5", "Application.ReadWrite.All", "Delegated", "Indirect"),
    ("18a4783c-866b-4cc7-a460-3d5e5662c884", "Application.ReadWrite.OwnedBy", "Application", "Indirect"),
    ("06b708a9-e830-4db3-a914-8e69da51d44f", "AppRoleAssignment.ReadWrite.All", "Application", "Indirect"),
    ("84bccea3-f856-4a8a-967b-dbe0a3d53a64", "AppRoleAssignment.ReadWrite.All", "Delegated", "Indirect"),
    ("9241abd9-d0e6-425a-bd4f-47ba86e767a4", "DeviceManagementConfiguration.ReadWrite.All", "Application", "Indirect"),
    ("0883f392-0a7a-443d-8c76-16a6d39c7b63", "DeviceManagementConfiguration.ReadWrite.All", "Delegated", "Indirect"),
    ("e330c4f0-4170-414e-a55a-2f022ec2b57b", "DeviceManagementRBAC.ReadWrite.All", "Application", "Indirect"),
    ("0c5e8a55-87a6-4556-93ab-adc52c4d862d", "DeviceManagementRBAC.ReadWrite.All", "Delegated", "Indirect"),
    ("19dbc75e-c2e2-444c-a770-ec69d8559fc7", "Directory.ReadWrite.All", "Application", "Indirect"),
    ("c5366453-9fb0-48a5-a156-24f0c49a4b84", "Directory.ReadWrite.All", "Delegated", "Indirect"),
    ("9acd699f-1e81-4958-b001-93b1d2506e19", "EntitlementManagement.ReadWrite.All", "Application", "Indirect"),
    ("ae7a573d-81d7-432b-ad44-4ed5c9d89038", "EntitlementManagement.ReadWrite.All", "Delegated", "Indirect"),
    ("62a82d76-70ea-41e2-9197-370581804d09", "Group.ReadWrite.All", "Application", "Indirect"),
    ("4e46008b-f24c-477d-8fff-7bb4ec7aafe0", "Group.ReadWrite.All", "Delegated", "Indirect"),
    ("dbaae8cf-10b5-4b86-a4a1-f871c94c6695", "GroupMember.ReadWrite.All", "Application", "Indirect"),
    ("f81125ac-d3b7-4573-a3b2-7099cc39df9e", "GroupMember.ReadWrite.All", "Delegated", "Indirect"),
    ("29c18626-4985-4dcd-85c0-193eef327366", "Policy.ReadWrite.AuthenticationMethod", "Application", "Indirect"),
    ("7e823077-d88e-468f-a337-e18f1f0e6c7c", "Policy.ReadWrite.AuthenticationMethod", "Delegated", "Indirect"),
    ("a402ca1c-2696-4531-972d-6e5ee4aa11ea", "Policy.ReadWrite.PermissionGrant", "Application", "Indirect"),
    ("2672f8bb-fd5e-42e0-85e1-ec764dd2614e", "Policy.ReadWrite.PermissionGrant", "Delegated", "Indirect"),
    ("618b6020-bca8-4de6-99f6-ef445fa4d857", "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup", "Application", "Indirect"),
    ("ba974594-d163-484e-ba39-c330d5897667", "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup", "Delegated", "Indirect"),
    ("fee28b28-e1f3-4841-818e-2704dc62245f", "RoleEligibilitySchedule.ReadWrite.Directory", "Application", "Indirect"),
    ("62ade113-f8e0-4bf9-a6ba-5acb31db32fd", "RoleEligibilitySchedule.ReadWrite.Directory", "Delegated", "Indirect"),
    ("b38dcc4d-a239-4ed6-aa84-6c65b284f97c", "RoleManagementPolicy.ReadWrite.AzureADGroup", "Application", "Indirect"),
    ("0da165c7-3f15-4236-b733-c0b0f6abe41d", "RoleManagementPolicy.ReadWrite.AzureADGroup", "Delegated", "Indirect"),
    ("31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad", "RoleManagementPolicy.ReadWrite.Directory", "Application", "Indirect"),
    ("1ff1be21-34eb-448c-9ac9-ce1f506b2a68", "RoleManagementPolicy.ReadWrite.Directory", "Delegated", "Indirect"),
    ("741f803b-c850-494e-b5df-cde7c675a1ca", "User.ReadWrite.All", "Application", "Indirect"),
    ("204e0828-b5ca-4ad8-b9f3-f32a958e7cc4", "User.ReadWrite.All", "Delegated", "Indirect"),
    ("9241abd9-d0e6-425a-bd4f-47ba86e767a4", "DeviceManagementConfiguration.ReadWrite.All", "Application", "Indirect"),
    ("0883f392-0a7a-443d-8c76-16a6d39c7b63", "DeviceManagementConfiguration.ReadWrite.All", "Delegated", "Indirect"),
    ("e330c4f0-4170-414e-a55a-2f022ec2b57b", "DeviceManagementRBAC.ReadWrite.All", "Application", "Indirect"),
    ("0c5e8a55-87a6-4556-93ab-adc52c4d862d", "DeviceManagementRBAC.ReadWrite.All", "Delegated", "Indirect"),
    ("7e05723c-0bb0-42da-be95-ae9f08a6e53c", "Domain.ReadWrite.All", "Application", "Indirect"),
    ("0b5d694c-a244-4bde-86e6-eb5cd07730fe", "Domain.ReadWrite.All", "Delegated", "Indirect"),
    ("292d869f-3427-49a8-9dab-8c70152b74e9", "Organization.ReadWrite.All", "Application", "Indirect"),
    ("46ca0847-7e6b-426e-9775-ea810a948356", "Organization.ReadWrite.All", "Delegated", "Indirect"),
    ("01c0a623-fc9b-48e9-b794-0756f8e8f067", "Policy.ReadWrite.ConditionalAccess", "Application", "Direct"),
    ("ad902697-1014-4ef5-81ef-2b4301988e8c", "Policy.ReadWrite.ConditionalAccess", "Delegated", "Direct"),
]

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
ADMIN_ROLES = [
    "62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "29232cdf-9323-42fd-ade2-1d097af3e4de", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", "fe930be7-5e62-47db-91af-98c3a49a38b1", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "158c047a-c907-4556-b7ef-446551a6b5f7", "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "e8611ab8-c189-46e8-94e1-60213ab1f814",
]
HIGHLY_PRIVILEGED = [
    "62e90394-69f5-4237-9190-012177145e10", "fe930be7-5e62-47db-91af-98c3a49a38b1", "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "158c047a-c907-4556-b7ef-446551a6b5f7", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
]
PHISH_RESISTANT_STRENGTH = "00000000-0000-0000-0000-000000000004"
MICROSOFT_TENANTS = {"72f988bf-86f1-41af-91ab-2d7cd011db47", "f8cdef31-a31e-4b4a-93e4-5f571e91255a"}
WATCHED_FIRST_PARTY = {
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI / Azure Developer CLI",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph Command Line Tools",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell (legacy)",
    "12128f48-ec9e-42f0-b203-ea49fb6af367": "Microsoft Teams PowerShell Cmdlets",
    "fb78d390-0c51-40cd-8e17-fdbfab77341b": "Microsoft Exchange Online PowerShell",
    "9bc3ab49-b65d-410a-85ad-de819febfddc": "Microsoft SharePoint Online Management Shell",
    "9cee029c-6210-4654-90bb-17e6e9d36617": "Power Platform CLI",
}
CIS_LOG_CATEGORIES = [
    "AuditLogs", "SignInLogs", "RiskyUsers", "UserRiskEvents", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs",
    "ADFSSignInLogs", "RiskyServicePrincipals", "ServicePrincipalRiskEvents", "EnrichedOffice365AuditLogs",
    "MicrosoftGraphActivityLogs", "ManagedIdentitySignInLogs",
]

FW_CA = "Conditional Access"
FW_SH = "Jolera Extended Controls"
FW_APP = "Applications & permissions"
FW_ID = "Identity settings"
FW_PA = "Privileged access"
FW_EM = "Entitlement management"
FW_REC = "Entra recommendations"
FW_LOG = "Logging"
FW_CISA = "CISA SCuBA"


# ------------------------------------------------------------------------------ small helpers with PowerShell semantics
def lc(x: Any) -> Any:
    return x.lower() if isinstance(x, str) else x


def as_list(x: Any) -> list:
    if x is None:
        return []
    return list(x) if isinstance(x, list) else [x]


def has(x: Any, value: Any) -> bool:
    """PowerShell -contains / -eq against a value or an array (case-insensitive for strings)."""
    return any(lc(i) == lc(value) for i in as_list(x))


def dget(d: dict, key: str) -> Any:
    if key in d:
        return d[key]
    lk = key.lower()
    for k, v in d.items():
        if k.lower() == lk:
            return v
    return None


def g(obj: Any, *keys: str) -> Any:
    """Safe nested lookup. Like PowerShell member access, it runs over the items of a list."""
    cur = obj
    for k in keys:
        if cur is None:
            return None
        if isinstance(cur, list):
            vals: list = []
            for it in cur:
                v = g(it, k)
                if isinstance(v, list):
                    vals.extend(v)
                elif v is not None:
                    vals.append(v)
            cur = vals
        elif isinstance(cur, dict):
            cur = dget(cur, k)
        else:
            return None
    return cur


def to_str(v: Any) -> str:
    """[string]$value in PowerShell: bool -> True/False, null -> empty, list -> space separated."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, list):
        return " ".join(to_str(i) for i in v)
    return str(v)


def parse_dt(value: Any) -> dt.datetime | None:
    if not value:
        return None
    s = str(value).replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def names(items: list, key: str = "displayName") -> list[str]:
    return [str(g(i, key)) for i in items]


def html_to_md(text: Any) -> str:
    """Entra recommendation texts contain a little HTML (<br>, <a href>); turn it into plain markdown."""
    if not text:
        return ""
    t = str(text).replace("<br />", "\n").replace("<br/>", "\n").replace("<br>", "\n")
    t = re.sub(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", lambda m: f"[{m.group(2)}]({m.group(1).replace(chr(92) + 'l', '#')})", t, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", "", t)
    return html.unescape(t).strip()


def rec_details(rec: dict) -> dict:
    """Test details of an Entra recommendation, taken from the recommendation itself."""
    steps = sorted([x for x in as_list(rec.get("actionSteps")) if isinstance(x, dict)], key=lambda x: x.get("stepNumber") or 0)
    lines = []
    for i, step in enumerate(steps, 1):
        text = html_to_md(step.get("text"))
        action = step.get("actionUrl") or {}
        url = str(action.get("url") or "").replace("\\l", "#")
        if url:
            text += f" [{action.get('displayName') or url}]({url})"
        lines.append(f"{i}. {text}")
    portal = f"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RecommendationDetails.ReactView/recommendationId/{rec.get('id')}"
    return {"description": html_to_md(rec.get("benefits")), "remediation": "\n".join(lines),
            "impact": html_to_md(rec.get("remediationImpact")),
            "links": [{"text": f"{rec.get('displayName')} - Microsoft Entra admin center", "url": portal}]}


def join_findings(items: list[str], limit: int = 40) -> str:
    f = [i for i in items if i]
    if len(f) > limit:
        return "; ".join(f[:limit]) + f"; ... +{len(f) - limit} more"
    return "; ".join(f)


# ------------------------------------------------------------------------------ engine
class Engine:
    def __init__(self, run_dir: Path, emergency_ids: list[str]):
        self.run_dir = run_dir
        self.emergency = list(emergency_ids)
        self.results: list[dict] = []
        self.details: dict[str, dict] = {}
        details_file = paths.DATA_DIR / "rule_details.json"
        if details_file.exists():
            self.details = json.loads(details_file.read_text(encoding="utf-8"))

        def _json(path: Path) -> dict:
            try:
                return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            except (OSError, ValueError):
                return {}
        self.severity_overrides = _json(paths.CONFIG_DIR / "severity_overrides.json")      # {rule_id: "Critical"}: reviewed ratings
        nist = _json(paths.SPECS_DIR / "nist_map.json")
        self.nist_map, self.nist_default_rec = nist.get("rules", {}), nist.get("rec_default", "")
        self.required_licence = _json(paths.SPECS_DIR / "required_licence.json")
        self.reference_map = _json(paths.SPECS_DIR / "reference_map.json")      # {rule_id: [extra benchmark references]}
        self.data: dict[str, list] = {}
        self.status: dict[str, str] = {}
        self.manifest: dict = {}
        self._load()
        for x in self.manifest.get("emergency_access_ids", []):  # break-glass ids kept per company in companies.json
            if x not in self.emergency:
                self.emergency.append(x)
        self.now = dt.datetime.now(dt.timezone.utc)
        self.plan = self._plan()

    def _load(self) -> None:
        mf = self.run_dir / "manifest.json"
        if mf.exists():
            self.manifest = json.loads(mf.read_text(encoding="utf-8"))
            for e in self.manifest.get("datasets", []):
                self.status[e["dataset"]] = e["status"]
        for f in sorted((self.run_dir / "raw").glob("*.json")):
            self.data[f.stem] = json.loads(f.read_text(encoding="utf-8"))
            self.status.setdefault(f.stem, "OK")

    def ds(self, name: str) -> list | None:
        """None = not collected (failed / missing); [] = collected but empty."""
        if name in self.data:
            return self.data[name]
        if self.status.get(name) == "OK":
            return []
        return None

    def first(self, name: str) -> dict | None:
        rows = self.ds(name)
        return rows[0] if rows else None

    def _plan(self) -> str:
        skus = self.ds("SubscribedSkus")
        if skus is None:
            return "Unknown"
        plans = {sp.get("servicePlanName") for sku in skus for sp in as_list(sku.get("servicePlans"))
                 if sp.get("provisioningStatus") == "Success"}
        if "AAD_PREMIUM_P2" in plans:
            return "P2"
        if "AAD_PREMIUM" in plans:
            return "P1"
        return "Free"

    def details_for(self, ref: str) -> dict | None:
        for token in re.split(r"\s*/\s*", ref):
            d = self.details.get(token.strip())
            if d:
                return {k: d[k] for k in ("description", "remediation", "impact", "links") if d.get(k)}
        return None

    def add(self, rid: str, ref: str, fw: str, title: str, status: str, expected: str, actual: str = "",
            reason: str = "", dataset: str = "", severity: str | None = None, affected: list | None = None,
            details: dict | None = None, *, area: str = "Entra ID", nist: str = "", required_licence: str = "",
            kind: str | None = None, origin: str = "") -> None:
        names_ = [str(a.get("displayName") or a.get("id")) if isinstance(a, dict) else str(a) for a in (affected or []) if a is not None]
        self.results.append({
            "rule_id": rid, "reference_id": ref, "framework": fw, "title": title,
            "severity": self.severity_overrides.get(rid) or severity or SEVERITY.get(rid, "Medium"), "status": status, "expected": expected,
            "area": area, "nist": nist or self.nist_map.get(rid) or (self.nist_default_rec if rid.startswith("REC-") else ""),
            "outcome": self._outcome(status, kind, reason), "required_licence": required_licence or self.required_licence.get(rid, ""),
            "references": [r for r in dict.fromkeys([ref] + self.reference_map.get(rid, [])) if r], "origin": origin,
            "actual": str(actual), "reason": reason, "dataset": dataset,
            "affected_count": len(names_), "affected": names_[:500],
            "details": details if details is not None else self.details_for(ref),
        })

    @staticmethod
    def _outcome(status: str, kind: str | None, reason: str) -> str:
        """Pass / Fail / Not Assessable (licence, missing data or permission) / Not Applicable (feature or workload not used)."""
        if status == "Passed":
            return "Pass"
        if status == "Failed":
            return "Fail"
        if kind in ("licensing", "data"):
            return "Not Assessable"
        if kind == "not_applicable" or str(reason).lower().startswith("no "):
            return "Not Applicable"
        return "Not Assessable"

    # one check: fn returns {"pass": bool, "actual": str} or {"skip": reason}
    def run(self, rid: str, ref: str, fw: str, title: str, expected: str, fn: Callable[[], dict], *, needs: tuple = (),
            min_plan: str = "Any", meta: dict | None = None) -> None:
        meta = meta or {}
        dataset = ", ".join(needs)
        for n in needs:
            if self.ds(n) is None:
                why = next((d.get("error") for d in self.manifest.get("datasets", []) if d.get("dataset") == n and d.get("error")), "")
                return self.add(rid, ref, fw, title, "Skipped", expected, reason=f"Data set '{n}' was not collected" + (f" ({why})" if why else ""),
                                dataset=dataset, kind="data", **meta)
        if min_plan == "P1" and self.plan == "Free":
            return self.add(rid, ref, fw, title, "Skipped", expected, reason="Requires Entra ID P1 or higher", dataset=dataset, kind="licensing", **meta)
        if min_plan == "P2" and self.plan in ("Free", "P1"):
            return self.add(rid, ref, fw, title, "Skipped", expected, reason="Requires Entra ID P2 (or Entra ID Governance)", dataset=dataset, kind="licensing", **meta)
        try:
            r = fn()
        except Exception as exc:  # noqa: BLE001 - a broken check must not stop the run
            return self.add(rid, ref, fw, title, "Skipped", expected, reason=f"Check could not run: {exc}", dataset=dataset, kind="data", **meta)
        if r.get("skip"):
            return self.add(rid, ref, fw, title, "Skipped", expected, reason=r["skip"], dataset=dataset, kind=r.get("kind"), **meta)
        self.add(rid, ref, fw, title, "Passed" if r["pass"] else "Failed", expected, r.get("actual", ""), dataset=dataset,
                 affected=None if r["pass"] else r.get("affected"), **meta)


# ------------------------------------------------------------------------------ EIDSCA
def eidsca_value(rule: dict, obj: Any, rows: list) -> str:
    kind, arg = rule["value"]
    if kind == "path":
        return to_str(g(obj, *arg.split(".")))
    if kind == "setting":
        vals = [v for s in rows for v in as_list(s.get("values")) if isinstance(v, dict)]
        return to_str([v.get("value") for v in vals if lc(v.get("name")) == lc(arg)])
    if arg == "af05":
        guids = g(obj, "keyRestrictions", "aaGuids")
        return to_str(False if guids is None else None not in as_list(guids))
    if arg == "af06":
        guids = g(obj, "keyRestrictions", "aaGuids")
        ok = guids is not None and None not in as_list(guids) and g(obj, "keyRestrictions", "enforcementType") in ("allow", "block")
        return to_str(ok)
    if arg == "ap08":
        ids = [i for i in as_list(g(obj, "permissionGrantPolicyIdsAssignedToDefaultUserRole")) if str(i).startswith("ManagePermissionGrantsForSelf")]
        return to_str(ids)
    if arg == "as04":
        seen: list = []
        for v in as_list(g(obj, "includeTargets", "isUsableForSignIn")):
            if v not in seen:
                seen.append(v)
        return to_str(seen)
    raise ValueError(f"unknown value rule {rule['id']}")


def eidsca_test(test: tuple, value: str) -> bool:
    op, arg = test
    if op == "eq":
        return lc(value) == lc(arg)
    if op == "in":
        return lc(value) in [lc(a) for a in arg]
    if value == "":
        return False
    try:
        number = float(value)
    except ValueError:
        return False
    return number <= arg if op == "le" else number >= arg


def run_eidsca(e: Engine) -> None:
    outcome: dict[str, str] = {}
    for r in EIDSCA_RULES:
        rid = f"EIDSCA.{r['id']}"
        expected = "value " + r["test_text"]
        rows = e.ds(r["sheet"])
        skip = None
        obj: Any = None
        if rows is None:
            skip = f"Data set '{r['sheet']}' was not collected"
        else:
            if r["mode"] == "all":
                obj = rows
            elif r["mode"] == "filter":
                obj = next((x for x in rows if x.get("id") == r["filter"]), None)
            else:
                obj = rows[0] if rows else None
            for pre in r["pre"]:
                kind, _, arg = pre.partition(":")
                if kind == "authmethod":
                    cfg = next((x for x in (e.ds("AuthMethodConfigs") or []) if x.get("id") == arg), None)
                    if (cfg or {}).get("state") != "enabled":
                        skip = f"Authentication method {arg} is not enabled"
                elif kind == "dep":
                    if outcome.get(f"EIDSCA.{arg}") != "Passed":
                        skip = f"Depends on EIDSCA.{arg} which did not pass"
                elif kind == "plan":
                    if e.plan == "Free":
                        skip = "Requires Entra ID P1 or higher"
                elif kind == "adminconsent":
                    p = (e.ds("AdminConsentPolicy") or [{}])[0] if e.ds("AdminConsentPolicy") else {}
                    if p.get("isEnabled") is False:
                        skip = "Admin consent workflow is not enabled"
                elif kind == "setting":
                    setting_names = [lc(v.get("name")) for s in rows for v in as_list(s.get("values")) if isinstance(v, dict)]
                    if lc(arg) not in setting_names:
                        skip = f"Directory setting {arg} is not present"
                elif kind == "prop":
                    if isinstance(obj, dict) and arg not in obj:
                        skip = f"Property {arg} not returned by this tenant"
                elif kind == "ap08":
                    ids = as_list(g(obj, "permissionGrantPolicyIdsAssignedToDefaultUserRole"))
                    if not any(re.search(r"ManagePermissionGrantsForSelf.microsoft-", str(i), re.I) for i in ids):
                        skip = "No user consent policy assigned"
                if skip:
                    break
        if skip:
            outcome[rid] = "Skipped"
            e.add(rid, rid, "EIDSCA", r["title"], "Skipped", expected, reason=skip, dataset=r["sheet"], severity=r["severity"])
            continue
        value = eidsca_value(r, obj, rows)
        passed = eidsca_test(r["test"], value)
        outcome[rid] = "Passed" if passed else "Failed"
        e.add(rid, rid, "EIDSCA", r["title"], outcome[rid], expected, value if value != "" else "(not configured explicitly)",
              dataset=r["sheet"], severity=r["severity"])


# ------------------------------------------------------------------------------ Conditional Access
def requires_mfa(p: dict) -> bool:
    return has(g(p, "grantControls", "builtInControls"), "mfa") or has(g(p, "grantControls", "authenticationStrength", "requirementsSatisfied"), "mfa")


def non_corp_device_filter(p: dict) -> bool:
    f = g(p, "conditions", "devices", "deviceFilter") or {}
    mode, rule = lc(f.get("mode")), f.get("rule") or ""
    return (mode == "include" and bool(re.search(r"device.isCompliant -ne True", rule, re.I))) or \
           (mode == "exclude" and bool(re.search(r"device.isCompliant -eq True", rule, re.I)))


def all_users_all_apps(p: dict) -> bool:
    return has(g(p, "conditions", "users", "includeUsers"), "All") and has(g(p, "conditions", "applications", "includeApplications"), "All")


def run_ca(e: Engine) -> None:
    ca_all = e.ds("CA_Policies")
    enabled = [p for p in (ca_all or []) if p.get("state") == "enabled"]
    no_risk = [p for p in enabled
               if not has(g(p, "grantControls", "builtInControls"), "passwordChange")
               and not has(g(p, "grantControls", "builtInControls"), "riskRemediation")
               and not g(p, "conditions", "userRiskLevels") and not g(p, "conditions", "signInRiskLevels")]

    def ca_rule(rid, ref, title, expected, match, *, fw=FW_CA, min_plan="P1", risk_free=False):
        def fn():
            pool = no_risk if risk_free else enabled
            hits = [p for p in pool if match(p)]
            if hits:
                return {"pass": True, "actual": "Matching policies: " + join_findings(names(hits))}
            return {"pass": False, "actual": "No enabled policy matches"}
        e.run(rid, ref, fw, title, expected, fn, needs=("CA_Policies",), min_plan=min_plan)

    bic = lambda p: g(p, "grantControls", "builtInControls")  # noqa: E731
    cond = lambda p, *k: g(p, "conditions", *k)  # noqa: E731
    sess = lambda p, *k: g(p, "sessionControls", *k)  # noqa: E731

    ca_rule("CA-01", "MT.1001", "A Conditional Access policy requires device compliance",
            "Enabled policy with grant control compliantDevice", lambda p: has(bic(p), "compliantDevice"))
    ca_rule("CA-03", "MT.1006", "A Conditional Access policy requires MFA for admins",
            "Enabled policy: MFA, all apps, all privileged admin roles included",
            lambda p: requires_mfa(p) and has(cond(p, "applications", "includeApplications"), "All")
            and all(has(cond(p, "users", "includeRoles"), r) for r in ADMIN_ROLES), risk_free=True)
    ca_rule("CA-04", "MT.1007", "A Conditional Access policy requires MFA for all users",
            "Enabled policy: MFA, all users, all apps", lambda p: requires_mfa(p) and all_users_all_apps(p), risk_free=True)
    ca_rule("CA-05", "MT.1009", "A Conditional Access policy blocks other legacy authentication",
            "Enabled policy: block, client app type other, all users, all apps",
            lambda p: has(bic(p), "block") and has(p.get("conditions", {}).get("clientAppTypes"), "other") and all_users_all_apps(p))
    ca_rule("CA-06", "MT.1010", "A Conditional Access policy blocks Exchange ActiveSync legacy authentication",
            "Enabled policy: block, client app type exchangeActiveSync, all users, all apps",
            lambda p: has(bic(p), "block") and has(p.get("conditions", {}).get("clientAppTypes"), "exchangeActiveSync") and all_users_all_apps(p))
    ca_rule("CA-07", "MT.1012", "A Conditional Access policy requires MFA for risky sign-ins",
            "Enabled policy: MFA, all users, all apps, sign-in risk medium and high",
            lambda p: requires_mfa(p) and not has(bic(p), "passwordChange") and all_users_all_apps(p)
            and has(cond(p, "signInRiskLevels"), "high") and has(cond(p, "signInRiskLevels"), "medium"), min_plan="P2")
    ca_rule("CA-08", "MT.1015", "A Conditional Access policy blocks unknown or unsupported device platforms",
            "Enabled policy: block, platforms All",
            lambda p: has(bic(p), "block") and has(cond(p, "platforms", "includePlatforms"), "All"))
    ca_rule("CA-09", "MT.1016", "A Conditional Access policy requires MFA for guest access",
            "Enabled policy: MFA, all apps, applies to guests or all users, guests not excluded",
            lambda p: requires_mfa(p) and has(cond(p, "applications", "includeApplications"), "All")
            and not cond(p, "users", "excludeGuestsOrExternalUsers")
            and (has(cond(p, "users", "includeUsers"), "GuestsOrExternalUsers") or has(cond(p, "users", "includeUsers"), "All")
                 or bool(cond(p, "users", "includeGuestsOrExternalUsers"))), risk_free=True)
    ca_rule("CA-10", "MT.1017", "A Conditional Access policy enforces non-persistent browser sessions on non-corporate devices",
            "Enabled policy: persistent browser mode never, all users, all apps, non-compliant device filter",
            lambda p: sess(p, "persistentBrowser", "isEnabled") is True and lc(sess(p, "persistentBrowser", "mode")) == "never"
            and non_corp_device_filter(p) and all_users_all_apps(p))
    ca_rule("CA-11", "MT.1018", "A Conditional Access policy enforces sign-in frequency on non-corporate devices",
            "Enabled policy: time-based sign-in frequency, all users, all apps, non-compliant device filter",
            lambda p: sess(p, "signInFrequency", "isEnabled") is True and lc(sess(p, "signInFrequency", "frequencyInterval")) == "timebased"
            and non_corp_device_filter(p) and all_users_all_apps(p))

    # CA-02: every enabled policy excludes at least one emergency-access object
    title = "All Conditional Access policies exclude an emergency (break-glass) account or group"
    exp = "Each enabled policy excludes a break-glass user or group"
    if ca_all is None:
        e.add("CA-02", "MT.1005", FW_CA, title, "Skipped", exp, reason="Data set 'CA_Policies' was not collected", dataset="CA_Policies")
    elif not e.emergency:
        e.add("CA-02", "MT.1005", FW_CA, title, "Skipped", exp, reason="Pass --emergency-access-ids to run this check", dataset="CA_Policies")
    else:
        missing = [p for p in enabled
                   if not any(i in (as_list(cond(p, "users", "excludeUsers")) + as_list(cond(p, "users", "excludeGroups"))) for i in e.emergency)]
        if missing:
            e.add("CA-02", "MT.1005", FW_CA, title, "Failed", exp, "Policies without an exclusion: " + join_findings(names(missing)), dataset="CA_Policies",
                  affected=names(missing))
        else:
            e.add("CA-02", "MT.1005", FW_CA, title, "Passed", exp, f"All {len(enabled)} enabled policies exclude one", dataset="CA_Policies")

    # more Conditional Access checks
    def ca12():
        n = sum(1 for p in enabled if has(cond(p, "applications", "includeUserActions"), "urn:user:registerdevice"))
        required = (e.first("DeviceRegPolicy") or {}).get("multiFactorAuthConfiguration") == "required"
        return {"pass": not (required and n > 0), "actual": f"Device registration MFA required = {required}; register-device policies = {n}"}
    e.run("CA-12", "MT.1061", FW_CA, "Device registration MFA setting does not conflict with Conditional Access",
          "If the device registration policy requires MFA, no policy targets the register-device user action", ca12,
          needs=("CA_Policies", "DeviceRegPolicy"))

    def ca13():
        trusted = [x.get("id") for x in (e.ds("CA_NamedLocations") or [])
                   if x.get("@odata.type") == "#microsoft.graph.ipNamedLocation" and x.get("isTrusted") is True]
        hits = []
        for p in enabled:
            if has(bic(p), "passwordChange"):
                continue
            ex = [x for x in as_list(cond(p, "locations", "excludeLocations")) if x]
            ex_trusted = has(ex, "AllTrusted") or any(x in trusted for x in ex)
            if (has(cond(p, "users", "includeUsers"), "All") and has(p.get("conditions", {}).get("clientAppTypes"), "all")
                    and has(cond(p, "applications", "includeUserActions"), "urn:user:registersecurityinfo")
                    and has(cond(p, "locations", "includeLocations"), "All") and ex_trusted):
                hits.append(p)
        return {"pass": bool(hits), "actual": ("Matching policies: " + join_findings(names(hits))) if hits else "No matching policy"}
    e.run("CA-13", "MT.1011", FW_CA, "A Conditional Access policy restricts security info registration to trusted locations",
          "Enabled policy: all users, all client apps, user action registersecurityinfo, all locations, a trusted location excluded",
          ca13, needs=("CA_Policies",), min_plan="P1")

    def ca14():
        hits = [p for p in enabled if has(bic(p), "passwordChange") and all_users_all_apps(p) and has(cond(p, "userRiskLevels"), "high")]
        return {"pass": bool(hits), "actual": ("Matching policies: " + join_findings(names(hits))) if hits else "No matching policy"}
    e.run("CA-14", "MT.1013", FW_CA, "A Conditional Access policy requires a password change for high user risk",
          "Enabled policy: passwordChange grant, all users, all apps, user risk high", ca14, needs=("CA_Policies",), min_plan="P2")

    def ca15():
        hits = []
        for p in enabled:
            flows = to_str(cond(p, "authenticationFlows", "transferMethods"))
            if not re.search("deviceCodeFlow", flows, re.I):
                continue
            locs = cond(p, "locations")
            block_all_locations = has(bic(p), "block") and (not locs or has(cond(p, "locations", "includeLocations"), "All"))
            if (has(cond(p, "users", "includeUsers"), "All") and has(p.get("conditions", {}).get("clientAppTypes"), "all")
                    and (block_all_locations or has(bic(p), "compliantDevice") or has(bic(p), "domainJoinedDevice"))):
                hits.append(p)
        return {"pass": bool(hits), "actual": ("Matching policies: " + join_findings(names(hits))) if hits else "No policy sufficiently covers the device code flow"}
    e.run("CA-15", "MT.1052", FW_CA, "A Conditional Access policy covers the device code authentication flow",
          "Enabled policy targeting deviceCodeFlow for all users and all client apps that blocks (all locations) or requires a managed device",
          ca15, needs=("CA_Policies",))

    def ca16():
        if not [p for p in enabled if cond(p, "userRiskLevels") or cond(p, "signInRiskLevels")]:
            return {"skip": "No risk-based Conditional Access policy exists"}
        bad = [p for p in enabled if cond(p, "userRiskLevels") and cond(p, "signInRiskLevels")]
        return {"pass": not bad, "affected": bad, "actual": ("Combined risk policies: " + join_findings(names(bad))) if bad else "No policy combines both risk types"}
    e.run("CA-16", "MT.1049", FW_CA, "User risk and sign-in risk are configured in separate Conditional Access policies",
          "No enabled policy combines user risk and sign-in risk levels", ca16, needs=("CA_Policies",), min_plan="P2")

    def ca17():
        dims = [
            ("users", ("users", "includeUsers"), ("users", "excludeUsers")),
            ("groups", ("users", "includeGroups"), ("users", "excludeGroups")),
            ("roles", ("users", "includeRoles"), ("users", "excludeRoles")),
            ("applications", ("applications", "includeApplications"), ("applications", "excludeApplications")),
            ("service principals", ("clientApplications", "includeServicePrincipals"), ("clientApplications", "excludeServicePrincipals")),
            ("locations", ("locations", "includeLocations"), ("locations", "excludeLocations")),
            ("platforms", ("platforms", "includePlatforms"), ("platforms", "excludePlatforms")),
        ]
        gaps = []
        for label, inc_path, exc_path in dims:
            inc = {lc(x) for p in enabled for x in as_list(cond(p, *inc_path)) if x}
            exc = []
            for p in enabled:
                for x in as_list(cond(p, *exc_path)):
                    if x and x not in exc:
                        exc.append(x)
            missing = [x for x in exc if lc(x) not in inc]
            if missing:
                gaps.append(f"{label}: {', '.join(missing)}")
        return {"pass": not gaps, "affected": gaps, "actual": ("Excluded without fallback - " + join_findings(gaps, 20)) if gaps else "All exclusions have a fallback include"}
    e.run("CA-17", "MT.1036", FW_CA, "Every excluded object has a fallback include in another policy",
          "Each excluded user, group, role, app, location or platform is explicitly included by some enabled policy", ca17, needs=("CA_Policies",))

    def ca18():
        exist = {x.get("id") for x in e.ds("Groups") or []}
        hit = [f"{p.get('displayName')}: {gid}" for p in ca_all or []
               for gid in as_list(cond(p, "users", "includeGroups")) + as_list(cond(p, "users", "excludeGroups")) if gid and gid not in exist]
        return {"pass": not hit, "affected": hit, "actual": ("Missing groups - " + join_findings(hit)) if hit else "All referenced groups exist"}
    e.run("CA-18", "MT.1038", FW_CA, "Conditional Access policies do not include or exclude deleted groups",
          "Every group referenced by a policy exists", ca18, needs=("CA_Policies", "Groups"))

    def ca19():
        users = {x.get("id") for x in e.ds("Users") or []}
        groups = {x.get("id") for x in e.ds("Groups") or []}
        roles = {x.get("id") for x in e.ds("RoleDefinitions") or []}
        hit = []
        for p in ca_all or []:
            name = p.get("displayName")
            for i in as_list(cond(p, "users", "includeUsers")) + as_list(cond(p, "users", "excludeUsers")):
                if i and i not in ("All", "GuestsOrExternalUsers", "None") and i not in users:
                    hit.append(f"{name}: user {i}")
            for i in as_list(cond(p, "users", "includeGroups")) + as_list(cond(p, "users", "excludeGroups")):
                if i and i not in groups:
                    hit.append(f"{name}: group {i}")
            for i in as_list(cond(p, "users", "includeRoles")) + as_list(cond(p, "users", "excludeRoles")):
                if i and i not in roles:
                    hit.append(f"{name}: role {i}")
        return {"pass": not hit, "affected": hit, "actual": ("Missing objects - " + join_findings(hit)) if hit else "All referenced objects exist"}
    e.run("CA-19", "MT.1066", FW_CA, "Conditional Access policies do not reference non-existent users, groups or roles",
          "Every user, group and role referenced by a policy exists", ca19, needs=("CA_Policies", "Users", "Groups", "RoleDefinitions"))

    # Global Administrator count (CISA SCuBA MS.AAD.7.1)
    def ga_count():
        gas = {a.get("principalId") for a in e.ds("RoleAssignments") or []
               if a.get("roleDefinitionId") == GLOBAL_ADMIN and (a.get("principal") or {}).get("@odata.type") == "#microsoft.graph.user"}
        ok = 2 <= len(gas) <= 8
        return {"pass": ok, "actual": f"{len(gas)} users (direct assignments only; group-based assignments are not expanded)"}
    e.run("CISA.MS.AAD.7.1", "CISA.MS.AAD.7.1", FW_CISA, "Between 2 and 8 users hold the Global Administrator role",
          "2 to 8 Global Administrator users", ga_count, needs=("RoleAssignments",))

    # Session-hijack protection (custom)
    ca_rule("SH-01", "CUS.SH.001", "A Conditional Access policy enforces Token Protection for sign-in sessions",
            "Enabled policy with secureSignInSession enabled", lambda p: sess(p, "secureSignInSession", "isEnabled") is True, fw=FW_SH)
    ca_rule("SH-02", "CUS.SH.002", "A Conditional Access policy strictly enforces location policies (CAE)",
            "Enabled policy with CAE mode strictEnforcement/strictLocation",
            lambda p: lc(sess(p, "continuousAccessEvaluation", "mode")) in ("strictenforcement", "strictlocation"), fw=FW_SH)

    def sh03():
        off = [p for p in enabled if lc(sess(p, "continuousAccessEvaluation", "mode")) == "disabled"]
        return {"pass": not off, "affected": off, "actual": ("Disabling policies: " + join_findings(names(off))) if off else "None disable CAE"}
    e.run("SH-03", "CUS.SH.003", FW_SH, "Continuous Access Evaluation is not disabled by any policy",
          "No enabled policy sets CAE mode disabled", sh03, needs=("CA_Policies",))
    ca_rule("SH-04", "CUS.SH.004", "A Conditional Access policy blocks access from outside trusted locations",
            "Enabled policy: block, all locations included, some excluded, all apps",
            lambda p: has(bic(p), "block") and has(cond(p, "locations", "includeLocations"), "All")
            and len(as_list(cond(p, "locations", "excludeLocations"))) > 0 and has(cond(p, "applications", "includeApplications"), "All"), fw=FW_SH)
    ca_rule("SH-05", "CUS.SH.005", "A Conditional Access policy requires phishing-resistant MFA",
            "Enabled policy: built-in Phishing-resistant MFA authentication strength, all apps",
            lambda p: g(p, "grantControls", "authenticationStrength", "id") == PHISH_RESISTANT_STRENGTH
            and has(cond(p, "applications", "includeApplications"), "All"), fw=FW_SH)


# ------------------------------------------------------------------------------ applications and permissions
def run_apps(e: Engine) -> None:
    def app_rule(rid, ref, title, expected, needs, fn, pass_text, severity):
        def wrapped():
            findings = fn()
            if findings is None:
                return {"skip": "not applicable"}
            if not findings:
                return {"pass": True, "actual": pass_text}
            return {"pass": False, "affected": findings, "actual": f"{len(findings)} finding(s): {join_findings(findings)}"}
        e.run(rid, ref, FW_APP, title, expected, wrapped, needs=needs)
        e.results[-1]["severity"] = severity

    apps = e.ds("Applications")
    sps = e.ds("ServicePrincipals")

    app_rule("APP-01", "MT.1057", "App registrations should no longer use client secrets", "No app registration has a client secret",
             ("Applications",), lambda: [a.get("displayName") for a in apps if as_list(a.get("passwordCredentials"))],
             "No app registrations use secrets", "Medium")

    def unique_certs(app):
        seen, out = set(), []
        for c in as_list(app.get("keyCredentials")):
            key = c.get("customKeyIdentifier") or c.get("keyId")
            if key not in seen:
                seen.add(key)
                out.append(c)
        return out

    def long_certs():
        hit = []
        for app in apps:
            for c in unique_certs(app):
                start, end = parse_dt(c.get("startDateTime")), parse_dt(c.get("endDateTime"))
                if not start or not end or end < e.now:
                    continue
                days = -(-int((end - start).total_seconds()) // 86400)
                if days > 365:
                    hit.append(f"{app.get('displayName')} ({days} days)")
        return hit
    app_rule("APP-02", "MT.1198", "App registration certificates should not have excessive validity periods (more than 365 days)",
             "No unexpired certificate is valid for more than 365 days", ("Applications",), long_certs,
             "No certificate has an excessive validity period", "Medium")

    def expiring():
        hit = []
        for app in apps:
            creds = [("certificate", c) for c in unique_certs(app)] + [("secret", c) for c in as_list(app.get("passwordCredentials"))]
            for kind, c in creds:
                end = parse_dt(c.get("endDateTime"))
                if not end:
                    continue
                left = -(-int((end - e.now).total_seconds()) // 86400)
                if end < e.now:
                    hit.append(f"{app.get('displayName')} {kind} expired {abs(left)} day(s) ago")
                elif left <= 30:
                    hit.append(f"{app.get('displayName')} {kind} expires in {left} day(s)")
        return hit
    app_rule("APP-03", "MT.1199", "App registration credentials should not be expired or expiring within 30 days",
             "No secret or certificate is expired or expires within 30 days", ("Applications",), expiring,
             "No credential is expired or about to expire", "Medium")

    def owners_mfa():
        mfa = {m.get("id"): m.get("isMfaRegistered") is True for m in e.ds("MfaRegistration") or [] if m.get("id")}
        return [f"{o.get('userPrincipalName') or o.get('displayName')} owns {a.get('displayName')}"
                for a in apps for o in as_list(a.get("owners")) if o.get("id") in mfa and not mfa[o["id"]]]
    app_rule("APP-04", "MT.1063", "All app registration owners should have MFA registered",
             "Every user who owns an app registration has MFA registered", ("Applications", "MfaRegistration"), owners_mfa,
             "All app owners have MFA registered", "High")

    app_rule("APP-05", "MT.1075", "Third-party enterprise applications should require explicit user assignment",
             "No enabled third-party service principal is open to all users", ("ServicePrincipals",),
             lambda: [s.get("displayName") for s in sps if s.get("appOwnerOrganizationId") not in MICROSOFT_TENANTS
                      and s.get("appRoleAssignmentRequired") is not True and s.get("accountEnabled") is True
                      and s.get("servicePrincipalType") in ("Application", "Legacy")],
             "No third-party service principal is open to all users", "Medium")

    def first_party():
        hit = []
        for app_id, name in WATCHED_FIRST_PARTY.items():
            sp = next((s for s in sps if lc(s.get("appId")) == app_id), None)
            if sp is None:
                hit.append(f"{name}: service principal missing (assignment not enforced)")
            elif sp.get("appRoleAssignmentRequired") is not True:
                hit.append(f"{name}: " + ("open to all users" if sp.get("accountEnabled") is True else "disabled but assignment not required"))
        return hit
    app_rule("APP-06", "MT.1186", "High-privilege first-party enterprise applications should require explicit user assignment",
             "Each monitored app has a service principal that requires assignment", ("ServicePrincipals",), first_party,
             "All monitored first-party apps require assignment", "High")

    for path, rid, ref in (("Direct", "APP-07", "MT.1050"), ("Indirect", "APP-08", "MT.1051")):
        def risky(path=path):
            watch = [r for r in RISK_PERMISSIONS if r[3] == path]
            hit = []
            for grant in e.ds("SP_AppRoleAssignments") or []:
                for rp in watch:
                    if rp[2] == "Application" and lc(rp[0]) == lc(grant.get("appRoleId")):
                        hit.append(f"{grant.get('servicePrincipalName')}: {rp[1]} (Application)")
            for grant in e.ds("SP_Oauth2Grants") or []:
                for scope in [s for s in str(grant.get("scope") or "").split(" ") if s]:
                    for rp in watch:
                        if rp[2] == "Delegated" and lc(rp[1]) == lc(scope):
                            hit.append(f"{grant.get('servicePrincipalName')}: {rp[1]} (Delegated)")
            return hit
        app_rule(rid, ref, f"No app holds high-risk permissions with a {path.lower()} path to Global Administrator",
                 f"No application or delegated grant of the {path.lower()}-path permissions",
                 ("SP_AppRoleAssignments", "SP_Oauth2Grants"), risky, "No app holds these permissions", "High")

    # who can register and consent to apps (tenant settings)
    authz = e.first("AuthorizationPolicy")
    consent = e.first("AdminConsentPolicy")

    def simple(rid, ref, title, expected, needs, value_fn, ok_fn, severity):
        def fn():
            v = value_fn()
            return {"pass": ok_fn(v), "actual": v[1] if isinstance(v, tuple) else str(v)}
        e.run(rid, ref, FW_APP, title, expected, fn, needs=needs)
        e.results[-1]["severity"] = severity

    def create_apps():
        v = g(authz, "defaultUserRolePermissions", "allowedToCreateApps")
        return {"pass": v is False, "actual": f"allowedToCreateApps = {to_str(v)}"}
    e.run("APP-09", "CISA.MS.AAD.5.1 / CIS.M365.5.1.2.2", FW_APP, "Only administrators can register applications",
          "allowedToCreateApps is false", create_apps, needs=("AuthorizationPolicy",))
    e.results[-1]["severity"] = "High"

    def user_consent():
        pols = [p for p in as_list(g(authz, "permissionGrantPolicyIdsAssignedToDefaultUserRole")) if str(p).startswith("ManagePermissionGrantsForSelf")]
        return {"pass": not pols, "actual": "User consent disabled" if not pols else "Assigned: " + ", ".join(pols)}
    e.run("APP-10", "CISA.MS.AAD.5.2 / CIS.M365.5.1.5.1", FW_APP, "Only administrators can consent to applications (user consent is not allowed)",
          "No ManagePermissionGrantsForSelf policy is assigned to the default user role", user_consent, needs=("AuthorizationPolicy",))
    e.results[-1]["severity"] = "High"

    def consent_workflow():
        v = (consent or {}).get("isEnabled")
        return {"pass": v is True, "actual": f"isEnabled = {to_str(v)}"}
    e.run("APP-11", "CISA.MS.AAD.5.3 / CIS.M365.5.1.5.2", FW_APP, "An admin consent workflow is enabled for applications",
          "isEnabled is true", consent_workflow, needs=("AdminConsentPolicy",))
    e.results[-1]["severity"] = "Medium"


# ------------------------------------------------------------------------------ identity, privileged access, hybrid, governance, ...
def run_identity(e: Engine) -> None:
    org = e.first("Organization") or {}
    tenant_id = org.get("id") or e.manifest.get("tenant_id")
    sync_enabled = org.get("onPremisesSyncEnabled") is True
    sync_skip = {"skip": "Directory synchronization from on-premises is not enabled in this tenant"}

    def rule(rid, ref, fw, title, expected, fn, needs=(), min_plan="Any"):
        e.run(rid, ref, fw, title, expected, fn, needs=needs, min_plan=min_plan)

    # authentication methods
    def id01():
        cfg = e.ds("AuthMethodConfigs")
        bad = []
        for m in ("Sms", "Voice", "Email"):
            c = next((x for x in cfg if x.get("id") == m), None)
            if c is None or c.get("state") == "enabled":
                bad.append(m)
        return {"pass": not bad, "affected": bad, "actual": ("Enabled or missing: " + ", ".join(bad)) if bad else "All three disabled"}
    rule("ID-01", "CISA.MS.AAD.3.5 / CIS.M365.5.2.3.5", FW_ID, "SMS, voice call and email OTP authentication methods are disabled",
         "Sms, Voice and Email methods all have state disabled", id01, ("AuthMethodConfigs",), "P1")

    def id02():
        a = next((x for x in e.ds("AuthMethodConfigs") if x.get("id") == "MicrosoftAuthenticator"), None)
        f = (a or {}).get("featureSettings") or {}
        app_info, loc_info = f.get("displayAppInformationRequiredState") or {}, f.get("displayLocationInformationRequiredState") or {}
        ok = bool(a) and a.get("state") == "enabled" and has(g(a, "includeTargets", "id"), "all_users") and a.get("isSoftwareOathEnabled") is False \
            and app_info.get("state") == "enabled" and has(g(app_info, "includeTarget", "id"), "all_users") \
            and loc_info.get("state") == "enabled" and has(g(loc_info, "includeTarget", "id"), "all_users")
        return {"pass": ok, "actual": f"state={to_str((a or {}).get('state'))}; OTP={to_str((a or {}).get('isSoftwareOathEnabled'))}; "
                                      f"appInfo={to_str(app_info.get('state'))}; location={to_str(loc_info.get('state'))}"}
    rule("ID-02", "CISA.MS.AAD.3.3", FW_ID, "Microsoft Authenticator shows application and location context for all users",
         "Authenticator enabled for all users, OTP off, app name and geographic location shown to all users", id02, ("AuthMethodConfigs",), "P1")

    def id03():
        v = (e.first("AuthMethodsPolicy") or {}).get("policyMigrationState")
        return {"pass": v in ("migrationComplete", None, ""), "actual": f"policyMigrationState = {to_str(v)}"}
    rule("ID-03", "CISA.MS.AAD.3.4", FW_ID, 'Authentication methods "Manage migration" is set to Migration Complete',
         "policyMigrationState is migrationComplete (or not set)", id03, ("AuthMethodsPolicy",), "P1")

    # guests and external access
    rule("ID-04", "CISA.MS.AAD.8.1 / CIS.M365.5.1.6.2", FW_ID, "Guest user access to directory objects is limited or restricted",
         'guestUserRoleId is the "limited" or "restricted" role',
         lambda: {"pass": (e.first("AuthorizationPolicy") or {}).get("guestUserRoleId") in ("10dae51f-b6af-4016-8d66-8c2a99b929b3", "2af84b1e-32c8-42b7-82bc-daa82404023b"),
                  "actual": f"guestUserRoleId = {to_str((e.first('AuthorizationPolicy') or {}).get('guestUserRoleId'))}"}, ("AuthorizationPolicy",))
    rule("ID-05", "CISA.MS.AAD.8.2", FW_ID, "Only admins and guest inviters (or nobody) can invite guests",
         "allowInvitesFrom is adminsAndGuestInviters or none",
         lambda: {"pass": (e.first("AuthorizationPolicy") or {}).get("allowInvitesFrom") in ("adminsAndGuestInviters", "none"),
                  "actual": f"allowInvitesFrom = {to_str((e.first('AuthorizationPolicy') or {}).get('allowInvitesFrom'))}"}, ("AuthorizationPolicy",))

    def id06():
        p = e.first("CrossTenantDefault") or {}
        u, a = g(p, "b2bCollaborationInbound", "usersAndGroups", "accessType"), g(p, "b2bCollaborationInbound", "applications", "accessType")
        return {"pass": u == "blocked" and a == "blocked", "actual": f"usersAndGroups = {to_str(u)}; applications = {to_str(a)}"}
    rule("ID-06", "CISA.MS.AAD.8.3", FW_ID, "Inbound B2B collaboration is blocked by default for users, groups and applications",
         "Default cross-tenant inbound B2B collaboration accessType is blocked for users/groups and applications", id06, ("CrossTenantDefault",))

    # groups and tenant creation
    def id07():
        vals = [v for s in e.ds("DirectorySettings") for v in as_list(s.get("values")) if isinstance(v, dict) and v.get("name") == "EnableGroupCreation"]
        v = vals[0] if vals else None
        return {"pass": v is not None and str(v.get("value")).lower() == "false",
                "actual": "EnableGroupCreation is not set (default: anyone can create groups)" if v is None else f"EnableGroupCreation = {v.get('value')}"}
    rule("ID-07", "MT.1055", FW_ID, "Microsoft 365 group creation is restricted to approved users",
         "Directory setting EnableGroupCreation is false", id07, ("DirectorySettings",))
    rule("ID-08", "MT.1068", FW_ID, "Non-admin users cannot create tenants", "defaultUserRolePermissions.allowedToCreateTenants is false",
         lambda: {"pass": g(e.first("AuthorizationPolicy"), "defaultUserRolePermissions", "allowedToCreateTenants") is False,
                  "actual": f"allowedToCreateTenants = {to_str(g(e.first('AuthorizationPolicy'), 'defaultUserRolePermissions', 'allowedToCreateTenants'))}"},
         ("AuthorizationPolicy",))
    rule("ID-09", "MT.1069", FW_ID, "Non-admin users cannot create security groups", "defaultUserRolePermissions.allowedToCreateSecurityGroups is false",
         lambda: {"pass": g(e.first("AuthorizationPolicy"), "defaultUserRolePermissions", "allowedToCreateSecurityGroups") is False,
                  "actual": f"allowedToCreateSecurityGroups = {to_str(g(e.first('AuthorizationPolicy'), 'defaultUserRolePermissions', 'allowedToCreateSecurityGroups'))}"},
         ("AuthorizationPolicy",))

    def id10():
        hit = [x.get("displayName") for x in e.ds("Groups") if has(x.get("groupTypes"), "Unified") and x.get("visibility") == "Public"]
        return {"pass": not hit, "affected": hit, "actual": f"{len(hit)} public group(s): " + join_findings(hit) if hit else "No public Microsoft 365 groups"}
    rule("ID-10", "CIS.M365.1.2.1", FW_ID, "Only organizationally approved public Microsoft 365 groups exist (none are public)",
         "No Microsoft 365 (Unified) group has visibility Public", id10, ("Groups",))

    def id11():
        managed = [d for d in e.ds("Domains") if d.get("isVerified") is True and d.get("authenticationType") == "Managed"]
        managed = [d for d in managed if not (len(as_list(d.get("supportedServices"))) == 1 and has(d.get("supportedServices"), "SharePoint"))]
        if not managed:
            return {"skip": "No applicable verified managed domains"}
        bad = [f"{d['id']} ({to_str(d.get('passwordValidityPeriodInDays'))})" for d in managed
               if str(d.get("passwordValidityPeriodInDays")) != "2147483647"]
        return {"pass": not bad, "affected": bad, "actual": ("Passwords expire on: " + ", ".join(bad)) if bad else f"All {len(managed)} domain(s) set to never expire"}
    rule("ID-11", "CISA.MS.AAD.6.1 / CIS.M365.1.3.1", FW_ID, "User passwords do not expire (all verified managed domains)",
         "passwordValidityPeriodInDays is 2147483647 on every verified managed domain", id11, ("Domains",))

    def id12():
        if e.plan != "Free":
            return {"skip": "Tenant has Entra ID Premium; use Conditional Access instead of security defaults"}
        v = (e.first("SecurityDefaults") or {}).get("isEnabled")
        return {"pass": v is True, "actual": f"isEnabled = {to_str(v)}"}
    rule("ID-12", "MT.1021", FW_ID, "Security defaults are enabled (tenants without Entra ID Premium)", "isEnabled is true", id12, ("SecurityDefaults",))

    # devices
    drp = lambda: e.first("DeviceRegPolicy") or {}  # noqa: E731
    t = g(drp(), "azureADJoin", "allowedToJoin", "@odata.type")
    rule("ID-13", "MT.1070", FW_ID, "Device join is restricted to selected users/groups or none", "azureADJoin.allowedToJoin is enumerated membership or none",
         lambda: {"pass": ((drp().get("azureADJoin") or {}).get("allowedToJoin") or {}).get("@odata.type") in
                  ("#microsoft.graph.enumeratedDeviceRegistrationMembership", "#microsoft.graph.noDeviceRegistrationMembership"),
                  "actual": f"allowedToJoin = {to_str(((drp().get('azureADJoin') or {}).get('allowedToJoin') or {}).get('@odata.type'))}"}, ("DeviceRegPolicy",))
    rule("ID-14", "MT.1090", FW_ID, "Global Administrator is not added as local administrator during Entra join",
         "azureADJoin.localAdmins.enableGlobalAdmins is false",
         lambda: {"pass": g(drp(), "azureADJoin", "localAdmins", "enableGlobalAdmins") is False,
                  "actual": f"enableGlobalAdmins = {to_str(g(drp(), 'azureADJoin', 'localAdmins', 'enableGlobalAdmins'))}"}, ("DeviceRegPolicy",))
    rule("ID-15", "MT.1091", FW_ID, "The registering user is not added as local administrator during Entra join",
         "azureADJoin.localAdmins.registeringUsers is noDeviceRegistrationMembership",
         lambda: {"pass": (g(drp(), "azureADJoin", "localAdmins", "registeringUsers") or {}).get("@odata.type") == "#microsoft.graph.noDeviceRegistrationMembership",
                  "actual": f"registeringUsers = {to_str((g(drp(), 'azureADJoin', 'localAdmins', 'registeringUsers') or {}).get('@odata.type'))}"}, ("DeviceRegPolicy",))

    # hybrid identity
    def hy01():
        if not sync_enabled:
            return sync_skip
        f = (e.first("OnPremSync") or {}).get("features") or {}
        soft, hard = f.get("blockSoftMatchEnabled"), f.get("blockCloudObjectTakeoverThroughHardMatchEnabled")
        return {"pass": soft is not False and hard is not False,
                "actual": f"blockSoftMatchEnabled = {to_str(soft)}; blockCloudObjectTakeoverThroughHardMatchEnabled = {to_str(hard)}"}
    rule("HY-01", "MT.1073", FW_ID, "Soft-match and hard-match of synchronized objects are blocked",
         "features.blockSoftMatchEnabled and blockCloudObjectTakeoverThroughHardMatchEnabled are not false", hy01, ("Organization", "OnPremSync"))

    def hy02():
        if not sync_enabled:
            return sync_skip
        v = ((e.first("OnPremSync") or {}).get("features") or {}).get("allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled")
        return {"pass": v is not True, "actual": f"allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled = {to_str(v)}"}
    rule("HY-02", "MT.1183", FW_ID, "The temporary bypass for onPremisesObjectIdentifier updates is disabled",
         "features.allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled is not true", hy02, ("Organization", "OnPremSync"))

    def hy03():
        if not sync_enabled:
            return sync_skip
        hit = []
        for u in e.ds("Users"):
            if u.get("onPremisesSyncEnabled") is not True:
                continue
            candidates = [u.get("displayName"), u.get("mailNickname"), u.get("onPremisesSamAccountName")]
            upn_prefix = str(u.get("userPrincipalName") or "").split("@")[0]
            if any(lc(c) == "krbtgt_azuread" for c in candidates) or lc(upn_prefix) == "krbtgt_azuread" \
                    or re.search(r"(^|,)CN=krbtgt_AzureAD,", str(u.get("onPremisesDistinguishedName") or ""), re.I):
                hit.append(u.get("userPrincipalName"))
        return {"pass": not hit, "affected": hit, "actual": ("Synchronized: " + ", ".join(map(str, hit))) if hit else "Not synchronized"}
    rule("HY-03", "MT.1147", FW_ID, "krbtgt_AzureAD is not synchronized to Entra ID", "No synchronized user is named krbtgt_AzureAD", hy03, ("Organization", "Users"))

    # privileged access
    assignments = e.ds("RoleAssignments")
    control_plane = [a for a in (assignments or []) if a.get("roleDefinitionId") in CONTROL_PLANE_ROLES]
    role_names = {r.get("id"): r.get("displayName") for r in e.ds("RoleDefinitions") or []}
    fmt = lambda a: f"{g(a, 'principal', 'displayName')} ({role_names.get(a.get('roleDefinitionId'), a.get('roleDefinitionId'))})"  # noqa: E731

    def pa(rid, ref, title, expected, pred):
        def fn():
            hit = [fmt(a) for a in control_plane if pred(a)]
            return {"pass": not hit, "affected": hit, "actual": join_findings(hit) if hit else "None"}
        rule(rid, ref, FW_PA, title, expected, fn, ("RoleAssignments",))
    pa("PA-01", "MT.1025", "No external (guest) user has a permanent Control Plane role assignment",
       "No permanent assignment of a Control Plane role to a guest user", lambda a: g(a, "principal", "userType") == "Guest")
    pa("PA-02", "MT.1026", "No hybrid (synced) user has a permanent Control Plane role assignment",
       "No permanent assignment of a Control Plane role to a synchronized user",
       lambda a: g(a, "principal", "onPremisesImmutableId") is not None and g(a, "principal", "onPremisesSyncEnabled") is True)
    apps_with_secret = {a.get("appId") for a in e.ds("Applications") or [] if as_list(a.get("passwordCredentials"))}
    pa("PA-03", "MT.1027", "No service principal with a client secret has a permanent Control Plane role assignment",
       "No permanent Control Plane role held by a service principal that has a client secret",
       lambda a: g(a, "principal", "servicePrincipalType") == "Application" and (
           bool(as_list(g(a, "principal", "passwordCredentials")))
           or (g(a, "principal", "appOwnerOrganizationId") == tenant_id and g(a, "principal", "appId") in apps_with_secret)))
    pa("PA-04", "MT.1028", "No mailbox-enabled user has a permanent Control Plane role assignment",
       "No permanent Control Plane assignment to a user with an enabled Exchange plan",
       lambda a: any(p.get("capabilityStatus") == "Enabled" and has(p.get("service"), "exchange") for p in as_list(g(a, "principal", "provisionedPlans"))))

    def pim_alert(rid, ref, title, dataset, control_plane_only=False):
        def fn():
            alert = e.first(dataset) or {}
            items = as_list(alert.get("alertIncidents")) if alert.get("isActive") is True else []
            if control_plane_only:
                items = [i for i in items if i.get("roleTemplateId") in CONTROL_PLANE_ROLES]
            items = [i for i in items if i.get("assigneeId") not in e.emergency]
            if items:
                labels = [f"{i.get('assigneeDisplayName')} / {i.get('roleDisplayName')}" for i in items]
                return {"pass": False, "affected": labels, "actual": f"{len(items)} affected item(s): " + join_findings(labels)}
            return {"pass": True, "actual": "Alert not active or no affected items"}
        rule(rid, ref, FW_PA, title, "The PIM alert is not active, or has no affected items (break-glass accounts excluded)", fn, (dataset,), "P2")
    pim_alert("PA-05", "MT.1029", "Stale accounts are not assigned to privileged roles", "PIM_Alert_StaleSignIn")
    pim_alert("PA-06", "MT.1030", "Eligible role assignments on Control Plane are in use by administrators", "PIM_Alert_Redundant", True)
    pim_alert("PA-07", "MT.1031", "Control Plane roles are managed by PIM only", "PIM_Alert_OutsidePim", True)
    pim_alert("PA-08", "MT.1032", "A limited number of Global Administrators is assigned", "PIM_Alert_TooManyGA")

    def role_users(role_ids):
        allrows = (e.ds("RoleAssignments") or []) + (e.ds("RoleEligibility") or [])
        return [a for a in allrows if a.get("roleDefinitionId") in role_ids and (a.get("principal") or {}).get("@odata.type") == "#microsoft.graph.user"]

    def pa09():
        ga = len(role_users([GLOBAL_ADMIN]))
        other = len(role_users([r for r in HIGHLY_PRIVILEGED if r != GLOBAL_ADMIN]))
        if other == 0:
            return {"pass": False, "actual": f"{ga} Global Administrator assignment(s) and 0 in the other highly privileged roles"}
        return {"pass": ga / other <= 1, "actual": f"Ratio {round(ga / other, 2)} = {ga} / {other} (direct assignments only)"}
    rule("PA-09", "CISA.MS.AAD.7.2", FW_PA, "Privileged users use finer-grained roles instead of Global Administrator",
         "Global Administrator user assignments are no more than the assignments to the other highly privileged roles (ratio <= 1)",
         pa09, ("RoleAssignments", "RoleEligibility"))

    def pa10():
        synced = {u.get("id") for u in e.ds("Users") or [] if u.get("onPremisesSyncEnabled") is True}
        hit = sorted({g(a, "principal", "displayName") for a in role_users([GLOBAL_ADMIN])
                      if g(a, "principal", "onPremisesSyncEnabled") is True or a.get("principalId") in synced})
        return {"pass": not hit, "affected": hit, "actual": ("Synchronized Global Administrators: " + join_findings(hit)) if hit else
                "All Global Administrators are cloud-only (users checked from RoleAssignments and RoleEligibility; Users data used when collected)"}
    rule("PA-10", "CISA.MS.AAD.7.3", FW_PA, "Global Administrators are cloud-only accounts",
         "No Global Administrator user is synchronized from on-premises", pa10, ("RoleAssignments", "RoleEligibility"))

    def pa11():
        hit = [fmt(a) for a in e.ds("RoleAssignmentSchedules") if a.get("roleDefinitionId") in HIGHLY_PRIVILEGED and a.get("assignmentType") == "Assigned"
               and g(a, "scheduleInfo", "expiration", "type") == "noExpiration"]
        return {"pass": not hit, "affected": hit, "actual": join_findings(hit) if hit else "None"}
    rule("PA-11", "CISA.MS.AAD.7.4", FW_PA, "No permanent active assignments for highly privileged roles",
         "No active (Assigned) schedule with no expiration for the highly privileged roles", pa11, ("RoleAssignmentSchedules",), "P2")

    def pa12():
        hit = [fmt(a) for a in e.ds("RoleAssignmentSchedules") if a.get("roleDefinitionId") in HIGHLY_PRIVILEGED and a.get("assignmentType") == "Assigned"
               and (a.get("createdUsing") is None or g(a, "scheduleInfo", "startDateTime") is None)]
        return {"pass": not hit, "affected": hit, "actual": join_findings(hit) if hit else "None"}
    rule("PA-12", "CISA.MS.AAD.7.5", FW_PA, "Highly privileged roles are provisioned only through PIM",
         "Every Assigned schedule for the highly privileged roles was created through PIM", pa12, ("RoleAssignmentSchedules",), "P2")

    def policy_rules(role_id):
        pol = next((x for x in e.ds("RoleMgmtPolicies") if x.get("roleDefinitionId") == role_id), None)
        return as_list(g(pol, "policy", "rules"))

    def pa13():
        rl = next((r for r in policy_rules(GLOBAL_ADMIN) if r.get("@odata.type") == "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"), None)
        v = g(rl, "setting", "isApprovalRequired")
        return {"pass": v is True, "actual": f"isApprovalRequired = {to_str(v)}"}
    rule("PA-13", "CISA.MS.AAD.7.6", FW_PA, "Activation of the Global Administrator role requires approval",
         "The Global Administrator role policy approval rule has isApprovalRequired true", pa13, ("RoleMgmtPolicies",), "P2")

    def notification(rid, ref, title, roles, rule_ids):
        def fn():
            bad = []
            for role in roles:
                for rule_id in rule_ids:
                    rl = next((r for r in policy_rules(role) if r.get("id") == rule_id), None)
                    if not as_list((rl or {}).get("notificationRecipients")):
                        bad.append(f"{role_names.get(role, role)}: {rule_id}")
            return {"pass": not bad, "affected": bad, "actual": ("No recipients - " + join_findings(bad)) if bad else "Notifications configured"}
        rule(rid, ref, FW_PA, title, "Each role policy has a notification rule with recipients configured", fn, ("RoleMgmtPolicies",), "P2")
    other_priv = [r for r in HIGHLY_PRIVILEGED if r != GLOBAL_ADMIN]
    notification("PA-14", "CISA.MS.AAD.7.7", "Eligible and active assignments of highly privileged roles trigger an alert", HIGHLY_PRIVILEGED,
                 ["Notification_Admin_Admin_Eligibility", "Notification_Admin_Admin_Assignment"])
    notification("PA-15", "CISA.MS.AAD.7.8", "Activation of the Global Administrator role triggers an alert", [GLOBAL_ADMIN], ["Notification_Admin_EndUser_Assignment"])
    notification("PA-16", "CISA.MS.AAD.7.9", "Activation of other highly privileged roles triggers an alert", other_priv, ["Notification_Admin_EndUser_Assignment"])

    # entitlement management
    def em01():
        sp_ids = {s.get("id") for s in e.ds("ServicePrincipals")}
        hit = [f"{r.get('parentName')}: {r.get('displayName')}" for r in e.ds("EntMgmt_CatalogResources")
               if re.search("Application", f"{r.get('resourceType') or ''}{r.get('originSystem') or ''}") and r.get("originId") and r["originId"] not in sp_ids]
        return {"pass": not hit, "affected": hit, "actual": ("Service principal not found - " + join_findings(hit)) if hit else "All application resources resolve"}
    rule("EM-01", "MT.1106", FW_EM, "Catalog application resources point to existing service principals",
         "Every application resource in a catalog has a service principal in the tenant (app-role validity not checked)", em01,
         ("EntMgmt_CatalogResources", "ServicePrincipals"), "P2")

    def em02():
        groups = {x.get("id") for x in e.ds("Groups")}
        hit = []
        for p in e.ds("EntMgmt_AssignmentPolicies"):
            for stage in as_list(g(p, "requestApprovalSettings", "approvalStages")):
                for ap in as_list(stage.get("primaryApprovers")):
                    if ap.get("@odata.type") == "#microsoft.graph.groupMembers" and ap.get("groupId") and ap["groupId"] not in groups:
                        hit.append(f"Policy '{p.get('displayName')}': approver group {ap['groupId']}")
        for rs in e.ds("EntMgmt_PackageRoleScopes"):
            sc = rs.get("accessPackageResourceScope") or {}
            if sc.get("originSystem") == "AadGroup" and sc.get("originId") and sc["originId"] not in groups:
                hit.append(f"Package {rs.get('parentName')}: resource group {sc.get('displayName')}")
        return {"pass": not hit, "affected": hit, "actual": join_findings(hit) if hit else "All referenced groups exist"}
    rule("EM-02", "MT.1107", FW_EM, "Access packages and catalogs do not reference deleted groups",
         "Every group used as an approver or package resource exists", em02, ("EntMgmt_AssignmentPolicies", "EntMgmt_PackageRoleScopes", "Groups"), "P2")

    def em03():
        hit = []
        for p in e.ds("EntMgmt_AssignmentPolicies"):
            issues = []
            rs = p.get("requestorSettings") or {}
            if rs.get("acceptRequests") is False:
                issues.append("not accepting requests")
            if rs.get("scopeType") == "NoSubjects":
                issues.append("no eligible requestors")
            if rs.get("scopeType") == "SpecificDirectorySubjects" and not as_list(rs.get("allowedRequestors")):
                issues.append("no allowed requestors")
            ras = p.get("requestApprovalSettings") or {}
            if ras.get("isApprovalRequired") is True:
                stages = as_list(ras.get("approvalStages"))
                if not stages or not any(as_list(s.get("primaryApprovers")) for s in stages):
                    issues.append("approval required but no approvers")
            exp = parse_dt(p.get("expirationDateTime"))
            if exp and exp < e.now:
                issues.append("expired")
            if issues:
                hit.append(f"{p.get('displayName')}: {', '.join(issues)}")
        return {"pass": not hit, "affected": hit, "actual": join_findings(hit) if hit else "No inactive policies"}
    rule("EM-03", "MT.1108", FW_EM, "Access packages do not use inactive or orphaned assignment policies",
         "No policy is closed to requests, has no eligible requestors, requires approval without approvers, or is expired", em03,
         ("EntMgmt_AssignmentPolicies",), "P2")

    def em04():
        users = {u.get("id"): u for u in e.ds("Users")}
        groups = {x.get("id") for x in e.ds("Groups")}
        hit = []
        for p in e.ds("EntMgmt_AssignmentPolicies"):
            name = str(p.get("displayName") or "")
            if "all members" in name.lower() and "excluding guests" in name.lower():
                continue
            ras = p.get("requestApprovalSettings") or {}
            if ras.get("isApprovalRequired") is not True:
                continue
            stages = as_list(ras.get("approvalStages"))
            if not stages:
                hit.append(f"{name}: no approval stages")
                continue
            for stage in stages:
                prim = as_list(stage.get("primaryApprovers"))
                if not prim:
                    hit.append(f"{name}: stage has no primary approvers")
                    continue
                for ap in prim:
                    t = ap.get("@odata.type")
                    if t == "#microsoft.graph.singleUser":
                        uid = ap.get("userId") or ap.get("id")
                        if not uid or uid not in users or users[uid].get("accountEnabled") is False:
                            hit.append(f"{name}: approver user {uid} is missing or disabled")
                    elif t == "#microsoft.graph.groupMembers" and ap.get("groupId") not in groups:
                        hit.append(f"{name}: approver group {ap.get('groupId')} not found")
        return {"pass": not hit, "affected": hit, "actual": join_findings(hit) if hit else "All approvers valid"}
    rule("EM-04", "MT.1109", FW_EM, "Access package approval workflows have valid approvers",
         "Every policy that requires approval has stages with approvers that exist and are enabled", em04,
         ("EntMgmt_AssignmentPolicies", "Users", "Groups"), "P2")

    def em05():
        pkg_catalog = {p.get("id"): p.get("catalogId") for p in e.ds("EntMgmt_AccessPackages")}
        used = {f"{pkg_catalog.get(rs.get('parentId'))}|{(rs.get('accessPackageResourceScope') or {}).get('originId')}"
                for rs in e.ds("EntMgmt_PackageRoleScopes") if (rs.get("accessPackageResourceScope") or {}).get("originId")}
        catalogs_with_packages = set(pkg_catalog.values())
        hit = [f"{r.get('parentName')}: {r.get('displayName')}" for r in e.ds("EntMgmt_CatalogResources")
               if r.get("parentId") in catalogs_with_packages and f"{r.get('parentId')}|{r.get('originId')}" not in used]
        return {"pass": not hit, "affected": hit, "actual": ("Unused resources - " + join_findings(hit)) if hit else "All catalog resources are used"}
    rule("EM-05", "MT.1110", FW_EM, "No catalog contains resources without an associated access package",
         "Every catalog resource is used by an access package in that catalog", em05,
         ("EntMgmt_CatalogResources", "EntMgmt_AccessPackages", "EntMgmt_PackageRoleScopes"), "P2")

    # Entra recommendations (one result per recommendation)
    recs = e.ds("Entra_Recommendations")
    if recs is None:
        e.add("REC-ALL", "MT.1024", FW_REC, "Entra recommendations are completed", "Skipped", "Each recommendation has status completedBySystem",
              reason="Data set 'Entra_Recommendations' was not collected", dataset="Entra_Recommendations", severity="Medium")
    else:
        premium = ("insiderRiskPolicy", "userRiskPolicy", "signinRiskPolicy")
        for rec in recs:
            short = re.sub(r"^[^_]+_", "", str(rec.get("id")))
            rid, ref = f"REC-{short}", f"MT.1024.{short}"
            sev = str(rec.get("priority") or "medium").title()
            title = str(rec.get("displayName"))
            expected = "status is completedBySystem"
            detail = rec_details(rec)
            if re.search("dismissed", str(rec.get("status")), re.I):
                e.add(rid, ref, FW_REC, title, "Skipped", expected, reason="Dismissed by an administrator", dataset="Entra_Recommendations", severity=sev, details=detail)
                continue
            if e.plan in ("Free", "P1") and any(str(rec.get("id")).endswith(p) for p in premium):
                e.add(rid, ref, FW_REC, title, "Skipped", expected, reason="Requires Entra ID P2", dataset="Entra_Recommendations", severity=sev, details=detail)
                continue
            ok, note = rec.get("status") == "completedBySystem", ""
            if not ok and rec.get("recommendationType") in ("userRiskPolicy", "signinRiskPolicy") and e.emergency:
                open_res = [r for r in as_list(rec.get("impactedResources")) if r.get("status") != "completedBySystem"]
                if open_res and all((r.get("subjectId") or r.get("id")) in e.emergency for r in open_res):
                    ok, note = True, " (only break-glass accounts are impacted)"
            open_res = [r for r in as_list(rec.get("impactedResources")) if isinstance(r, dict) and r.get("status") != "completedBySystem"]
            insights = html_to_md(rec.get("insights"))
            if ok:
                actual = f"status = {to_str(rec.get('status'))}{note}"
            elif insights:
                actual = insights
            else:
                actual = f"status = {to_str(rec.get('status'))}" + (f"; {len(open_res)} impacted resource(s) not yet remediated" if open_res else "")
            e.add(rid, ref, FW_REC, title, "Passed" if ok else "Failed", expected, actual, dataset="Entra_Recommendations", severity=sev,
                  affected=None if ok else [r.get("displayName") or r.get("id") for r in open_res], details=detail)

    # logging
    def lg01():
        available = [c.get("name") for c in e.ds("Azure_DiagCategories") if g(c, "properties", "categoryType") == "Logs"]
        enabled = {lg.get("category") for s in e.ds("Azure_DiagSettings") for lg in as_list(g(s, "properties", "logs")) if lg.get("enabled") is True}
        missing = [c for c in available if c in CIS_LOG_CATEGORIES and c not in enabled]
        return {"pass": not missing, "affected": missing, "actual": ("Not enabled: " + ", ".join(missing)) if missing else "All required categories enabled"}
    rule("LG-01", "CISA.MS.AAD.4.1", FW_LOG, "Entra security logs are sent to a monitoring destination",
         "Every required log category has a diagnostic setting that enables it", lg01, ("Azure_DiagCategories", "Azure_DiagSettings"), "P1")


# ------------------------------------------------------------------------------ output
def summarize_areas(results: list[dict]) -> list[dict]:
    """Posture score per area (workload): pass / (pass + fail). Not Assessable and Not Applicable are counted but not scored."""
    out = []
    for area in sorted({r.get("area", "Entra ID") for r in results}):
        sub = [r for r in results if r.get("area", "Entra ID") == area]
        c = {k: sum(1 for r in sub if r.get("outcome") == k) for k in ("Pass", "Fail", "Not Assessable", "Not Applicable")}
        scored = c["Pass"] + c["Fail"]
        out.append({"area": area, "total": len(sub), "pass": c["Pass"], "fail": c["Fail"], "not_assessable": c["Not Assessable"],
                    "not_applicable": c["Not Applicable"], "score": round(c["Pass"] * 100 / scored) if scored else None})
    return out


def summarize(results: list[dict]) -> list[dict]:
    out = []
    for fw in sorted({r["framework"] for r in results}, key=str.lower):
        sub = [r for r in results if r["framework"] == fw]
        out.append({"framework": fw, "total": len(sub), **{s.lower(): sum(1 for r in sub if r["status"] == s) for s in ("Passed", "Failed", "Skipped")}})
    out.append({"framework": "ALL", "total": len(results), **{s.lower(): sum(1 for r in results if r["status"] == s) for s in ("Passed", "Failed", "Skipped")}})
    return out


def write_excel(path: Path, results: list[dict], summary: list[dict]) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    wb = Workbook()
    ws = wb.active
    ws.title = "Test_Summary"
    ws.append(["Framework", "Total", "Passed", "Failed", "Skipped"])
    for s in summary:
        ws.append([s["framework"], s["total"], s["passed"], s["failed"], s["skipped"]])
    ws2 = wb.create_sheet("Test_Results")
    cols = ["rule_id", "reference_id", "framework", "area", "title", "severity", "outcome", "status", "nist", "required_licence", "expected", "actual", "reason", "dataset"]
    ws2.append(cols)
    for r in results:
        ws2.append([r.get(c, "") for c in cols])
    fills = {"Fail": "F8CBAD", "Pass": "C6EFCE", "Not Assessable": "FFE699", "Not Applicable": "EDEDED"}
    for row in ws2.iter_rows(min_row=2):
        row[6].fill = PatternFill("solid", fgColor=fills.get(row[6].value, "FFFFFF"))
    ws3 = wb.create_sheet("Area_Scores")
    ws3.append(["Area", "Total", "Pass", "Fail", "Not Assessable", "Not Applicable", "Score %"])
    for a in summarize_areas(results):
        ws3.append([a["area"], a["total"], a["pass"], a["fail"], a["not_assessable"], a["not_applicable"], a["score"]])
    for sheet in (ws, ws2):
        for c in sheet[1]:
            c.font = Font(bold=True)
        sheet.freeze_panes = "A2"
    for col, width in zip("ABCDEFGHIJKLMN", (18, 24, 24, 22, 70, 10, 15, 10, 12, 22, 60, 70, 40, 30)):
        ws2.column_dimensions[col].width = width
    wb.save(path)


def run_all(run_dir: Path, emergency_ids: list[str]) -> tuple[list[dict], list[dict], dict]:
    e = Engine(run_dir, emergency_ids)
    print(f"  Entra licence detected from collected data: {e.plan}")
    run_eidsca(e)
    run_ca(e)
    run_apps(e)
    run_identity(e)
    import zta_checks  # Microsoft Zero Trust Assessment (Entra identity) checks, kept in their own file
    zta_checks.run_zta(e, sys.modules[__name__])
    try:
        import spec_engine  # Intune, Exchange, Teams, SharePoint, compliance, Defender, Azure and extra Entra checks from specs/*.json
        print(f"  Spec checks run: {spec_engine.run_specs(e, sys.modules[__name__])}")
    except Exception as exc:  # noqa: BLE001 - never lose the Entra results over a spec problem
        print(f"  Spec checks not run: {exc}", file=sys.stderr)
    results = sorted(e.results, key=lambda r: (r["framework"].lower(), r["rule_id"].lower()))
    return results, summarize(results), e.manifest


def check_run(run_dir: Path, emergency_ids: list[str], excel: bool) -> None:
    results, summary, manifest = run_all(run_dir, emergency_ids)
    out = run_dir / "enriched"
    out.mkdir(exist_ok=True)
    checked_at = dt.datetime.now(dt.timezone.utc).isoformat()
    who = {k: manifest.get(k) for k in ("run_id", "company_id", "company_name", "tenant_id")}
    (out / "check_results.json").write_text(json.dumps({**who, "checked_at": checked_at, "results": results}, indent=1, ensure_ascii=False), encoding="utf-8")
    (out / "check_summary.json").write_text(json.dumps({**who, "checked_at": checked_at, "summary": summary, "areas": summarize_areas(results)}, indent=1), encoding="utf-8")
    if excel:
        write_excel(out / "check_results.xlsx", results, summary)
    print(f"  {'Framework':<30}{'Total':>6}{'Passed':>8}{'Failed':>8}{'Skipped':>8}")
    for s in summary:
        print(f"  {s['framework']:<30}{s['total']:>6}{s['passed']:>8}{s['failed']:>8}{s['skipped']:>8}")
    print(f"  {'Area':<30}{'Pass':>6}{'Fail':>6}{'Not assessable':>16}{'Not applicable':>16}{'Score':>7}")
    for a in summarize_areas(results):
        print(f"  {a['area']:<30}{a['pass']:>6}{a['fail']:>6}{a['not_assessable']:>16}{a['not_applicable']:>16}{(str(a['score']) + '%') if a['score'] is not None else 'n/a':>7}")
    print(f"  Results written to {out}")


def run_dirs_from_args(args: argparse.Namespace) -> list[Path]:
    dirs = [Path(d) for d in (args.run_dir or [])]
    if args.last_run:
        last = Path(args.last_run) / "last_run.json"
        if not last.exists():
            sys.exit(f"{last} not found - run entra_collect.py first")
        dirs += [Path(r["run_dir"]) for r in json.loads(last.read_text(encoding="utf-8"))["runs"] if r.get("status") == "ok"]
    if not dirs:
        sys.exit("give --run-dir (one or more run folders) or --last-run <output-dir>")
    return dirs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", nargs="+", help="one or more run folders created by entra_collect.py")
    ap.add_argument("--last-run", metavar="OUTPUT_DIR", help="check every company of the latest batch listed in OUTPUT_DIR/last_run.json")
    ap.add_argument("--emergency-access-ids", default="", help="extra break-glass object IDs (comma-separated); per-company ids come from companies.json")
    ap.add_argument("--excel", action="store_true", help="also write enriched/check_results.xlsx in each run folder")
    args = ap.parse_args(argv)
    extra = [x.strip() for x in args.emergency_access_ids.split(",") if x.strip()]
    for run_dir in run_dirs_from_args(args):
        if not (run_dir / "raw").is_dir():
            sys.exit(f"{run_dir}\\raw not found - run entra_collect.py first")
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")) if (run_dir / "manifest.json").exists() else {}
        print(f"\n== {manifest.get('company_name', run_dir.name)} ({manifest.get('company_id', '?')}) ==")
        check_run(run_dir, extra, args.excel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
