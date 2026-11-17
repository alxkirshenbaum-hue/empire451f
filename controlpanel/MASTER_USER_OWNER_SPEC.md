# Master VPN identity is panel owner — minimal fresh-install contract

17.11.2026. Owner explicitly selected shared VPN/panel master credentials. Architect
master_identity_spec reviewed auth/storage/session/installer; Lead saves this spec
because architect role is read-only. Priority: profile404 release first; this package
second; JSON download UX third. One real clean reinstall after combined package.

## Identity and storage

Exactly one logical administrator: users.login=master_user, kind=service, protected=1,
status=active. Other users remain ordinary and cannot log in to the panel. Users
shows master as every other canonical user. The imported VPN user owner, if present,
remains an ordinary visible VPN account, not an administrator.

Reuse admin_accounts and admin_sessions as authentication/session projection. Admin
id equals canonical master users.id, username=master_user. No independently generated
owner, password or P01-P03 prompts. Add a new migration (never rewrite prior SQL)
with a canonical master binding including credential_id and foreign keys. Insert
validation must require protected service active master and current credential.
Bootstrap obtains existing current master secret through established registry/vault,
hashes exactly those bytes with existing Argon2, saves canonical id/binding/hash in
one transaction under existing writer lock. No new credential plaintext store.
Imported passwords follow current VPN validation, even if shorter than12; no trim,
replacement, automatic rotation or strengthened import requirement. New passwords
continue through current safe generator. Missing master/conflicting owner/binding
refuses; repeat bootstrap succeeds only for identical correct projection.

New fresh API uses strict master-only configuration. Login AND SessionOwner verify
binding, active protected canonical user and unchanged current credential id; drift
fails closed. Actor returned is canonical users.id. Existing session/Origin/CSRF/
throttling/cookie guards remain. Legacy independent owner data is not silently
converted; existing-installation upgrade is outside this fresh package.

Disable independent admin password-change endpoint and remove its form in master
mode: no admin-only password may drift from VPN. Existing master rotate/disable/
delete protections remain. Full common password rotation is deferred; no new saga,
role framework, helper or journal. Shared master profile contains the panel password:
warn briefly at handoff that it must not be shared.

## Installer and download

Initialize reviewed template and stage imported users as already implemented. Bind
missing imported profiles with priority404 fix. Bootstrap master only after its
canonical registry record/credential exists; no secret in argv/session/Git/logs.
At master handoff tell owner same master login/password works for VPN and panel,
with actual panel URL after readiness. Reuse native computer-side SCP transfer.
Offer Q24 subchoice 1 Download JSON (default), 2 Later; yes asks private new local
JSON path and downloads, later prints an executable correctly quoted SCP command
using actual host/port/key options without passwords/tokens/private-key contents.
Keep StrictHostKeyChecking and private local file handling; failure retries download
only, never regenerates credentials or re-applies VPN. Windows and macOS same meaning.

## Targeted checks

Imported short master secret works for VPN/panel; regular user and old owner denied.
One canonical master remains visible/protected; no hidden second administrator.
Bind replay/conflict/credential drift and session/Origin/CSRF guards; independent
password change denied without state change. Alpha13Ru/DM and base downloads for
all imported users preserve credentials. Windows default-yes/later/SCP failure and
paths with spaces; macOS syntax/branch checks, actual macOS not claimed.
One published combined command on software-cleaned authorized hh-entry/hh-exit:
JSON import, no separate owner questions, master login/create/download, exact engines,
TCP/UoT, private trusted HTTPS/public denial, fresh SSH. Preserve reserve and host
routes; no full E/DR/reboot/harness repeats. Update evidence/PLAN after actual result.
