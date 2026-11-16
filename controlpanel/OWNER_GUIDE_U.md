# Owner guide — local U candidate, 16 November 2026

Release applicability: v0.4.0-rc2, clean runtime8d9b87c/schema8. Use the fresh-install command in [README](../README.md). [Package checks and limits](RELEASE_RC2_2026-11-16.md). Prior candidate references below retain their evidence scope.

Applies to the development candidate with runtime source `5374923` and acceptance
controller `41d05d1` for CRUD and `70c980c` for service restart. Published
`v0.4.0-rc1` still contains runtime `0c05a61`;
the newer features below need a later packaged deployment. No production upgrade
is authorised by this guide. Fresh-install owner checks remain in
[FRESH_OWNER_ACCEPTANCE.md](FRESH_OWNER_ACCEPTANCE.md).

## Owner workflow

1. Connect to the VPN, then open `https://panel.home.arpa` with the installation's
   trusted panel CA. Sign in using the independent panel owner account.
2. Open **Users**. Create a user with the exact desired login and an approved
   base template/client. Login case is preserved. Wait for **Completed** in
   **Operations** and an **Active** account before downloading a profile.
3. Open the user and choose **Download profile**. The attachment uses
   `vpn-<login>-<client>.json`; unsafe legacy filenames fall back to UUID.
   The downloaded file contains the VPN credential: keep it in a private location.
   Repeated issuance does not rotate the password.
4. A display-name change keeps the immutable login. **Revoke new connections**
   denies new TCP/UoT connections and profile issuance; existing tunnels may stay
   open. **Enable** restores the same credential. **Delete** preserves a tombstone
   and reserves the login. The protected `master_user` has no ordinary mutation
   controls. Check an independent user's connection after a change.
5. **System** shows measured CPU interval, memory, load, registry filesystem and
   network counters, each with its source/time. Network scope is the collector's
   namespace, including loopback; it does not identify per-user VPN traffic.
   After 60 seconds cached observations become **Stale — refresh required**;
   **Refresh local resources** obtains a new sample. Missing data is **Unknown**.
6. **Overview → Stored evidence** shows local registry audit/backup timestamps.
   **Refresh records** reloads them. A saved verification timestamp does not prove
   a successful restore or current exit health. Unmeasured health stays
   **Not measured**. Restore and portable migration are not enabled in this UI.
7. **System → Change owner password** requires the current password and matching
   new values of 12–1024 UTF-8 bytes. Success signs out all owner's sessions;
   sign in again. VPN credentials and the vault key are preserved.

## Existing local CLI channel

Use SSH on the intended node and the installation's actual Unix API socket.
Set `VPNCTL_SOCKET` to that socket and `VPNCTL_SESSION_FILE` to a new session
file inside a private mode0700 directory. Do not put passwords in arguments.

```sh
vpnctl auth login OWNER_LOGIN
vpnctl auth whoami
vpnctl user list --json
vpnctl template list --json
vpnctl system resources --json
vpnctl backup list --json
vpnctl auth passwd
```

Login/password commands prompt interactively. `auth whoami` returns the exact
admin ID/login, role and expiry. For profile download use a private output
directory and a new filename; existing files are never replaced. HTTP404 for an
unavailable profile maps to CLI exit2; authentication/private-file refusal maps
to exit3. A queued operation is a receipt, not proof of successful application.

## Reproduce the local acceptance

Use the already qualified VPNControl-Lab and a **new** source/run directory; keep
the offline Go environment from [HANDOFF_W8_2026-11-15.md](HANDOFF_W8_2026-11-15.md).
Build `cmd/vpnctl` and `cmd/vpn-control` into that source's `rehearsal-bin`.
Use controller revision `70c980c` (includes the earlier CRUD controller and
private UI fixture parent). Choose an unused numeric NEW_RUN_ID >=916041.

```sh
VPN_REHEARSAL_PROJECT="$PROJECT" VPN_REHEARSAL_UI=1 \
  sh "$PROJECT/pilot/run_full_worker_rehearsal.sh" normal "$NEW_RUN_ID"
python3 -B "$PROJECT/pilot/owner_cli_rehearsal.py" "$PROJECT" "$NEW_RUN_ID" --mutations
python3 -B "$PROJECT/pilot/panel_frontend_rehearsal.py" "$PROJECT" "$NEW_RUN_ID" --browser-port 18900
```

For the service restart/failure/configuration-rollback acceptance use the same
frontend rehearsal with `--restart-check` instead of `--browser-port`.
It takes over the bootstrap API in that disposable root; browser view and owner
CRUD must run before it or in a separate new root. Never reinitialise a used
root after a failed attempt. This checks the same-version service/configuration
recovery, not a production upgrade or database downgrade.

Keep an owned foreground WSL keeper while detached units run. The optional
browser view is read-only synthetic localhost transport; real TLS/auth checks
run separately before it starts. On completion remove only that run's `ui-hold`
marker, wait for `MainPID=0/Result=success`, and release the owned keeper.
No production command, node cleanup or portable transfer is part of this recipe.
