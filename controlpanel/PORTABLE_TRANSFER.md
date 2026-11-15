# Portable user transfer (W8U)

Status: implementation and targeted acceptance in progress; do not use on production yet.

This path imports users into an independently initialized, empty VPN Control registry. It retains the destination admin account, vault key and topology. It transfers exact logins, credential history/status, protected master_user and template/profile links. It does not restore a source system, admin sessions, TLS/SSH keys or runtime paths.

## Preconditions

- Linux, protected first-start staging; root-controlled worker policy and the ordinary installation lock. No existing destination users/master/custom template catalog. Existing records are a conflict, never overwritten.
- Destination VPN/bootstrap configuration, registry init and independent admin already prepared. Worker policy owner_run is a newly chosen destination UUID, reused on retries.
- Preserve the original connection endpoint/domain/ports and necessary trusted TLS setup to keep old client profiles usable. Moving users alone cannot preserve connectivity if those parameters change.
- Keep sufficient free disk on registry, state-journal and auth filesystems. Import checks actual available space. Retain the source export and private staging until import/recovery completes.

## Owner export and verification

Use the existing authenticated owner `vpnctl backup create --label portable --idempotency-key UUID --json`, inspect the operation/backup receipt, then `vpnctl backup download BACKUP_ID --output /PRIVATE/export.jwe --sha256 CIPHER_SHA256`. The configured public recipient is used by the source worker. Keep recipient RSA private key off the source and destination runtime.

On the owner's protected Linux recovery host use existing `vpnctl backup offline-verify` with envelope/private-key, authenticated ciphertext/manifest SHA, source owner/operation UUIDs and explicitly trusted source-root/wrapper policy (see `backup offline-verify` implementation). It creates NEW private verified staging. Preserve the staged standalone source state.db and vault.key as protected import input; do not install either as the destination registry/key. Recipient RSA private key is not needed by portable preview/import.

## Preview and import

Commands below run under the existing installation writer lock. SOURCE_DB and SOURCE_KEY are the authenticated private immutable staging files; SOURCE_OPERATION identifies the backup captured inside that DB. DEST_RUN is the destination policy writer UUID.

```sh
vpnctl portable preview --installation lab \
  --source-db /PRIVATE/source.db --source-key /PRIVATE/source.key \
  --source-owner-run SOURCE_RUN --source-operation SOURCE_OPERATION \
  --destination-run DEST_RUN
```

Review `users_preview` (exact login/status/kind/protected/profile_count), `replace_initial_template_catalog`, `plan_sha256` and `installation_sha256`. Replacing the pristine bootstrap catalog/auth is explicit; a non-pristine destination is refused.

```sh
vpnctl portable import --installation lab \
  --source-db /PRIVATE/source.db --source-key /PRIVATE/source.key \
  --source-owner-run SOURCE_RUN --source-operation SOURCE_OPERATION \
  --destination-run DEST_RUN \
  --plan-sha256 PLAN_SHA --expected-installation-sha256 INSTALLATION_SHA \
  --replace-initial-catalog
```

Success reports `verified_cutover` only after active/disabled probes, exact-state checks and existing journal completion. Disabled/deleted users are never temporarily activated. Source credentials are reencrypted with the destination key; source admin/key/topology are not adopted.

## Safe failure and retry

Wrong key, corrupt export, stale preview and occupied destination are refusals. Do not edit journals, reset keys, mark a migration verified or blindly rerun export/import to hide a failure. After a partial application preserve the same source/plan/destination UUID and inspect the protected existing journal. Explicitly repeat the exact import command with `--resume`; only the bound operation and known before/after state can continue. Ordinary writer admission remains closed until finalization. Completed replay must return the same operation without another apply.

After successful acceptance and any necessary replay, remove owner-controlled plaintext staging according to its custody policy. The import never deletes caller-owned source inputs. Preserve ciphertext/private recipient key in separate protected owner custody. No secrets belong in Git, reports, argv values or public logs; file paths and receipt hashes are not passwords.
