# W8 backup candidate — SOL-A, integrated status

Date2026-11-14. Baseline84c5262. Source final6dde629, integrated7e0d761.
Package3/3 portable steps complete; G8 OPEN. Reviewed independently by SOL-B
and Lead. No SSH, owner materials or production operations.

Read-only inspect_archive reuses existing G3-SNAPSHOT v1 tar inputs, source
receipt SHA256 and generation. Existing g3_snapshot remains the snapshot creator;
existing owner RSA-OAEP-256/A256GCM envelope remains the encryption implementation.
No extraction, new crypto, daemon, journal, database status changes or live restore.

## Implemented / tested portable boundary

- Chunked64KiB archive/member hashing, descriptors instead of retaining contents;
  only G3 JSON retained with1MiB cap. Archive limit32MiB/member limit4096.
- Path/type/link/duplicate/sparse/PAX/WAL/SHM and excessive-byte refusal.
- Missing refs, hash/generation drift, inventory uid/gid/mode/digest matching,
  nonempty/invalid xattrs and unexpected member refusal. state.db is explicitly
  allowed as an un-inventoried G3 member but is NOT validated as a database.
- Same opened FD, regular/single-link fstat, before/after identity/size/timestamps;
  O_NOFOLLOW only where available and Windows O_BINARY. Private immutable staging
  including parent paths is mandatory; hostile concurrent mutation safety is NOT
  proven. No claim of a second full archive hash after parsing.
- Output only artifact_check_passed, registry_consistency=not_run and pending
  gates. Artifact success never grants persisted verified status/restorable PASS.

Bundled Windows Python3.12.14:8 unittest methods PASS, no skips,19 artifact
negative cases,2 existing-envelope negatives (wrong key/tamper), binary CRLF/ctrlZ
payload, real filesystem hardlink refusal and bounded-read guard. Lead combined
suite at4d64384:13 tests PASS, no skips. No Linux acceptance claimed.

## Explicit remaining limitations

GNUtar --acls/--xattrs can use PAX: current conservative PAX/nonempty-xattr refusal
is NOT producer compatibility. Need reviewed allowlist and actual producer
round-trip. Existing envelope buffers whole payload; end-to-end LLD M-006 remains
open although artifact inspector now streams. Parent-path/Windows adversarial
mutation and Linux O_NOFOLLOW identity checks need actual staging proof.

G3 metadata does not inventory SQLite DB or bind its generation to registry.
Schema/checksums/integrity/foreign keys, credential-vault binding, unfinished and
prepared states, master/protected/current/revoked semantics require canonical
storage checks. No staging extraction, usable owner login/fresh old-profile or
revoked negative proof, ENOSPC/retention, allocated blocks or RAM/cgroup peaks.
These remain pending under W8_INTEGRATION_CONTRACT.md and LOCAL_LINUX_RUNNER.md.

Review corrections were successful; failed-fix count0. Initial local import error
was fixed on the first corrective attempt. An earlier handoff incorrectly called
4285e73 streaming;4d7c1f9 implemented actual chunked inspection. Final source and
integrated test evidence above supersede interim report wording.
