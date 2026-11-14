# W8 backup candidate — SOL-A

Baseline 84c5262. Synthetic local preparation only; G8 OPEN.

Implemented bounded read-only inspect_archive over existing G3-SNAPSHOT v1 tar;
no new encryption, daemon, journal, extraction or runtime writes. Authenticated
receipt SHA256 is required from caller. Rejects path traversal, links, duplicate
members, PAX/sparse extension metadata, excessive members/bytes, missing refs,
hash drift, generation mismatch and WAL/SHM companions. Existing g3_snapshot
online backup remains sole snapshot creator; existing owner JWE remains sole
envelope implementation. PAX rejection is deliberately conservative: production
ACL/xattr archives can require extensions; compatibility needs Lead contract.

Verification: bundled Python 3.12.14 targeted unittest: Ran 3 tests, OK (0.466s). Initial discovery found
WindowsApps aliases; Lead subsequently located bundled runtime. No SSH/production/owner materials used.
Failed-fix counter: 0. Step 1 inventory/interface done; step 2 bounded portable
artifact checks done as limited candidate; step 3 portable execution PASS; Linux runner proof pending.

Explicit gaps: wrong-key/tamper envelope negatives need existing envelope runner;
SQLite schema/integrity/generation/unfinished operations and credential binding,
protected master/current/revoked semantics need canonical storage contract and
copy harness. No extraction into staging implemented before those gates. No
owner login/fresh profile/live stack proof, ENOSPC rehearsal, allocated blocks,
RAM/cgroup peak or retention measured. Plan result never means verified/restored.
No status promotion is available in this candidate.
Review revision: chunked SHA256 and member hashing (64KiB), descriptor-only inventory; only G3 JSON retained (1MiB cap). Whole-archive buffering removed. Same opened FD used for hash and tar; parent symlink/hostile concurrent mutation hardening pending. Targeted Python: Ran 5 tests OK (0.748s), 12 parameterized artifact refusals plus existing envelope positive/wrong-key/tamper and bounded-read guard. No failed fixes. Initial claim of streaming in handoff was inaccurate; this revision implements it.
