# W8U portable activation — proposed bounded completion package

**Последнее решение владельца15.11.2026:** [W9.5U-Fresh — установить VPN+панель одной командой](PRIORITY_FRESH_INSTALL.md), 0/4, выполнять сразу. Portable export/import и его тестовые расширения отложены; предыдущие зависимости от W8U/G9 ниже отменены для fresh-install. Будущий минимальный перенос допускает plaintext JSON с паролями; сейчас на него время не тратить. Сохранять существующие PASS и WIP.

Base f75d135; discovery/partial adapter d326bcd, independent fixtures697adc2. These commits are NOT U acceptance. Production and E work are excluded. Existing encrypted owner export/download, offline verifier and runtime proofs remain reused per W8_UE_EVIDENCE.

## User path

1. Owner configures public recipient using existing backup configure, then authenticated backup create/download; owner keeps RSA private key off destination/runtime.
2. Existing offline verification authenticates bundle on owner host and creates private staging. Portable preview compares staged source with independently initialized destination DB/key/admin/template catalog, reports conflicts and explicit bootstrap-catalog/auth replacement.
3. Portable import requires exact preview hash and explicit replacement consent; only users, credential history (reencrypted destination key), templates/routing/profile links move. Source admin sessions/accounts, vault identity, topology and system paths do not move. Nonempty destination users/master/custom catalog conflict.
4. A portable-specific branch of EXISTING migration/file journal applies active-only auth and validates/probes Caddy. Only then verified_cutover; disabled/deleted remain unchanged throughout. Failure restores beforeimage or enters existing fail-closed reconcile gate.

## Why existing functions cannot simply be connected

handoff_legacy verifies users/passwords against destination legacy snapshot. CompleteLegacyCutover requires provisioning/v1 and activates every imported user. A clean independent destination has a different bootstrap master/auth; using unchanged legacy assumptions can reject valid import or activate disabled accounts. Candidate-only DB creation is not a completed Import.

Storage review also found that public InstallInitialSFA automatically installs routing variants, while initial portableClean only permits a base revision and rejects variants. Must recognize EXACT canonical generated bootstrap catalog and hash it; custom catalogs still conflict. Existing internal-init-only fixtures must not hide this real-path issue.

## Bounded implementation

- internal/storage/portable.go: exact canonical clean catalog, explicit baseline/consent, atomic transfer and preview conflict report; retain fresh destination admin/key/topology.
- cmd/vpnctl/portable_linux.go and platform stub/dispatch: owner-host preview/import commands, private immutable staging, shared installation lock, receipt/preview binding, no RSA private key on runtime.
- handoff_legacy.py: narrow portable branch in existing journal, binds destination beforeimage + imported IDs/status/currentrefs + active-only afterimage. Legacy branch unchanged.
- internal/storage/cutover.go: portable validation/finalization preserving statuses, no arbitrary markverified, active/disabled probes and finalchecks.
- NEW targeted portable harness/tests, independent security review. No schema migration, daemon, parallel queue/journal, prune, rotation activation or full DR cycle.

## One local acceptance

Independently initialize destination DB/vault/admin/runtime; actual owner export/download→offline verify→preview→import→first start. Privately compare exact-case Alex/alex, passwords/history/status, protected master_user and profile/template joins. Same connection settings: original profile fresh TCP/UoT PASS; disabled credentials FAIL. Wrong recipient key, corrupted ciphertext, stale preview and occupied/master/custom-catalog conflicts leave valid destination and source unchanged. Check available disk and bounded private temp cleanup. Required critical partial-publication test demonstrates beforeimage or reconcile-safe startup. Report SHA+actual targets; no E-gate promotion.

## Authorization boundary

The user explicitly requires approval for a new large implementation or extended-test cycle. Inspection shows one additional activation adapter + CLI/target acceptance group is necessary beyond the initially assumed simple glue. Implementation of that activation group has not started; request approval against this concrete plan. Partial storage code is not usable import and must not be activated.
