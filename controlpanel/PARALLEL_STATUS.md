# Parallel development journal

## 16.11.2026 — rc2 published and public command verified

**U: W9U3/5 · W10U1/4. E: W8E3/8 reused, no new gate closures.**
`v0.4.0-rc2` artifactc5f74fc, clean core8d9b87c/schema8 published; main README/
GUIDE command updated byf9e8596 without merging WIP into stable code. Public
bootstrap/fullZIP/checksum and encoded loader URL/SHA verified; actual public
command reaches first master prompt in PS5.1/7 from a new directory, stopped
before SSH target. [Release evidence](RELEASE_RC2_2026-11-16.md).
F1/F2/F4 ready with stated local/provenance boundaries; **F3 remains OPEN** for
owner manual cleared-node install→old VPN→owner login→create→download→TCP/UoT.
Owner confirmed checked JSON; recheck freshness before destructive steps. No
production actions. Further implementation paused; next action is owner's F3,
not next W10U development. Earlier publication-pending entries are historical.


## 16.11.2026 — rc2 release preparation (current priority)

W9U3/5 (02,04,05), W10U1/4 (03); W8E3/8 reused, E unchanged.
Further development paused at owner's request. Clean runtime8d9b87c/schema8,
installer71fc540, verified final ZIP and actual release ELF acceptance PASS.
[Release provenance, tests and limits](RELEASE_RC2_2026-11-16.md).
Full exact Go suite, Q13 JSON/master compatibility, actual owner CRUD/TCP/UoT,
canonical restart/config rollback and Windows/Linux launchers PASS. No production
changes; rc1 unchanged. Next: publish rc2 and verify public bootstrap/full ZIP;
then owner manual F3 on independently cleared nodes. Do not resume portable or
next W10U development before this release result. Historical next-task entries
below are superseded by this release priority.


## 16.11.2026 — whole U acceptance

W9U04 complete: lead_coder owner_password controller70c980c/fixture37d97b5,
actual916043 canonical-derived restart/badstartup/configrollback/owner+TLS+
old-controlTCP-UoT PASS,11mocksPASS0.048s. Architect reviewed each mount/root/header
adaptation, no product weakening. Main independently checked publicunitSHA from
GitLF, unchanged537core, typedreceipt and completed-unit cleanup. All keepers/
runtime dirs/activeunits removed; no production. W9U3/5, W10U1/4; E unchanged.

Main: actual normal/fault runtime916001 PASS; final5374923 build/API1.312s,
owner API CRUD controller41d05d1 PASS; resources OS/API/CLI/browser/stale/refresh
PASS; final auth6.447s/CLI0.033s/inventory0.063s PASS; cleanup observed.
lead_coder local_observations: CPU/network a328910 + diagnostic-test5374923,
targetPASS0.593s, all191 source Git blob hashes MATCH, no remaining WIP.
lead_coder owner_password: readonly browser adapter6121f3c/0bc42c9,
8mocktestsPASS0.049s; synthetic owner-parent0700 fixe45cb7f, no policy weakening.
architect security: adapter contract/concrete guard review complete; required
canonical socket/unit recheck fixed and reviewed, local execution clear.
explorer next_whole_u: readonly code triage complete; W9U04 canonical restart
is the smallest remaining whole local candidate, current proof gap is explicit.
No nested agents/heavy parallel runs/production changes. [Current ledger](U_ACCEPTANCE_2026-11-16.md).

## 16.11.2026 — локальная ночная U-очередь

[Итоги и доказательства](U_NIGHT_RESULTS_2026-11-16.md). Независимые bounded-пакеты:
coder profile_filename — complete `70626a2`, target PASS0.540s;
lead_coder local_observations — complete `daa33d0`/`fdd0c1d`, API/CLI PASS;
lead_coder owner_password — AUTH04 complete `4d40278`/`8a25436`/`216c721`,
full auth4.203s/CLI79.796s, CLI target0.015s PASS; readonly AUTH03 `abc0876`;
final code/header `8c0309b`, full auth7.251s/identity CLI0.012s PASS, lab free;
architect security — AUTH04 contract/final review complete, no blockers.
Main — inventory timestamps/order `f70bd62`, storage0.070s/owner API0.964s PASS.
Без nested agents и параллельных тяжёлых прогонов. Новых E-gates/production
изменений нет; опубликованный rc1 не заменялся. Старые строки ниже — история.


## 2026-11-14 — approved round 1, integrated portable checkpoint

Owner approved PARALLEL_PLAN_2026-11-14 and automatic ASTRA escalation.
Every progress/final report includes completed deliverable steps and agent status.
Steps are package deliverables, not tool calls or Wn gate completion.

Baseline84c5262; Lead contract/checkpoint4bdd985. Two independent branches:
SOL-A work/w8-restore-20261114, SOL-B work/w8-security-20261114, each in its
own worktree. Integrations were sequential, existing commits retained as Git
checkpoints. Tracked changes clean before integration; foreign BACKLOG untouched.

| Agent | Completed steps | Result / current status |
|---|---|---|
| SOL Lead | 4/4: isolation/checkpoint, portable runtime, integration contract, review/integration | Integrated 4d64384; 13 targeted tests PASS; local Linux chosen, admin enable/reboot pending |
| SOL-A | 3/3: reuse/interface, portable artifact checks, verification/report | Source6dde629 -> integrated7e0d761; 8 tests PASS, reviewed by B and Lead; package done, runtime proof pending |
| SOL-B | 3/3: SEC inventory, fixture checker, verification/report; next mapping2/2 | Source2ba7245 ->7ff71f5; report7fdb84e ->4d64384; 5 tests PASS, 22-ID mapping done; A final review PASS limited scope |

Lead contract was independently reviewed by BOTH A and B: no blocking findings.
A independently reviewed B fixture-only code: no blocking finding within scope.
B independently reviewed A and reran final8 tests; Lead reran integrated13.
Review findings corrected before integration: whole-archive buffering, leaf
FD/single-link/identity checks, inventory owner/mode/unlisted-member checks and
Windows binary read mode. Parent/concurrent hostile mutation protection and
GNUtar PAX/xattr producer compatibility remain explicitly unproven. Artifact
checks never set registry consistency, persisted verified status or restore PASS.

Targeted command: bundled Python unittest discovery tests/test_w8_*.py.
Result at4d64384: Ran13, OK, no skips (0.673s). A includes19 artifact-negative
cases + existing-envelope wrong-key/tamper; B covers fixture metadata only.
Windows runtime Python3.12.14 / SQLite3.53.1 / cryptography50.0.2, no installation.
Linux identities/namespaces/CGO/live restore/full suite/resource peaks: NOT_RUN.
Full release/gate suite not claimed or rerun for this limited helper checkpoint.

Existing audit gap map found SEC15/16/17/19/20/21 absent, plus missing actual
API/frontend/worker identity and current restrictive capability coverage. Human
collector labels are not stable SEC IDs. Never run collector blindly on live VDS.

## Local Linux decision

Owner has only production VDS and asked Lead to choose local or production.
Lead selected local WSL2 first. Verified Windows10 Pro19045, firmware virtualization
and SLAT true,32GiB RAM; WSL/VirtualMachinePlatform disabled. Windows admin token
required for enabling, then manual reboot; unsandboxed tool is not admin.
[Concrete next step and reversal](LOCAL_LINUX_RUNNER.md). No features installed,
UAC prompts launched, reboot or production fallback performed. This environment
step is not an ASTRA bug escalation and does not invalidate portable test results.

W6 3/4, W7 3/4 unchanged. Three phone profiles connect; alpha13 owner login on
Wi-Fi confirmed. Deferred ChatGPT/Download Manager issue remains deferred.
W8 preparation is not G8 acceptance and does not supersede missing G6/G7 evidence.
No production access, deploy, stop or CRUD in this round. E1 not released.

## Automatic ASTRA routing log

Cases routed:0. Failed corrective attempts on current cases:0.
A first local import error was fixed successfully on first correction; ordinary
review iterations are not failed fixes. Worktree sandbox-path denials resolved
with authorized local escalation are also not bug-fix attempts.

For each ASTRA case record ID/date, originating agent, affected task, reproducible
symptom,3 failed corrective attempts/SHAs, sanitized evidence, ASTRA agent/model,
analysis/result, Lead decision, final test and limitations. No secrets/raw owner
artifacts. Count across the team. After third failed SOL correction pause that
case and start ASTRA in a freed slot (max2 concurrent Subagents). Analysis does
not reset the count; after a fourth failed correction stop/report to owner.

Final environment-plan review: SOL-B1/1 independently approved LOCAL_LINUX_RUNNER.md, no blocking findings; commands not executed. Agent tasks idle after completed portable packages/reviews, awaiting actual local environment step; no background production work.

14.11.2026 — владелец явно согласовал локальное развёртывание WSL2. Lead выполнил проверенный SOL-B1/1 скрипт через Windows UAC: Microsoft-Windows-Subsystem-Linux и VirtualMachinePlatform Disabled→Enabled, оба RestartNeeded=true; отдельный CIM подтвердил InstallState1, helper завершён. -NoRestart соблюдён, автоматической перезагрузки нет. Receipt и SHA/порядок продолжения — [LOCAL_LINUX_RUNNER.md](LOCAL_LINUX_RUNNER.md), raw receipt вне Git в worktrees/wsl-setup-20261114/receipt.json. Lead local runner1/3 (компоненты), distro/systemd и runtime tests ещё не выполнены; SOL-A3/3 portable завершён/idle, SOL-B3/3+mapping2/2 завершён, дополнительное review установки1/1 PASS; ASTRA0/failedfix0. Production не затронут. Первое следующее действие — владельцу сохранить работу и вручную перезагрузить Windows, затем сообщить о возврате; Lead проверяет WSL engine/distro и продолжает стенд. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN, G8 не принят.

## 2026-11-14 — post-reboot local lab installed

Owner confirmed manual Windows reboot. Both optional features enabled and
HypervisorPresent=true. Old inbox WSL lacked --version; installed official stable
microsoft/WSL3.0.5 (not prerelease), MSI exit0, AuthenticodeValid Microsoft,
SHA2562313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa.
No automatic reboot. SOL-B independently reviewed install/config scope.

Created only NEW VPNControl-Lab, WSL2 Ubuntu24.04, under
C:\AllFiles\SoftWare\VPN\Amnezia\CodexVPN\worktrees\wsl-lab-20261114.
Official Canonical image356736729bytes, SHA256
2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934 verified
by SOL-A and Lead. Rootfs/installer/source manifests/receipts/logs are outside Git
in worktrees/wsl-setup-20261114. Existing distro inventory was empty.

Preserved original /etc/wsl.conf in new distro. Enabled systemd, disabled automatic
Windows drive mounts/interop/Windows PATH append; restarted ONLY VPNControl-Lab.
This reduces accidental hostfile exposure, not a hostile-root boundary against
Windows. No real owner materials copied. One trailing CR in a PowerShell-piped
script caused final cat to fail; config was then reread and validated directly,
no repeated feature/install changes. First correction successful, failedfix0.

Observed WSL3.0.5.0/kernel6.18.58.1, Ubuntu Python3.12.3/cryptography41.0.7,
SQLite3.45.1, GCC13.3.0; signed Ubuntu apt installed build-essential/pkg-config/
python3-cryptography/nftables/CA packages, exit0. Exact Go1.27.3 installed in
/opt/vpn-control/toolchain/go (CGO_ENABLED1/CCgcc observed, actual CGO build pending).
Official Go archive70588678bytes SHA256
65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 verified
by SOL-A and Lead before use. No Go network modules fetched.

Base runtime observations PASS: PID1systemd; no /mnt/c mount or Windows PATH;
unshare network/mount/PID available, nft list in private netns succeeds; real
systemd transient PrivateNetwork/UID65534/CapEff0/NoNewPrivs1 job succeeds.
Pinned tracked source e263338 transferred via binary stdin (no untracked BACKLOG,
secrets or Windows mount) to /opt/vpn-control/src-e263338. Linux targeted W8
suite Ran13 OK/no skips0.771s. This is NOT full Go/Python product gate evidence.

Lead local runner2/3 done: features + engine/distro/tooling; third product harness
qualification PARTIAL (base checks PASS). SOL-A Ubuntu artifact2/2 and Go artifact
2/2 done; SOL-B install review1/1 and distro config review1/1 done. Previous
portable A3/3/B3/3+mapping2/2 unchanged. ASTRA0, failed corrective attempts0.
No production access/downtime/CRUD/deploy and no Windows reboot by agent.

FIRST NEXT ACTION: qualify existing RootDirectory/LoadCredential/API Unix socket
harness on this lab, bring verified module proxy (repository go.sum+mod verify),
exact Caddy/Naive/SFA engines and run required pinned product tests. Actual restore,
security identity matrix and disk/RAM peak remain open. No new gate accepted:
W6 3/4/G6OPEN, W7 3/4/G7OPEN, G8OPEN, E1 unreleased. Local lab install succeeded;
no further Windows action required now. Start interactively: wsl -d VPNControl-Lab.

14.11.2026 — local qualification checkpoint: pinned e263338 tracked source in VPNControl-Lab, offline GOPROXY=file:///opt/vpn-control/proxy (3 exact modules/9files), GOSUMDBoff/GOTOOLCHAINlocal/GOFLAGS-p1-modreadonly. Baseline go test -count=1 ./... PASS all packages, actual CGO SQLite build works. Initial and post-build mod verify PASS; go.sum compared to repository. This baseline did NOT enable Caddy/Naive/SFA exact-engine opt-ins and was not launched under PrivateNetwork; it is NOT the required final network/full acceptance suite. Those remain pending under separate systemd-run PrivateNetwork=yes.

Lead minimal harness portability patch03f627a replaces only two /usr/bin/python3.14 paths with /usr/bin/python3; SOL-B independent review PASS, frontend AST PASS, protections unchanged. Dependency/report integrations3137669/f9a4360/9676d20; SOL-A inventory3/3 + official sing-box1.14.4 acquisition2/2 verified archive699a1b...f7c24968, existingalpha13 identified. Read-only Lead scp attempt for public Caddy binary failed SSH publickey; no server change, no authentication change/retry. Local pinned Caddy build started by SOL-A after baseline finished, no concurrent heavy tests. Next action — finish builder/manifest, stage binaries + reviewed revision in NEW run directory, then actual RootDirectory/API/frontend/full exact-engine tests. Lead runtime qualification still PARTIAL, W6 3/4/G6OPEN/W7 3/4/G7OPEN/G8OPEN. ASTRA0/failedfix0, no production mutations. See PARALLEL_STATUS and reports/W8_LOCAL_DEPENDENCIES.md, reports/W8_LAB_HARNESS_REVIEW.md.

14.11.2026 — local runner3/3 квалифицирован, [полный протокол](W8_LAB_QUALIFICATION_2026-11-14.md). Pinned78515f4: полный Go с Caddy/Naive/двумя SFA/DNS в PrivateNetwork PASS, Python82/skipped4 PASS, RootDirectory frontend8202 UID981/CapEff0/denials/privateAPI/TLS PASS, actual ownerCLI/3privateprofiles/freshTCP-UoT PASS. Полная mutation/rollback/reconcile/installer-return копия8204 PASS. Go mod verify и go.sum repo hash PASS. Интегрирован независимо проверенный raw-tar guard2ae9706; полный Linux Python84/skipped4 PASS, Goкод/deps785..2ae не менялись (reuse, не новый прогонGo). Копии8201/8202/8204 inactive/MainPID0;8201 прерван и не PASS,8203 частичный после преждевременной подготовки/ETXTBSY сохранён. Нет оставшихся продуктовых процессов. Локальная identity981 provisioned locked/nologin; все защиты сохранены. Подробные причины/первые успешные исправления/WSL keeper и ограничения в протоколе. Caddy локально побайтно совпал с историческим hash; read-only scp attempt был отклонён publickey, production не менялся.

Lead3/3; SOL-A inventory3/3+singbox2/2+Caddybuild3/3+rawguard3/3 завершены; SOL-B portability3/3+suite2/2+Caddyreview1/1+rawreview2/2 завершены. ASTRA0/failedcorrections0. Первое следующее действие — W8 canonical snapshot/DB-generation/vault binding и совместимый producer/restore proof через существующие механизмы. Прототип не ставит verified; PAX/ACL/envelope streaming/usablebackuprestore/полныйdisk+RAM gate открыты. W6 3/4/G6OPEN, W7 3/4/G7OPEN, G8OPEN, E1 не выпущен. Приёмка локального runner не закрывает продуктовые gates.

14.11.2026 — roadmap steering985e04a получен обоими SOL-агентами. G9=components, E1 additionally G9.1; W8→W9→W9.1sixsteps0/6. Scope/ownership/production approvals неизменны. SOL-A raw guard boundary fixtures3/3 fa6c55a,11testsPASS pendingLeadintegration; SOL-B canonical snapshot binding inventory2steps в работе. ASTRA0.

14.11.2026 — продолжены именно W8-задачи после roadmap985e04a: SOL-A raw count/size/end fixtures3/3 sourcefa6c55a→d576dcc, target11testsPASS на bundledPython3.12.14 после интеграции; SOL-B canonical binding inventory2/2 source6d92468→8202ed1, source-backed report-only. Lead уточнил W8_INTEGRATION_CONTRACT: общей scalarDBgeneration нет, manifest/peruser/pernode версии различны, Open мигрирует, auth/session/issuance не считать остановленными одним installationflock; callback/onlinebackup/проверки остаются реализацией W8/1. Новых BKP endpoint/verified/acceptance не заявлять. W9/G9 принимает компоненты, общийE1 требуетG9.1. Первыми по-прежнему W8/1 и связанные проверки, не installerW9.1. W6 3/4 · W7 3/4 · W8 0/4 fullyclosed(partial1–2) · W9 0/4 · W9.1 0/6. ASTRA0/failedfix0, production не менялся. Полный productнабор не повторялся для test/report/contract-only группы; прежние квалификационные результаты774c07a сохранены.

14.11.2026 — ПАУЗА по явному запросу владельца (лимиты). [Точка возобновления](RESUME_W8_2026-11-14.md). WIP fcea3d4 сохраняет Registry.InspectSnapshot + shared vault/migration refactor; НЕ скомпилирован/НЕ протестирован/не к deploy. SOL-B review emptyownID blocker исправлен первой попыткой, повторное review PASS. Независимые SOL-A tests3a1882c/2596b40 сохранены в restorebranch, НЕ интегрированы/НЕ запускались; перед запуском нужны fixture corrections(master отсутствует в mutationFixture, CHECK/FK corruption setup, согласование typederror). Агент A прерван, B idle, новых заданий/прогонов до возобновления не запускать. Первое следующее действие после нового транша — исправить эти fixtures, определить ErrSnapshotState wrapping, составить pinned candidate+tests и выполнить targetstorage/общиепотребители на локальной копии. GoWIP не покрыт прежним полным набором. E1 6/11; W6 3/4 · W7 3/4 · W8 0/4fullyclosed · W9 0/4 · W9.1 0/6. ASTRA0/failedcorrections0. Production не менялся.

14.11.2026 — возобновлено по запросу владельца, глобальный C:/Users/a.filatov/.codex/AGENTS.md прочитан. Tool-presets подтверждают explorerLunaHigh/coderSolLow/lead_coderSolMedium/architectAstraMedium; coder и lead_coder реально запущены для текущих независимых задач, explorer/architect без необходимости не запускались. Настройки модели главного чата инструмент не раскрывает/не менялись. Новая маршрутизация coder2неудачныхfix-validation→lead_coder, lead_coder3→architect; старое ограничение владельца4неудачныхисправления однойпроблемы сохраняется как stop, счётчики не обнулять между ролями. Без nestedagents, минимальные контексты/непересекающиесяфайлы; сейчас2субагента.

Кодер snapshot_fixtures_resume исправил тестовыеfixtures master/CHECK/FK/tombstone, source84e70f5→fa803e8; Lead отформатировал c4bf7bb. Ошибки credential проверки классифицированы черезerrors.Join(ErrSnapshotState,err) b50cd99, независимоеlead_coder reviewPASS. Первые Snapshot target tests наc4bf7bb в локальномPrivateNetwork PASS (8именованныхтестов+subcases,1.422s). Код/тесты прежнегоWIP впервые скомпилированы. Сейчас Go-потребители общейvault/migrationлогики запущены; полныйPython/исследования неизменённой среды не повторялись. Production не менялся. Snapshot helper НЕ создаётbackup и не повышаетverified, общийDBgenerationне введён; следующийшаг после потребителей — actualonlinebackup/stagedDB+file binding подпрежнимlock. W8 0/4fullyclosed; G6/G7/G8/G9/G9.1 открыты, E1 6/11. Architect/ASTRA0, неудачныхfix-validation0.

14.11.2026 — завершён проверенный подшаг W8/1 snapshot inspection. [Протокол](W8_SNAPSHOT_INSPECTION_2026-11-14.md), pinnedc4bf7bb: targetSnapshot8именованных+subcasesPASS; все затронутые Goпотребители ./...count1 сCaddy/Naive/обеимиSFA/DNS вPrivateNetworkPASS. Старый WIPfcea теперь покрыт этими тестами. Кодер3/3fixtures послеLeadintegration/validation; lead_coder1/1independentsecurityreviewPASS; orchestratorintegration/target/consumersPASS. Роли explorer/coder/lead_coder/architect подтверждены tool-presets, запущены только необходимые coder/lead_coder; mainmodelsettingsнеподтверждаем/неменяем. Не повторяли прежние исследования/Python/неизменённые runtimeсценарии; consumerповтор нужен иззаобщегоvault/migrationrefactor. Productionне менялся, architect0, failedfix-validation0. Следующее действие — actualSQLiteonlinebackup/capturedDB+managedfilebinding под прежнимwriter, не считатьpreflight гарантирующим будущуюкопию. W6 3/4·W7 3/4·W8 0/4fullyclosed(partial1–2)·W9 0/4·W9.1 0/6. E1 6/11, все последующиеgatesостаютсяOPEN.

14.11.2026 — завершён подшаг W8/1 SQLiteonlinecapture. [Протокол](W8_ONLINE_CAPTURE_2026-11-14.md). lead_coder3/3 one-file implementation62d44b3→e0eef09, coder3/3 independentfixtures0760583/ebc33e8→c065132/5b01836, orchestrator review/integration/actualLinux testsPASS. Initialtargetadd2d78PASS; finalpinned5b01836 fullaffectedstoragePASS5.297s includingexternalWALwriter+20MiBcut, standaloneimmutableDB/SHA/size/permissions/uniqueoutputs, cancel/unfinished/unsafeparent/oversizecleanup. No newcapturetestskips; storage-onlyrun skipped3unconfiguredSFAchecker subcases+subprocessguard, notnewfull-engineproof. Priorc4bf7bb exactengineconsumerresults reused for unchangedcode, no routinePython/fullGo/runtime repeats. Productcode/dependencies/units outside newfiles unchanged. Capture validates copiedDB, notlivepreflight; outputprivateplaintextstaging only, no backupverified/API/queue/restore claim. PrimarySQLiteAPI semantics documented; tests firstattemptPASS, failedfix-validation0/architect0. Новые правила эффективности приняты: focusedreads/output, no unnecessaryagents/retests. Production не затронут. W8 0/4fullyclosed(partial1–2); E1 6/11, W6 3/4 W7 3/4 W9 0/4 W9.1 0/6. Первое следующее действие — capturedDB+managedfile hashes/generation/owner-run под существующимwriter, затем encryptedartifact/operationmetadata через прежние механизмы.

14.11.2026 — W8/1 binding подшагPASS, [протокол](W8_BINDING_2026-11-14.md), pinnedbf04c54. СуществующийwithOwnedInstallation/lock переиспользован1раз, actualcopiedDB проверяется с observedvaultkey иcanonicalowner-run; boundedSHA observations manifest/auth/manifest.Files/key до/после, отказpending/prepared/unsafe/drift, удаление толькоnewchild сошибкамиcleanup. ОбщийverifyOwnedFiles потоковый, без snapshot32MiBpolicy дляобычныхmanagedfiles;33MiBcompatregressionPASS, typedLegacyDrift сохранён. Targetcmd2.495sPASS +5directstoragekey/owner casesPASS; fullaffectedGo ./...count1 сCaddy/Naive/обеимиSFA/DNS вPrivateNetworkPASS (CLI85.931s,storage7.334s). Первыйtargetb511failed иззаневерногоfixturebasename; coder5cb43c2→bf04c54 исправилпервойпопыткой безослабленияguard. lead_coder3/3, coder3/3, orchestratorreview/integration/validationdone; architect0/failedfix-validation0. ФайлыmanagedещёНЕскопированы/НЕзашифрованы, liveCaddyfreshness/backupverified/endpoint не заявляются. SourcecanonicalOpen сохраняетсвоюmigrationполитику, неиспользоватькакpre-upgradelegacybackup. Следующее действие — copyingobservedfiles+existing_envelope sealing втомжепрежнемwriter callback, проверитьcopiedbytes; не nestedflock и неcopyafterunlock. W8 0/4fullyclosed, E1 6/11; W6 3/4·W7 3/4·W9 0/4·W9.1 0/6, G8 не принят. Productionне менялся; Python/неизменённыеruntimeпроверкинеповторялись.

14.11.2026 — W8 integration checkpoint b67290b (не G8). Schema8/maintenance f9f579c+297d770, streaming JWE 4b0f37e/7f7305f, writer-bound archive90f30fa, canonical readonly verifier fafc865, safe inventory be625db. Target integration on pinned b67290b in local VPNControl-Lab / PrivateNetwork PASS: storage Maintenance/admission1.454s, CLI archive/snapshot/owner targets1.080s; API compiled, selected pattern matched no API tests (not endpoint acceptance). Separate SOL tests: maintenance0.472s PASS, archive targeted PASS, safe Python collector12tests PASS. Both admission orderings + separate SQLite connections covered; immutable per-attempt owner attestation preserves earlier successful restore proof. All22 audit checks normalized, unknown/not_run and destructive skips remain honest; safe inventory alone is not full audit PASS. Archive currently refuses xattrs/ACL explicitly, restore support remains open. API/CLI/worker create/verify/download/cancel/prune wiring requires actual runtime proof; no verified artifact/restore/G8 claim.

Lead integration in progress. SOL-A streaming3/3+archive3/3 done, offline restore verifier in progress. SOL-B maintenance3/3+safe inventory3/3 done. Planned ASTRA case W8-SEC-001 reviewed crypto/schema/CAS/restoreprep; review corrections applied (immutable evidence, reverse admission, bounded helper stdout). Debugging escalations0, failed corrective attempts0. Production untouched. W8 0/4 fully closed (partial1–2), W6 3/4 G6OPEN, W7 3/4 G7OPEN, W9 0/4, W9.1 0/6; E1 6/11 and unreleased. FIRST NEXT ACTION: authenticated offline restore verifier and NEW-root normalization, actual owner API/CLI encrypted backup roundtrip, copy-only vault rotation, resource/identity matrix and required pinned full suite. Continue through W8 per owner; no pause/checkpoint-as-completion.

## 15.11.2026 — PAUSED: актуальная точка передачи

Владелец явно остановил разработку 14.11; новых разработок/тестов 15.11 не запускали. Сохранение точки после остановки было прервано лимитом automatic approval review; теперь незавершённые файлы сохранены: main bf6f693 (vault rotation WIP, НЕ compiled/tested) и отдельный c99e9b0 (API/worker tests WIP, итоговый PASS не получен). Последняя функциональная интеграция fc2ec74. Полная передача: [HANDOFF_W8_2026-11-15.md](HANDOFF_W8_2026-11-15.md); готовый [промпт продолжения](CONTINUE_W8_PROMPT_2026-11-15.md). Эта запись отменяет прежнее указание продолжать без паузы до нового разрешения владельца.

Дополнительно подтверждено до остановки: pinned b67290b Python18tests PASS2.556s; SOL-A verifier0bc5513→fc2ec74 targeted PASS, интегрированный full suite ещё не запускался. W8 0/4 fully closed, G8OPEN; E1 6/11, W6 3/4/G6OPEN, W7 3/4/G7OPEN, W9 0/4, W9.1 0/6. Lead остановлен; SOL-A streaming/archive/verifier по3/3, ACL/xattrs ещё не реализованы; SOL-B maintenance/inventory по3/3, новые API/worker tests WIP; ASTRA1 planned case W8-SEC-001, debugging escalations0/failed corrective attempts0. Остаточные тестовые процессы WSL не считать подтверждённо остановленными: финальная read-only проверка до обрыва не вернула наблюдение. Production не менялся, push не выполнялся, BACKLOG не затронут.

FIRST NEXT ACTION после явного возобновления: читать состояние собственных тестовых units, review двух WIP testfiles c99e9b0, подготовить новый pinned candidate и выполнить целевые API/worker tests; параллельно независимый ACL/xattr пакет по HANDOFF. Не начинать с повторного исследования/переустановки стенда. Restore preparation/rotation/version handling/prune/audit/full restore/resources/полный G8 остаются открыты.

15.11.2026 resumed: SOL-A ACL/xattrs3/3 targetPASS3.417s integrated6f89bfb; SOL-B ownerAPI/worker fixtures done, restore preparation+security negatives13PASS1.584s and encryptedCLI preparePASS2.025s done03bb43f; SOL-C rotation5namedPASS0.513s then inner harness fe84121/c73fdae completed, now actual vertical runtime runner; Lead offlineCLI/integration/host runner2df0c9a. ASTRA W8-SEC-002 planned consequential review addressed code findings; exact runtime acceptance pending. No nested agents or production changes. Fixture failures corrected on first targeted corrections; no unresolved four-fix error.
