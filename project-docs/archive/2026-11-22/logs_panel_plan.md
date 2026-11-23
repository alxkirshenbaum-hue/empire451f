> Исторический документ: installer/controlpanel/PLAN.md. Не текущие указания. Исходные байты сохранены в V001/before; изменены только относительные Markdown-ссылки.

# План разработки панели

## 22.11.2026 — rc10 published / actual full fresh + Q27 PASS

Явно согласованные выпуск и очистка hh-entry/hh-exit выполнены. Artifact e80c2b1,
helper core0af8a3b, exact rc9/schema9 Go ELF reused. CURRENT JSON6 сохранён/сверен,
private snapshots/rollback подготовлены; SSH/ACME/WG сохранены, резерв не затронут.
Полный опубликованный Windows launcher + точный ZIP через -BundlePath: EXIT0.
Q27yes: preflight обеих нод до apply, secure-apply/новые SSH/commit обеих PASS;
ошибка writer после panel handoff устранена. Q28 пропущен при direct exit.
Post: original-key SSH обеих,6 exact credentials, panel_generation/DBintegrity/FK,
скачанный JSON externalTCP/UoTDNS/privateTLS/master200/ordinary401 PASS.
[Протокол и ограничения](../../installer/controlpanel/RELEASE_RC10_2026-11-22.md). Предыдущая запись о локальном
кандидате заменена этим результатом. W9.5U-Fresh4/4, W9U3/5, W10U1/4; E unchanged.
BL-010.7/010.8 (Q28/ProxyJump) и BL-010.9 (ACME/SAN) остаются бэклогом.
Следующее действие: владелец использует новый master JSON/URL; новые U-задачи отдельно.

## 22.11.2026 — SSH hardening после panel handoff: локальный hotfix

По новому реальному проходу владельца rc9: установка VPN/панели и JSON завершилась,
Q27 на exit применился, entry/secure-apply отказал из-за panel_generation, exit откатился.
Прямой SSH обеих нод и exit через entry доступны; Q28 был пропущен, не применён.
Исправляется только ограниченная SSH-транзакция: предварительная проверка обеих нод,
разрешённые SSH/firewall пути, сохранение актуального manifest панели при commit/rollback.
Обычный installer writer guard сохраняется. ProxyJump и явный выбор Q28 записаны
в BACKLOG BL-010.7/010.8; в этом hotfix не реализуются.
Проверки: 7 целевых post-panel security + 9 существующих RenderingTests PASS (16, 0.211s),
существующий WSL Python через временную копию исходников, без доработки стенда.
PowerShell parser и git diff --check PASS. Полный fresh на нодах не выполнялся.
Production/release bundle не менялись. Реальная fresh-приёмка кандидата пока OPEN;
установку и подтверждённые rc9 тесты не повторять до отдельного окна владельца.
W9.5U-Fresh4/4, W9U3/5, W10U1/4 и E сохраняют прежнюю область доказательств.

## 22.11.2026 — rc9 actual master package complete

U current owner package1–5:5/5. W9.5U-Fresh4/4 retained,W9U3/5,W10U1/4; E unchanged.
Supersedes old external-block/current-unavailable notes below. Actual rc9 completed
exit0 and saved full target PASS before prior approval usage limit. Completion now
rechecked SSH/services/schema9/single canonical master/currentCID/FK/private listeners/
trusted certificate; monitors already inactive/unloaded. No reinstall/repeated suite.
[Evidence and limits](../../installer/controlpanel/RELEASE_RC9_COMPLETION_2026-11-22.md). Main docs to rc9.
Next: owner uses current panel link/master credentials; further U work separately.

## 17.11.2026 — external ACME contact block; production rolled back

U: point5 accepted live inrc6 before authorized wipe. Points1–4 implemented/local
PASS, combined real acceptance OPEN. W9U3/5,W10U1/4; E unchanged. Do not close gates.
rc7 ordinary clean attempt and rc8 recovery both stopped at public TLS BEFORE panel
bootstrap; both rolled back. Current VPN/panel are NOT running; new SSH works on both.
Saved verified CURRENT installer JSON7 (including all original6/master) outside Git.
Monitors stopped, raw evidence retained, ACME storage/WG keys preserved after rollback.

Concrete external blocker: LE429 duplicate5/168h; server retry18.11 about04:32MSK.
Pinned Caddy2.11.9 DefaultIssuers(email) adds ZeroSSL ONLY when email nonempty; generic
docs/modules check was insufficient. No invented email or third blind retry.
Owner asked for ACME contact through async text question; awaiting actual email or
owner decision to wait. This is missing external data, not a permission request.

Prepared SEPARATE UNRELEASED email candidate: LC_EVPN_ACME_EMAIL via existing SSH
SendEnv/config, strict ASCII validation, renderglobal email; existing TLS wait36
attempts. Python10 PASS0.031s, production Caddy adapter TWO CA policies PASS with
synthetic email only (no registration/issuance). Go/schema/master code unchanged.
Candidate renderer/verifier differ fromd94 pin: MUST create clean helper-only core
child, verify Go tree unchanged/reuse exact ELF, update manifests before packaging.
First next AFTER actual email: complete candidate pin/build/release, reset ONLY owned
prepared component pool8 if version guard requires, no further node wipe/ACME deletion;
ordinary install with environment contact, then master/JSON/alpha13 actual acceptance.
[Full record](../../installer/controlpanel/RELEASE_RC7_2026-11-17.md). Main remains last accepted rc5 docs, not rc8 PASS.

## 17.11.2026 — priority profile404 hotfix real PASS

U counters unchanged (W9.5U-Fresh4/4,W9U3/5,W10U1/4); E unchanged.
Current owner package: point5 complete;1–3 implementation,4 next. rc6/e7c653e
published, imported profile binding repaired through approved locked registry init.
Actual master1144/alpha13/RuDM HTTP200; downloaded alpha13RuDM exact-engine and real
TCP/UoT PASS. No network/service restart, no repeated fresh install. [Evidence](../../installer/controlpanel/PROFILE_404_FIX_2026-11-17.md).
Architect spec saved MASTER_USER_OWNER_SPEC.md. Next: canonical master admin projection,
then default-yes native JSON handoff, one combined published clean install on hh pair.

## 17.11.2026 — BL-011.1 complete, actual rc5 PASS

U W9.5U-Fresh4/4 · W9U3/5 · W10U1/4; E unchanged. BL-011.1 closed1/1.
Published rc5/artifact47a81a2/corec174ba9, authorized cleanup and normal install exit0.
Actual VPN→system-trusted same-domain TLS→prefixed owner UI/API→create/worker/download→
new/master TCP/UoT PASS. Exact imported6 credentials/case/status/protected master PASS.
Public known prefix/forged headers denied, Origin/CSRF negatives and HTTP redirect PASS.
Same automatic Let's Encrypt certificate, private listeners retained after worker;
fresh SSH/default host routes PASS, monitors stopped. No CA install needed.
[Exact evidence and limits](../../installer/controlpanel/RELEASE_RC5_2026-11-17.md). No new E/phone UI gate claimed.
Next: owner uses updated Q24 profile and printed URL; no further reinstall required.

## 17.11.2026 — BL-011.1 domain/path HTTPS candidate

U W9.5U-Fresh4/4 from rc4; W9U3/5,W10U1/4. E unchanged. BL-011.1 local PASS,
rc5 real acceptance pending. Architect design/review: PANEL_DOMAIN_PATH_SPEC.md.
Python25 PASS; clean pinned corec174ba9 auth/API/CLI/storage target PASS. Caddy
public/private separation/frontend Host and exact sing-box configs PASS. go.sum
unchanged/mod verify PASS. Next: publish rc5, authorized actual hh-entry/hh-exit
cleanup/reinstall, real VPN→trusted TLS→owner→create/download→TCP/UoT acceptance.

## 17.11.2026 — real authorized F3 PASS

**W9.5U-Fresh F1–F4:4/4.** W9U3/5, W10U1/4, W8E3/8 and whole W9.5U/E/E1 unchanged.
[Actual execution, evidence and limits](../../installer/controlpanel/REAL_F3_2026-11-17.md).
Both current nodes software-cleaned by explicit owner instruction, no extra backups;
published rc4 command UNMODIFIED, JSON6, installerexit0. Real SSH/routes/VPN/TLS/
cutover/API/frontend/worker PASS. External real VPN→CA-verified owner login→create→
actualworker→download→new TCP/UoT and master control PASS. All6 passwords/case/master
protection preserved; whole profilecheck0. Private artifacts outside Git, monitors
stopped. Last old rc4 nested error remains unproven, not assigned a guessed cause.
Next: owner device profile/CA import and panel use; no reinstall/new tests needed.
Historical F3OPEN/PARTIAL below superseded for technical fresh path only. Phone UI
W9U01 and remaining E matrices not accepted by this result.


## 16.11.2026 — owner stopped gate debugging; publish rc4 for manual fresh

U W9U3/5, W10U1/4; E unchanged, **F3 OPEN**. Installer235e3a4, helper6bfb74b,
unchanged Go8d9b87c/schema8. Cutover+restore freshUnix preconditions, canonical
XDG and strict root-page TLS/API/worker startup checks corrected as one package.
[Exact evidence and limits](../../installer/controlpanel/RELEASE_RC4_2026-11-16.md).
Actual bundled install_panel to service boundary PASS; generated API/frontend,
TLS/root200 and owner login PASS. Latest gate916108 PARTIAL: worker did not run
because test RootDirectory mount226 failed on /run/lock/empire-vpn.lock. No
new CRUD/profile end-to-end PASS claimed. Owner explicitly requested no further
stand debugging/tests and publication for his own clean-install test. All failed
runs preserved, owned processes stopped. No production mutations.
rc4 published: artifactde4c5fa, main instruction31f02c9. Public bootstrap/ZIP
hashes and encoded URL verified without running installer/stand. Next: owner's
manual F3 after both OS reinstalls actually complete. No further gate debugging.


## 16.11.2026 — rc3 hotfix validated after owner F3 failure

U W9U3/5, W10U1/4; E unchanged. **F3 rc2 FAIL; rc3 OPEN for owner repeat.**
Root cause: installer-created root lock0644 rejected by protected Go registry
init before owner bootstrap/DB/key. Fix7c7b679, installer sourceb2336af, unchanged
accepted runtime8d9b87c/schema8. [Evidence and limits](../../installer/controlpanel/RELEASE_RC3_2026-11-16.md).
Linux71 tests PASS/4 platform skips, Windows16 PASS/1 macOS skip; security review
no blocker. Real isolated controller022→lock0600; legacy0644→actual vpnctl exit5;
sameinode helper repair→Go init PASS. Full worker916082 mutations/new-old-control
TCP/UoT/MIG05/CLI/owner download/return PASS; cleanup MainPID0/Resultsuccess.
Phase-specific safe failures and corrected final shutdown guidance included.
No node cleanup, chmod or service restart by agent. Phase resume remains BL-010.5,
not a new rc3 feature. Publication PASS: tagv0.4.0-rc3/artifacta35f31d; main READMEbfbbeca. Public
bootstrap/full ZIP/hash/loader and actual command PS5.1/7 first prompt verified.
First next action: owner manually repeats fresh using the new README command.
The owner's checked JSON stays required before any node cleanup.


## 16.11.2026 — rc2 published and public command verified

**U: W9U3/5 · W10U1/4. E: W8E3/8 reused, no new gate closures.**
`v0.4.0-rc2` artifactc5f74fc, clean core8d9b87c/schema8 published; main README/
GUIDE command updated byf9e8596 without merging WIP into stable code. Public
bootstrap/fullZIP/checksum and encoded loader URL/SHA verified; actual public
command reaches first master prompt in PS5.1/7 from a new directory, stopped
before SSH target. [Release evidence](../../installer/controlpanel/RELEASE_RC2_2026-11-16.md).
F1/F2/F4 ready with stated local/provenance boundaries; **F3 remains OPEN** for
owner manual cleared-node install→old VPN→owner login→create→download→TCP/UoT.
Owner confirmed checked JSON; recheck freshness before destructive steps. No
production actions. Further implementation paused; next action is owner's F3,
not next W10U development. Earlier publication-pending entries are historical.


## 16.11.2026 — rc2 release preparation (current priority)

W9U3/5 (02,04,05), W10U1/4 (03); W8E3/8 reused, E unchanged.
Further development paused at owner's request. Clean runtime8d9b87c/schema8,
installer71fc540, verified final ZIP and actual release ELF acceptance PASS.
[Release provenance, tests and limits](../../installer/controlpanel/RELEASE_RC2_2026-11-16.md).
Full exact Go suite, Q13 JSON/master compatibility, actual owner CRUD/TCP/UoT,
canonical restart/config rollback and Windows/Linux launchers PASS. No production
changes; rc1 unchanged. Next: publish rc2 and verify public bootstrap/full ZIP;
then owner manual F3 on independently cleared nodes. Do not resume portable or
next W10U development before this release result. Historical next-task entries
below are superseded by this release priority.


## 16.11.2026 — закрыты целые U-критерии

**W9U [███░░] 3/5 (02,04,05) · W10U [█░░░] 1/4 (03).**
W8U0/4, W13U0/4, W14U0/4; W8E3/8 reused, новых E-gates нет.
[Точная приёмка](../../installer/controlpanel/U_ACCEPTANCE_2026-11-16.md), [инструкция владельца](../../installer/controlpanel/OWNER_GUIDE_U.md).
Runtime5374923 + controller41d05d1: настоящий owner API→worker→CRUD→private
profiles→freshTCP/UoT, disabled/deleted denial, unchanged control/master protection
PASS. Actual API/CLI/browser CPU/RAM/load/disk/network/source/timestamps/stale+
refresh PASS; backup timestamps проверены как stored metadata, не новый restore.
Pinned targeted regression: API1.312s/auth6.447s/CLI0.033s/storage0.063s PASS,
modverify/go.sum сохранены. Оба runtime и браузерный adapter завершены;
MainPID0/Resultsuccess/listenerclosed/no owned units; старые артефакты сохранены.
Raw логи остаются в Lab; в Git только фиксированные numeric/boolean receipts.

W9U04 дополнительно принят: controller70c980c/fixture37d97b5/run916043,
unchanged537binaries. Actual canonical-derived API/frontend restart→newPID,
stable owner/session/users/key/profiles; badconfigstartup failed/API unavailable
while freshTCP/UoT worked; exactenvrollback throughsameunits→TLS/owner/controlPASS.
PublicunitSHA verified againstGitLF; cleanup independently verified. Не boot,
не cross-version/schema downgrade и не полный W8DR. [Receipt](../../installer/controlpanel/reports/W9U04_5374923_916043.json).
Первый следующий целый кандидат — **W10U02**: проверить существующий collector и
доступный readonly источник exit-local audit; без producer не подменять его
owner-provided fiction. W9U01 ждёт телефона, W9U03 migration deferred.
W13 partial report не начинать вместо целого критерия. W14 plan без конкретного
desired ingress не засчитывать. F3/phone и production действия ждут владельца.
Новый код остаётся локальным; опубликованный rc1 и его runtime0c05a61 не менялись.

Нижеследующие счётчики 0/5 и очереди описывают предшествующие точки.

## 16.11.2026 — актуальная U-очередь ночного продолжения

По новому поручению владельца выбираем самые простые полезные остатки W8U/W9U,
пропуски до W9.5U, W10U/W13U/W14U. Участие владельца и изменения серверов отложены
до утра; portable migration не возобновлять. [Результаты и точные границы](../../installer/controlpanel/U_NIGHT_RESULTS_2026-11-16.md).
Проверены подшаги: PROF-03 `70626a2`; ingress resources `daa33d0`/`fdd0c1d`;
AUTH-04 `4d40278`/`8a25436`/`216c721` с независимым security review;
stored evidence overview `f70bd62`. Последний combined target: storage0.070s,
owner API0.964s PASS, modverify/go.sum сохранены. Полные U-gates не закрыты:
W8U0/4, W9U0/5, W10U0/4, W13U0/4, W14U0/4; W8E3/8 reused без новых E-gates.
Дополнительно AUTH-03 `abc0876` + header `8c0309b`: exact admin ID/login/role/expiry,
missing/revoked/idle/expired/disabled denial; final pinned full auth7.251s +
identity CLI0.012s PASS. Первое следующее локальное действие — оценка минимального
W13U readonly plan bridge через существующий installer, без нового writer и
передачи SSH keys на ingress. Architecture review выявил конкретные guard,
immutable-plan и transport ограничения; см. отчёт. Минимальный следующий пакет —
sanitized readonly owner-provided preview report (partial, ещё не реализован).
Исполнение и F3 — действия владельца утром.
Ночные коммиты локальные, опубликованный rc1 не менялся; F3 ждёт ручной установки
владельцем. Исторические очереди ниже не отменяют эту актуализацию.


**Уточнение владельца15.11.2026:** [единый вход и точная приёмка F1–F4](../../installer/controlpanel/INSTALLER_ENTRY_CONTRACT.md). Сейчас реализуется только новая пара VPN+панель через автоматически загружаемую команду из GitHub и общий мастер. F4 закрывается после публикации и проверки из пустой локальной папки; локальный ZIP недостаточен. Доустановка и обновление панели в будущем идут через тот же мастер, оба сценария сейчас DEFERRED_BY_OWNER. Исторические заявления F4 ready ниже относятся к локальной подготовке.

**Последнее решение владельца15.11.2026:** [W9.5U-Fresh — установить VPN+панель одной командой](../../installer/controlpanel/PRIORITY_FRESH_INSTALL.md), 0/4, выполнять сразу. Portable export/import и его тестовые расширения отложены; предыдущие зависимости от W8U/G9 ниже отменены для fresh-install. Будущий минимальный перенос допускает plaintext JSON с паролями; сейчас на него время не тратить. Сохранять существующие PASS и WIP.

Актуальный порядок15.11.2026 — U-first/E-second. [Дельта](../../installer/controlpanel/UE_STRATEGY.md), [бэклог](../../installer/controlpanel/UE_BACKLOG.md), [evidence](../../installer/controlpanel/W8_UE_EVIDENCE.md). W8U 0/4 полностью закрытых, W8E 3/8 E_PASS_REUSED. Следующий результат — portable export/import на чистой staging-установке. W9.1 объединён с W9.5U/E по всем шести пунктам. Исторические счётчики ниже читаются с этой дельтой.

15.11.2026 — приоритет владельца W8 уточнён до переноса пользователей Export → Import → Working VPN. [Сопоставление четырёх пунктов, сохранённые PASS, результат rollback и минимальный пакет на согласование](../../installer/controlpanel/W8_TRANSFER_SCOPE.md). Этот порядок имеет приоритет над историческими списками ниже. WIP prune/audit изолирован; расширенный аудит/retention/ресурсы вынесены из блокеров G8. Общий статус G8 остаётся открытым до проверки пользовательского импорта.

14.11.2026 добавлен **W9.1 · интеграция в общий установщик, 0/6, G9.1 открыт**. [Проектирование, шесть пунктов и матрица приёмки](../../installer/controlpanel/W9_1_INSTALLER_INTEGRATION.md). Реализация следует за текущими W8/W9. W9 принимает компоненты панели, готовность общего E1 дополнительно требует G9.1. Общий счётчик ниже обновлён до одиннадцати этапов с W9.1.

**E1 [██████░░░░░] 6/11 этапов закрыты (W0–W5). W6 3/4 · W7 3/4 · W8 0/4 полностью закрытых (частично1–2) · W9 0/4 · W9.1 0/6.** [Единый статус и точные остатки G6–G9](../../installer/controlpanel/PROGRESS.md). Подготовка стенда и агентские шаги не считаются завершёнными продуктовыми пунктами.

**W3 · выполнено 5 из 5 пунктов.** На рабочей nh1 выполнен штатный MIG-05, общий writer/lock, очередь и systemd worker, проверены старые/новый профили и выдача владельцу. Защищённые pre/post snapshots сохранены на входе и зашифрованы/проверены на Windows. Переходим к оставшимся критериям W4; новые web-интерфейс/две SFA/полный E1 ещё не приняты.

- [x] **W0, W0a, W0b, W1.** Предварительные проверки, приватный доступ с телефона, проверка применения Caddy и проектирование миграции. Основания — [проверки пилота](../../installer/pilot/README.md), [применение Caddy](../../installer/pilot/caddy-apply.md), [решения по миграции](../../installer/pilot/legacy-migration.md) и [испытание восстановления](../../installer/pilot/recovery-results.md).

## W2

- [x] **1. Схема реестра.** SQLite, версионированные миграции, точный регистр логина, служебная запись `master_user`. Проверены открытие и обновление заполненной БД. Коммиты `93023f2`, `07ca3c4`.
- [x] **2. Хранение реквизитов.** AES-256-GCM с привязкой к пользователю и версиям; проверка ключа при открытии реестра. Тесты проверяют расшифровку и отсутствие открытого пароля в DB/WAL/SHM. Коммит `07ca3c4`.
- [x] **3. Операции и восстановление после сбоя процесса.** Атомарная постановка в очередь, повтор запроса, конфликт ключа, чтение статуса своей операции. Проверены конкуренция и остановка процесса до и после фиксации. Коммиты `07ca3c4`, `d3f2380`.
- [x] **4. Сверка старых файлов и план.** Офлайн-сверка auth, экспорта, манифеста и профилей; запись результата и неизменяемого плана в SQLite. Проверены коллизии регистра, повтор планирования и устаревание снимка. Коммиты `5d22d82`, `15dfa7a`.
- [x] **5. Адаптер переноса в staging.** Сквозной тест `TestStagePythonPlan` провёл синтетический снимок через Python-сверку и планирование, затем через Go CLI. Подтверждены сохранение точного логина и исходного пароля под AES-GCM, служебная роль и защита `master_user`, отказ при дрейфе, откат частичного импорта и повтор с исходной квитанцией. Пройдены `go test -v ./...` и пять Python-тестов сверки.
- [x] **6. Контракты API/CLI и Go.** Контракты хранения §5.8 сопоставлены с реализацией в [README](../../installer/controlpanel/README.md). Результаты проверок приведены ниже.
  - [x] OPS-02 при отказе обновления сессии возвращает типизированный JSON с request ID. У CLI импорта проверены коды конфликта и внутренней ошибки, `--json`, `--quiet` и совместимость прежней квитанции.
  - [x] Go-реестр читает метаданные пользователей постранично и меняет отображаемое имя по ожидаемой версии. Проверены конфликт двух обновлений, защита служебной записи и сохранение регистра. Расшифрованный секрет скрыт при стандартном форматировании и сериализации JSON.
  - [x] Журнал операций. `TestInterruptedJournal` проверяет конкурирующий захват, повторы и конфликты шагов, сохранение порядка через повторное открытие базы, чтение через OPS-02, откат и отказ при поздней отмене. Весь набор `go test ./...` прошёл.
  - [x] `TestEffectiveStateAndSecretPurpose` проверяет цели чтения секрета, сохранение пароля при повторном включении, смену состояния по версии, защиту мастер-записи и блокировку чтения при неопределённом результате. Прошли `go test ./...` и пять Python-тестов сверки.
- [x] **7. Приёмка G2.** Проверена версия `2754adc` ветки `feature/controlpanel-pilot`. На синтетических данных прошли 15 самостоятельных Go-тестов и 9 Python-тестов.

### Результаты G2 · 12 ноября 2026

| Критерий | Что подтвердил итоговый прогон |
|---|---|
| Контракты и схема SQLite | Сохраняется точный регистр логинов. Удалённый логин остаётся зарезервированным. При 99 обычных пользователях и одном `master_user` из двух конкурирующих записей проходит одна. Проверены защита служебной записи, привязка реквизитов к владельцу и отказ при устаревшей версии. |
| Сверка и staging | Изменение снимка блокирует прежний план. Перенос по согласованному плану сохраняет логины и пароли. Ошибка внутри транзакции откатывает частичный перенос; повтор успешного вызова возвращает исходную квитанцию. |
| Защита секретов | Сгенерированный пароль успешно расшифрован по назначению. Его открытое значение отсутствовало в проверенных непустых DB, WAL и SHM. Контрольный ID найден в DB и WAL. Тесты также проверили привязку шифротекста, отказ с чужим ключом и скрытие значения при форматировании и JSON-сериализации. |
| Восстановление базы | При аварийном завершении дочернего процесса до COMMIT повтор создал ровно одну операцию. После COMMIT повтор вернул прежние идентификаторы и сохранил доступ к реквизитам. После повторного открытия базы сохранились шаги прерванной операции. Проверено обновление заполненной схемы v1. |

Go запускался в отдельном Linux-процессе на входной ноде с временной БД и отключённой сетью. Команда из каталога `controlpanel` — `go test -count=1 -v ./...`. Служебный `TestCrashChild` имеет отметку SKIP при самостоятельном запуске; родительский `TestCrashAndRetry` вызвал его в обоих сценариях, оба прошли.

На Windows из корня репозитория выполнены `python -B -m unittest discover -s tests -p test_registry_schema.py -v` (4 теста) и `python -B -m unittest discover -s tests -p test_legacy_inventory.py -v` (5 тестов). Приёмка восстановления охватывает сбой процесса. Переключение рабочего исполнителя и проверка старых клиентских подключений входят в W3.

## Дальнейшая очередь

### W3 · импорт и передача права записи

- [x] **1. Проверка писателей на копии.** Сопоставлены исходники тега v0.3.6 и текущей ветки. Воспроизведена гонка при записи экспорта из ранее запущенного мастера. Исправленный мастер проверяет владельца под общим lock при записи экспорта и мастер-профиля. [Результаты и границы проверки](../../installer/pilot/legacy-migration.md#w3-проверка-писателей-на-копии).
- [x] **2. Передача права записи на копии.** Сквозной тест `TestStagePythonPlan` запускает команду после настоящего импорта в staging. Проверены четыре аварийных завершения (до и после замены манифеста при передаче и откате), повтор, отказ при смене копии, незавершённой транзакции, изменении экспорта или версии пользователя. После отката файлы совпали побайтно. Условие для старых сеансов и [порядок запуска](../../installer/pilot/legacy-migration.md#передача-права-записи-на-копии) записаны в инструкции.
- [x] **3. Единый путь постановки выдачи в очередь.** После передачи владения `vpn-add-user` вызывает локальный `vpnctl user create`. Реестр создаёт стандартную операцию `user.create`. Проверены отказ при одном лишь `copy_handed_off`, повтор с той же квитанцией после смены шаблона, точный регистр, дрейф и незавершённая транзакция. Прошли Go-тесты и 6 Linux-проверок блокировки и восстановления. На Windows прошли 53 теста, 7 пропущены. Рабочая активация и файл профиля после переключения зависят от W4–W6.
- [x] **4. Репетиция на синтетической паре данных.** После передачи на копии тест смоделировал исходное активное состояние и отключил одного пользователя через CAS. Повтор старого импорта и новый план по старому снимку получили отказ. Обратный экспорт содержал только активную запись с прежним паролем. Оба исходных профиля совпали побайтно. В отдельном сетевом пространстве Caddy с экспортированным auth и Naive-клиентом пропустил контрольный TCP до и после отказа отключённому логину. Для пробы адрес и доверенный сертификат задавались в тестовых копиях outbound. Прошли Go-тесты с `VPN_TEST_NAIVE_PROBE=1`. На Windows прошли 53 теста, 7 пропущены.
- [x] **5. Приёмка G3 на рабочей паре.** Согласовано пользователем «начинай», выполнено 13.11.2026; [протокол](../../installer/controlpanel/G3_ACCEPTANCE_2026-11-13.md). Код `69e4708`, исправление systemd worker `6621689`.
  - [x] На копии установки проверен возврат после отключения пользователя, включая прерывание процесса после каждой из четырёх атомарных замен файлов и повторный запуск. Установщик блокирует запись до завершения возврата. Исходные профили сохранились побайтно.
  - [x] Проверить выдачу нового профиля через панель до передачи ей права записи на рабочей паре. До переключения — на копии; после переключения nh1 — через настоящую сессию владельца приватного API.
    - [x] Рендеринг в памяти для SFA 1.14.4. На синтетической записи проверены версия клиента, статус пользователя, привязанная одобренная ревизия и SHA-256. Полученный профиль прошёл `sing-box check` в изолированной сети. Маршрут `panel.home.arpa` находится в общем шаблоне панели и установщика.
    - [x] Скачивание из сессии владельца и учёт выдачи. HTTP-тест проходит от входа и создания тестовой записи до скачивания по ссылке для активного пользователя. Проверены отзыв сессии, отказ до активации и откат при ошибке журнала.
    - [x] В изолированной сети исполнитель передал реквизиты нового пользователя тестовому адаптеру. Caddy применил конфигурацию через Unix-сокет; TCP прошёл у нового и контрольного пользователей, неверный пароль получил отказ. После проверки реестр атомарно зафиксировал активацию и успех операции. Выданный через HTTP JSON прошёл sing-box check, его Naive outbound прошёл TCP с адресом и сертификатом стенда.
    - [x] Для рабочей приёмки подключить адаптер и исполнитель к штатной очереди под lock, подготовить закрытый сокет Caddy и согласовать переключение пары. Выполнено на nh1, verified_cutover записан штатным MIG-05 после live/probe-проверок.
      - [x] 13.11.2026, код `87c3220` (база `4f14f40`): `runNextCreate` переиспользует проверку установки и общий lock из SSH-пути; `NextOwnedCreate` выбирает прерванную операцию раньше очереди. `RecoverCreate` повторно проверяет прежний секрет без применения Caddy и использует существующий атомарный `CompleteVerifiedCreate`. `reconcile_required` блокирует очередь. Полный `go test -count=1 ./...` прошёл в отдельном systemd-процессе с PrivateNetwork/PrivateTmp/ProtectSystem=strict на синтетике (Go 1.27.3). Проверены повтор после отказа SQLite, запрет выдачи до commit, сохранение секрета при переоткрытии, удержание lock и отказ при файловом дрейфе. Реальный адаптер и постоянный запуск исполнителя ещё не подключены; поколение кандидата должен проверять адаптер. Рабочие службы не изменены, владелец записи не передан, откат не требовался.
      - [x] 13.11.2026, диагностика nh1 чтением: новые SSH-сессии к `hh-entry` и `hh-exit` успешны; действующие `evpn-nh1-caddy` и `evpn-nh1-singbox` активны, обе под `evpn:evpn` в `/run/netns/naive`; в Caddyfile сохранён `admin off`, TimeoutStopUSec=90s. Auth/Caddyfile — 0640 root:evpn, manifest и общий lock — 0600 root:root. Вход: свободно 3431 МиБ. Это предварительная сверка, не приёмка G3 и не полная проверка манифеста/ACL.

| Этап | Результат |
|---|---|
| W3 | Рабочий импорт и передача права записи с общим lock, проверка старых клиентов и отката |
| W4 | Адаптер безопасного применения Caddy |
| W5 | Создание, отзыв, ротация и восстановление пользовательских операций |
| W6 | Формирование и выдача профилей |
| W7 | API, CLI и интерфейс владельца. Уже сохранены сессии (`00b6967`) и форма входа (`f52932f`); подключение формы к пилоту и проверка на телефоне предстоят |
| W8 | Безопасность, резервное копирование и дисковый бюджет |
| W9 | Проверка и приёмка компонентов панели (G9) |
| W9.1 | Интеграция в общий установщик, публикация и общий E1 (G9.1) |

### Согласованный порядок реализации W4–W9

Все функции E1 и критерии G3–G9 из спецификации v1.1 остаются в объёме. Текущий шаг бери из последней записи о ходе работы ниже. Эти комментарии применяются и к незаконченной репетиции G3.

- **W4 · применение Caddy.** Доведи штатный путь через существующие очередь, lock, адаптер, файловый журнал и проверку доступа. Сначала сравни наблюдаемое состояние после сбоя: операция, поколение файлов, фактическая конфигурация Caddy и результат новой попытки подключения. Если тайм-аут и потеря ответа требуют одной сверки и одного решения, используй один путь восстановления. При доказанном применении заверши операцию с прежними реквизитами; при неизвестном результате блокируй конфликтующие изменения через существующий механизм сверки. Границы SQLite, файлов и reload сохраняют свои проверки. Отдельный адаптер, журнал или служба оправданы, когда действительно различаются полномочия, владелец данных или способ восстановления.
- **W5 · пользовательские операции.** Переиспользуй механизм применения и сверки там, где совпадает порядок записи. Для каждой операции проверяй её собственный результат: после ротации новый пароль принимается, прежний отклоняется; после отключения новый CONNECT запрещён; контрольный пользователь сохраняет доступ. Все 14 точек отказа G5 оставь именованными и проверяемыми. Общие подготовку, запуск и проверки вынеси в один параметризованный набор. Защита master_user, точный регистр, ёмкость 100+1 и идемпотентность остаются отдельными утверждениями тестов.
- **W6 · профили.** Используй один рендер и путь выдачи для поддерживаемых версий с явными проверками совместимости. Сгруппируй ручные проверки маршрута панели, RU/Download Manager и импорта в один согласованный сеанс на телефоне, если обе сборки доступны. Записывай результат отдельно для SFA 1.14.4 и 1.15 alpha13; отсутствующее измерение остаётся открытым.
- **W7 · интерфейсы.** CLI и веб-панель используют общую логику операций. Сквозной сценарий «создать → увидеть результат → скачать» переиспользует уже проверенную выдачу. На границах API, CLI и браузера проверяй их собственные контракты, авторизацию, CSRF и отсутствие утечки секретов. Сбои Caddy и SQLite воспроизводи в тестах соответствующего исполнителя. Остальные предусмотренные экраны и команды остаются в плане.
- **W8 · эксплуатация.** На одной согласованной копии совмести восстановление резервной копии, вход владельца, подключение старым профилем и измерение пикового расхода диска при резервировании и восстановлении. Зафиксируй результат каждого критерия, включая бюджет 500 МБ. Проверки прав и изоляции выполняй с теми системными идентичностями, которые будут работать на nh1.
- **W9 · выпуск.** Полный приёмочный прогон выполняй на зафиксированном кандидате. Между изменениями запускай тесты затронутого кода; после изменения общего механизма прогони его потребителей. При повторном использовании результата укажи коммит, среду и что именно проверено. Изменения прав, unit-файлов или порядка запуска вновь требуют соответствующей системной проверки. Canary, cold reboot, load/soak и согласование рабочей раскатки остаются условиями G9.

В плане достаточно одной записи на законченный результат: коммит, пройденные проверки, что осталось и первый открытый шаг. Совмещённый прогон можно зачесть нескольким этапам, если совпали проверяемая сборка или затронутый код, условия и наблюдаемый результат. Приёмку на рабочей паре отмечай по фактической проверке на nh1.

### Продолжение G3 · 13 ноября 2026

Первый открытый пункт: подключить реальный адаптер к `runNextCreate` и штатный запуск очереди. Функция уже удерживает общий lock и переиспользует SSH-проверки, но пока вызывается только тестом. Не повторять реализацию сохранения пароля, атомарной активации и recovery-проверки из `87c3220`. Для recovery адаптер обязан подтвердить сохранённый кандидат, поколение и фактическую конфигурацию Caddy; одной успешной проверки логина недостаточно. Рабочая передача и G3/G4 не выполнены.

13.11.2026, следующий проверенный код `4eabbad`: добавлен `internal/caddy` — auth-only JSON patch единственного forward_proxy, validate, приватный fsync-журнал before/candidate с operation/generation, Unix-only runtime, проверка точного live-кандидата до/после проб, отдельный откат с запретом перезаписи внешнего дрейфа. Исходный формат auth подтверждён по установленному forwardproxy e747854e7874. Полный Go-набор прошёл офлайн с `VPN_TEST_CADDY_ADAPTER=1` в PrivateNetwork. На установленном Caddy SHA256 `7509cd6b38a5da3324a08f32f62a7000237e5e1f6ccfb58e818bf730de58d30c` отдельный процесс на loopback проверил новый/контрольный HTTP CONNECT, отказ неверному паролю, неизменный HTTP-сайт, recovery без reload и откат с отказом новому пользователю. Синтетические тесты проверили сохранение остальных JSON-директив и больших чисел, конфликт поколения, отказ validate, отказ пробы, дрейф во время пробы и запрет публичного сокета. go.sum не изменён; рабочие службы после прогона active.

Границы: стенд этого коммита — HTTP CONNECT без TLS/Naive/UoT, Caddy как дочерний процесс теста, не доказательство разделения системных учётных записей. Проверка Unix runtime ограничена приватностью пути/сокета; запрет доступа именно Web UI, sing-box и клиентскому proxy ещё открыт. Это часть адаптера для G3/W4, не приёмка G4. Пакет пока не подключён к очереди и не обновляет auth.caddy/манифест; его нельзя включать на рабочей паре. **Первый открытый шаг теперь:** согласовать durable-журнал с записью auth.caddy и panel_generation/panel_auth_hash, включая crash между заменами. Текущая общая preflight-проверка блокирует несовпадение файла и манифеста: для recovery нужен узкий путь проверки подготовленного журнала, а не обход контроля дрейфа. Затем подключить штатный запуск, повторить полный create/download/return-to-installer на копии и подготовить единый пакет согласования G3. Не повторять PatchCreate/UnixRuntime/Prepare/Verify/Rollback из `4eabbad`.

Офлайн-тесты: зеркало Windows `%TEMP%/w2proxy-5333edf4305f4eab99555586c8d03449` содержит `.info/.mod/.zip` всех трёх версий из go.mod. Передано в `/run/vpn-w3-worker-tests/proxy` на hh-entry. Полный финальный набор прошёл с `/opt/empire-vpn/cache/toolchain/go/bin/go`, `GOPROXY=file:///run/vpn-w3-worker-tests/proxy`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOFLAGS='-p=1 -mod=readonly'`; зависимости проверены по репозиторному go.sum, `go mod verify` успешен, go.sum не изменён. Запуск — отдельный systemd-run с PrivateNetwork=yes, PrivateTmp=yes, ProtectSystem=strict. Повторный прогон нужен после следующего изменения кода. Временные исходники/зависимости находятся в /run; рабочие реквизиты и профили туда не копировались.

13.11.2026, файловая часть `cc82d8a`: `owned_auth.py` переиспользует строгий auth-парсер `inspect_legacy`, проверку реквизитов `render`, атомарную публикацию `handoff_legacy.publish` и directory fsync из `return_legacy`. Приватный `panel-auth-pending.json` связывает operation/run/generation, идентичность каталогов, точные before/after auth/manifest, хеш подготовленного Caddy-кандидата и неизменного Caddyfile. Проверяется соответствие auth файловому baseline и JSON forward_proxy; посторонние JSON-поля и строки исходного auth сохранены. Прямая запись и возврат: auth первым, manifest последним; повтор допускает только известные before/after каждого файла. Владельцы, режим и xattr сохраняются, их внешнее изменение блокирует продолжение. Журнал удаляется только после подтверждения завершённой операции SQLite и соответствующих файлов. Очередь SSH и возврат установщику блокируются при наличии незавершённого файлового журнала.

Фактически прошли 9 Linux Python-тестов файловой части в PrivateNetwork/PrivateTmp: четыре реальных os._exit после замен auth/manifest при прямой записи и возврате, повтор, изменение generation/operation, конфигурационный дрейф, перенос журнала на другую копию, права/xattr, запрет замены открытого журнала, проверка SQLite перед finish и отсутствие секрета в ответах helper. Полный Go-набор прошёл через файловое зеркало, go.sum не изменён; включает прежние проверки миграции и новые отказы очереди при pending-журнале. Профили и рабочие службы не менялись; рабочий rollback не использован. Проверка сбоя процесса не доказывает устойчивость к потере питания.

**Первый открытый шаг после `cc82d8a`:** связать Python helper с Go-адаптером и исполнителем так, чтобы только операция из журнала могла восстановиться при известной смешанной паре auth/manifest. Сейчас обычная preflight-проверка намеренно блокирует этот путь. Нужны единый прогон queue → prepare → reload/probes → files → SQLite → finish, recovery при сбое между каждым этапом и cleanup после уже завершённого SQLite commit. Затем штатный запуск и репетиция create/download/return-to-installer с реальными путями. Полное восстановление исполнителем пока не реализовано; G3/W3 5/5 и G4 не отмечать. Не повторять файловый журнал/парсер/публикацию из `cc82d8a`.

13.11.2026, связанный исполнитель `c3dad01`: `createCaddyWorker.once` переиспользует Registry ApplyCreate/RecoverCreate/CompleteVerifiedCreate, Caddy Prepare/Verify, файловый helper и общий lock. Сохранён нормальный запрет pending-журнала для обычной очереди. Только worker может до общей preflight-проверки восстановить точную связанную операцию после проверки owner-run, SQLite-статуса, пути снимка, generation, обоих файловых preimage и live-кандидата. Затем обычная проверка auth/manifest выполняется снова. Очистка после завершённого SQLite commit и после удаления pending-журнала не вызывает reload. Удаляются только известный приватный prepared.json и его пустой каталог; рекурсивного удаления нет. Другая reconcile_required либо несколько running/verifying блокируют восстановление.

Фактически прошли все Go-тесты через файловое зеркало с неизменным go.sum, PrivateNetwork/PrivateTmp/ProtectSystem=strict, включая отдельный installed-Caddy тест (`VPN_TEST_CADDY_ADAPTER=1`). Сквозной тест исполнителя использовал файловый runtime-адаптер и синтетическую probe-функцию: проверены обычное завершение, реальный os.Exit исполнителя после load, отказ SQLite, смешанная пара файлов, SQLite commit до cleanup, остаток prepared после удаления журнала, дрейф, другая reconcile и две незавершённые операции. Повтор не вызывал load, финальные auth/manifest имели generation=2 и SQLite succeeded/active, plaintext-снимок удалён. Это не сквозная проба Naive/TLS/UoT штатным worker и не приёмка G3/G4. Старые миграционные тесты прошли; рабочие службы/профили не менялись, рабочий rollback не использован.

**Первый открытый шаг теперь:** штатный CLI/запуск worker с фиксированной root-owned политикой Unix runtime, непривилегированного validate в namespace и настоящих контрольных проб. Сам `createCaddyWorker` пока вызывается тестами. Затем единая репетиция на копии с установленным Caddy/Naive, скачиванием через сессию владельца и возвратом установщику; подготовка конкретного пакета согласования G3. Не реализовывать заново saga/recovery из `c3dad01`.

13.11.2026, штатный CLI и пробы `7ae2508`: добавлен `vpnctl worker once --installation ID --owner-run UUID`, политика `/etc/vpn-control/worker-ID.json` root/0600, привязка installation/run, запрет относительных и symlink-путей исполняемых файлов, проверка root-владения и запрет group/world-write. Клиент не задаёт команды или путь политики. `create_probe.py` переиспользует SOCKS/TCP/UoT из verify.py и auth-парсер; реквизиты кандидата только на stdin, canary читается из auth, временные профили — в закрытом scratch. Подготовлены неустановленные service/timer и [описание политики](../../installer/controlpanel/WORKER.md). На рабочей паре они не установлены/не включены.

Полный Go-набор и go mod verify прошли офлайн через зеркало, go.sum не изменён. Проверены отказ при чужом owner-run/публичной политике/относительной программе и отсутствие секрета в ошибке probe. Отдельная поставляемая probe-команда прошла через stdin на installed Caddy/sing-box в PrivateNetwork: доверенный TLS, точный site hash до/после, новый и контрольный TCP + UoT v2 echo, отказ неверному паролю, повторный контроль после отказа и отказ при чужом site hash. Лабораторный CA доверен явно; TLS verification не отключалась. Проверен синтетический профиль общего harness, не выдача из сессии владельца этим worker.

**Первый открытый шаг после `7ae2508`: общая репетиция штатного CLI на копии.** Объединить очередь с реальными UnixRuntime/Naive-пробами, владельческой выдачей и возвратом установщику; проверить непривилегированный validate в namespace, идентичности и права сокета, пути и systemd-шаблоны. Реальный режим exit_https/DNS и связанная CLI-репетиция ещё не проверены. Затем пакет согласования G3 с актуальной read-only сверкой nh1 и рабочая приёмка. Остались три крупных шага: общая репетиция, согласование готового пакета, переключение/приёмка. G3/W3 5/5/G4 пока открыты. Рабочие службы и профили не менялись; откат не применялся.

13.11.2026 19:12 MSK, общая репетиция: код `65ff2e2` (продуктовые файлы совпадают с замороженным `52e04ec`), [протокол](../../installer/controlpanel/G3_REHEARSAL_2026-11-13.md). PASS: реальные рабочие пути в RootDirectory/lo-only → штатный vpn-add-user/CLI → Caddy → новый/контрольный Naive TLS/TCP/UoT → выдача владельцу (до активации 404, без сессии 401, после 200/no-store/PROFILE_ISSUED) → оба профиля → возврат установщику до и после мутации с повтором. На реальном Caddy проверены отказ commit SQLite и завершение после сверки кандидата/прежнего секрета; потеря ответа не создаёт новый секрет/дубликат и использует прежнюю процедуру. Полный Go-набор с обоими сетевыми test-флагами и 9 тестов файлового журнала прошли; прежние migration/return/crash-потребители также PASS. go.sum неизменён. Согласованный раздел W4–W9 и коммит `71451ad` сохранены.

Права фактически: в копии UID Caddy/relay/API = 65534/65533/65532, CapEff=0, общая изолированная сеть; admin socket owner=65534, mode=0200, parent=0700, API/relay отказаны, proxy/admin HTTPS-путь не раскрывает config. Это тестовые UID, не окончательные production-идентичности; production worker unit с ProtectSystem=strict ещё не исполнен. Echo TCP/UoT проверены в копии; отдельно на двух существующих пользователях nh1 PASS exit_https/ожидаемый выход, DNS/UoT, TLS/site/неверный пароль, без изменений. Новые SSH обеих нод успешны, рабочие службы active, по-прежнему evpn:evpn/admin off. Профили, WG/firewall/маршруты и резерв не менялись; operational rollback не применялся.

**Первый открытый шаг после репетиции:** реализовать рабочий MIG-05 под lock с подтверждением фактов (тестовая preverified-фикстура его не заменяет), затем подготовить один конкретный пакет согласования G3: защищённый snapshot, production accounts/ACL/unit/socket, команды передачи и полного отката до/после мутаций, ожидаемый перерыв и stop-критерии. Возврат `--installation` проверен для данных/писателя; пакет должен согласовать системную идентичность и группу evpn старого wrapper при operational rollback. Рабочий verified_cutover вручную не выставлялся. W3 остаётся 4/5, G3/G4 открыты. После приёмки nh1 продолжать W4–W9 по согласованному порядку, сохраняя весь E1, обе SFA и 14 именованных точек G5.

13.11.2026, завершение общей репетиции, код **`69e4708`**: штатные registry init/owner bootstrap/inspect/plan/stage/MIG-05 заменили удалённую preverified-фикстуру. MIG-05 удерживает общий lock, сверяет исходные секреты, поколение/владельца/все tracked-файлы/полный live Caddy JSON и свежий доступ master+независимого пользователя; только затем атомарно активирует импорт и пишет verified_cutover/квитанцию. Повтор сохраняет исходный результат; неоднозначный отказ блокирует изменения через reconcile_required, явная SSH-сверка переиспользует тот же план/секреты. Общие lock/open-registry/baseline и прежние worker/adapter/file journal/probes переиспользованы. Prepared-секреты перемещены из каталога API в root-only state/panel-operations по реальной границе владения.

**PASS:** замороженная сборка из git-архива `69e4708`, полный Go-набор с обоими сетевыми test-флагами, go mod verify, неизменный репозиторный go.sum через прежнее Windows file-proxy; 9 Python owned_auth + 4 schema + 5 inventory. Изолированные RootDirectory/PrivateNetwork/ProtectSystem=strict-прогоны: настоящий CLI → Caddy → новый/контрольный TLS/TCP/UoT → отказ неверному → выдача владельцу (404 до active/401 без сессии/200 no-store + аудит) → обратный экспорт/возврат до и после нового пользователя → runtime restore/admin off/прежняя identity/профили. Проверены отказ commit создания, потеря ответа и прежний секрет, probe/commit/drift MIG-05, reconcile и отмена неудавшейся передачи; обрыв runtime restore после Caddyfile до manifest и повтор. Защищённые pre/post snapshot с SQLite online backup проверены в копии; Windows JWE self-test проверил ACL/roundtrip/replay/tamper и совместимость W1 без передачи private key на VPS. [Обновлённый протокол](../../installer/controlpanel/G3_REHEARSAL_2026-11-13.md).

Фактические identity копии: Caddy982:982, API981:981, relay999:986, CapEff=0, socket0200/parent0700, API/relay denied, proxy/HTTPS admin не раскрывают. Sandbox копии теперь ProtectSystem=strict с root-relative ReadWritePaths; точный production unit ещё должен быть проверен после согласованного запуска. Echo/TLS/TCP/UoT проверены вместе; exit_https/DNS — отдельно на старых пользователях nh1, повторить для старого/нового после переключения. Рабочая сверка чтением: 19/19 tracked hashes совпали, Caddy/sing-box active evpn:evpn/naive, admin off; registry/accounts/CLI ещё не установлены, UID/GID981/982 свободны, новые SSH обеих нод PASS, свободно3299МиБ. Рабочие профили/службы/сети/резерв не менялись; рабочий откат не применялся.

**Первый открытый шаг теперь — одно согласование [готового пакета G3](../../installer/controlpanel/G3_CUTOVER_PACKAGE.md)**: окно15мин, начальный restart Caddy (ожидаются секунды, предел текущей остановки90с+запуск), dedicated accounts/ACL/закрытый socket, установленный API/worker и передача записи. До изменения обязательны закрытый pre-snapshot и проверенная зашифрованная копия Windows; после мутаций возврат сохраняет текущих активных пользователей, а не старый auth из архива. Подготовлены команды отмены неудавшегося MIG-05 и возврата после verified_cutover, runtime/права/ACME, stop-критерии и проверки новых SSH. Новая web-интеграция/обе SFA/W8 backup budget остаются своими критериями; G3 их не подменяет. **W3 остаётся 4/5, G3/G4 открыты до nh1.** После согласования — рабочая приёмка, запись фактов/снимков/состояния возврата, затем остаток W4/G4 с повторным использованием этих доказательств; все E1/G3–G9/14 именованных G5 сохранены.

13.11.2026, **G3 PASS на nh1, W3 5/5**. После ответа пользователя «начинай» выполнен [согласованный пакет](../../installer/controlpanel/G3_CUTOVER_PACKAGE.md), [фактическая приёмка и откат](../../installer/controlpanel/G3_ACCEPTANCE_2026-11-13.md). Продуктовый код/бинарники `69e4708`, unit fix `6621689`. Реальный MIG-05 под lock записал verified_cutover после проверки live JSON/исходных секретов/свежего master+контрольного exit_https и DNS/UoT. Начальный restart90,38с; далее обычный vpn-add-user → user.create → настоящий systemd worker → Caddy validate/apply/verify → active/succeeded. Старые профили побайтно прежние, старый/новый JSON check и свежие exit/TLS/DNS/UoT/wrong-password PASS. Владелец приватного API:404 до active/401 без сессии/200 no-store и одна выдача; повтор запроса сохраняет ciphertext/одну запись, следующий worker idle.

Факты: Caddy982:982 в naive, только CAP_NET_BIND_SERVICE; relay999:986 прежний; API981:981/CapEff0/socket0600/parent0700. Admin socket0200/parent0700; API/relay/фактический DynamicUser frontend denied. Приватный panel через новый VPN с доверенным TLS401, внешнее Windows TLS с настоящим panel CA rejected; proxy2019/admin HTTPS не раскрывают JSON, сайт PASS. Новые SSH обеих нод PASS. Четыре active, generation2, integrity_check ok, pending0, prepared-секретов0; API/timer enabled+active. Реальное исправление worker: явный User=root снимал effective CAP_SETUID; стандартная root-идентичность сохраняет sandbox и работоспособный непривилегированный validate. Проверены unit idle/create/idle, лишнего restart Caddy не было.

Pre/post snapshots root-only на входе и encrypted/decrypt/hash-verified на Windows, ключ получателя только у владельца. Секреты/профили/архивы вне Git/отчётов. Рабочий откат не выполнялся; защищённый window rollback готов, использует journaled return до runtime restore и сохраняет нового пользователя; пути/команда в протоколе. WG/firewall/маршруты/sing-box/резерв не менялись. Результат не заменяет новый web UX, обе SFA, W8/полный E1.

### W4 · безопасное применение Caddy

- [x] **1. Управляемая область и поколение.** Переиспользованы PatchCreate/Prepare/ReadPrepared: меняется только managed auth, остальные JSON-директивы/большие числа сохранены; generation/operation conflict, внешний drift блокируют apply/recovery/rollback. Доказательства `4eabbad`, полный pinned Go-набор `69e4708` и G3 live baseline.
- [x] **2. Validate/apply/verify/rollback и восстановление.** Существующий UnixRuntime/Prepared и общий worker/journal; installed-Caddy staging включает успешные/отрицательные пробы и проверенный rollback. Сбои файлов/SQLite и потеря ответа не создают новые секреты; неизвестный результат блокируется. Доказательства G0b, `69e4708` и G3; 14 точек G5 этим ещё не закрыты.
- [x] **3. Закрытый socket и полномочия.** Реальные G3 owner/mode/identity/namespace/caps, API/relay/frontend denial, proxy/HTTPS не публикуют admin. Непривилегированный validate через production unit после `6621689` PASS.
- [x] **4. Предупреждение о влиянии и приёмка G4.** `c8880b0`: единый English caddy.ApplyNotice для CLI/будущего UI, выводится до queue, без обещания непрерывности/обрыва прежних туннелей и без restart fallback. [G4 PASS](../../installer/controlpanel/G4_ACCEPTANCE_2026-11-13.md): полный pinned Go-набор и RootDirectory35 с настоящим Caddy/Naive/выдачей/возвратом. G0b/G3 переиспользованы с явными версиями/средой/наблюдениями. На nh1 новый notice не развёртывался, рабочие службы в W4 не менялись; W7 подключит общий текст к UI.

**Первый открытый шаг после G3: W4 пункт4.** Не повторять adapter/saga/probes из W3; UI подсоединить к тому же notice на W7. После G4 — W5 с общей процедурой применения и всеми14 именованными fault points, отдельными доказательствами результата каждой операции. Все E1, обе SFA, G3–G9 сохранены.

13.11.2026, **W4 4/4, G4 PASS**, код `c8880b0`: [матрица](../../installer/controlpanel/G4_ACCEPTANCE_2026-11-13.md). Full suite/installed-Caddy test/реальные общий CLI и owner download/return на копии PASS, go mod verify PASS, go.sum неизменён. Непрерывность и закрытие действующих туннелей не обещаются. Рабочая версия остаётся `69e4708`+unit `6621689`; snapshots/возврат G3 сохранены, новый deploy не выполнялся.

**Первый открытый шаг теперь — W5/G5:** сопоставить существующие QueueOwnedCreate/ApplyCreate/RecoverCreate/Prepared/owned_auth и contract/state machine с disable/enable/rotate/delete, затем расширять их общим механизмом без второго adapter/journal/daemon. Сохранить все14 именованных failure points в параметризованном наборе; после каждой операции отдельно доказать результат, для rotate — новый пароль PASS/старый FAIL/контрольный PASS. Не повторять G0b/G3/G4; affected tests во время разработки, full suite на pinned версии перед G5. Обе SFA, E1 и G6–G9 остаются обязательными. Первые изменения W5 — на копии, согласование G3 не разрешает новые production CRUD/deploy/restart сверх выполненного пакета.

### W5 · пользовательские операции

- [x] **1. Сопоставление контрактов и общий auth-патч.** d62b4ad: [карта механизмов/состояний и 14 точек G5](../../installer/controlpanel/W5_CONTRACTS.md). PatchAuth/PrepareAuth расширяют существующие PatchCreate/Prepare/Prepared, без нового adapter/journal/daemon. Точное сравнение прежнего секрета перед заменой/удалением, точный регистр, отказ при неоднозначности и пустом auth-list; create остаётся потребителем общего пути. Memory-runtime lifecycle проверяет disable/enable с прежним секретом/rotate/delete, сохранение unmanaged JSON и canary, verify-only recovery без load и точный rollback. Это не доказательство новых CONNECT и не G5.
- [x] **2. Доменная очередь и общий исполнитель.** Расширить admission/CAS/идемпотентность/сериализацию, encrypted staged credentials, owned_auth и существующий worker для disable/enable/rotate/delete; сохранить master_user/protected, tombstones и capacity100+1. Не подключать неподдерживаемые операции к production.
- [x] **3. Пробы и параметризованные сбои.** Общий runner всех14 точек для каждой операции, SIGKILL/timeout/lost-response/read-only inspect и блокировка неоднозначности. Реальные fresh auth/UoT/TLS/site/control, rotate new PASS/old FAIL/control PASS; отдельные protection/capacity/case/CAS/idempotency/concurrency утверждения.
- [x] **4. Приёмка G5 на копии.** Полный обязательный набор на зафиксированном коммите, матрица результатов каждой операции/точки, версии/среды/наблюдения, переиспользование G0b/G3/G4. Обе SFA/E1/G6–G9 остаются обязательными.

13.11.2026, **W5 1/4, G5 открыт**, код d62b4ad. PASS затронутых пакетов internal/caddy, internal/storage, cmd/vpnctl в полной копии baseline317b1d5+W5 patch, отдельный systemd-run с PrivateNetwork=yes/PrivateTmp=yes/ProtectSystem=strict, GOFLAGS=-p=1 -mod=readonly, файловый proxy. Прогон /opt/empire-vpn/cache/w5-auth-XAtR3pjw; go mod verify PASS, SHA256 go.sum d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825 совпадает с репозиторием. Installed-Caddy флаг и полный набор здесь не запускались. Первые попытки не приняты: неполный source-only архив без templates/helpers; Go-cache заполнил /run (собственные cache удалены); /var/tmp скрыт PrivateTmp. Финальный прогон на диске PASS. Production CRUD/deploy/restart не выполнялись, службы/профили/резерв не менялись.

**Первое следующее действие:** W5 пункт2 — добавить admission пользовательской mutation с expected_version и устойчивым request hash к существующей очереди, затем расширить owned_auth.prepare/finish и worker dispatch, сохраняя прежний journal и процедуру сверки четырёх источников.

14.11.2026, **W5 2/4, G5 открыт**, код b318738. QueueOwnedMutation сохраняет request hash/CAS/reason/owner-run и encrypted staged rotate v+1 в schema5 без смены effective status/current credential до verify; revoke — alias disable. Общий createCaddyWorker dispatch/Prepared/UnixRuntime и прежний panel-auth-pending.json/owned_auth переиспользованы. CLI mutation выводит ApplyNotice; no-op подтверждается без load. При потере ответа load сначала выполняется точная live/fresh-auth сверка; доказанный candidate завершается, неоднозначность блокируется. Профили не выдаются при running/verifying/reconcile/rollback этого пользователя.
PASS на изолированной копии /opt/empire-vpn/cache/w5-auth-XAtR3pjw, baseline317b1d5 + текущие W5-изменения: caddy/storage/vpnctl, 9 Python owned_auth; повтор БД/replay/один secret/конкурентные disable+rotate/protected/tombstone; общий файловый lifecycle всех операций с SQLite отказом после live proof и recovery без load. Отдельный PrivateNetwork/PrivateTmp/ProtectSystem=strict прогон настоящего Caddy+Naive shipped probe: disable/enable/rotate/delete, candidate/revocation/control TCP/UoT/TLS/site PASS. Это отдельные доказательства probe и worker, ещё не полная G5-матрица реального worker со всеми14 SIGKILL. Исправлены два выявленных ограничения тестов: legacy inspector допускает schema5; echo-harness shutdown освобождает порты между сценариями (после первой попытки исправления повтор PASS). Production CRUD/deploy/restart не выполнялись.
Уточнение владельца14.11: [новая policy профилей](../../installer/controlpanel/PROFILE_ROUTING_POLICY.md) — базовый без RU/Download Manager, выключенная опция только для точной SFA1.15.0-alpha.13, предупреждение; 1.14.4 базовый. Синтаксис package_name/rule_set в upstream1.14.4 существует; работа сценария на Android и продуктовая поддержка различаются. Обе сборки доступны; телефонные измерения открыты. Основная внешняя LLD §2/§7 обновлена, существующие профили/immutable revisions не менялись.
**Первое следующее действие:** W5 пункт3 — именованные crash hooks и общий параметризованный runner14 точек для create/disable/enable/rotate/delete; затем полный набор на pinned commit и G5. После него W6 реализует policy вариантов через единый renderer, W7 — общие API/CLI/UI и один сеанс телефона. Новое указание владельца: продолжать до W7 без подтверждений; остановиться перед необходимой остановкой production либо после4 неудачных попыток исправления одной ошибки.

14.11.2026, подшаг **W5/3: именованная crash-матрица PASS**, кандидат52bca15. Единый TestG5NamedCrashMatrix: 5операций ×14границ =70 реальных SIGKILL дочернего канонического worker на файловом Caddy-runtime/синтетических probes; после старта сверены SQLite/точный live old-or-candidate/файлы при success и блокировка reconcile. after_rollback_verify исполняет явную recovery-ветвь того же Prepared.Rollback/owned_auth, не обещает автоматический rollback/restart в production. Крючки доступны только через внутренний callback; environment/API installed worker их не включают. after_desired_stage наблюдает уже durable intent/секрет очереди, повтор не генерирует его заново. Дефект lifetime DB-handle в общей fixture исправлен первой поправкой, повтор70/70 PASS. Полный Python-набор на pinned52bca15:69 тестов,4skip,PASS. G5 ещё открыт до полного pinned Go-набора и расширенной RootDirectory-репетиции настоящего CLI/worker/probes/return; W5 пока2/4. Подготовлен новый disk-backed pinned-каталог, старые прогоны не затёрты.

14.11.2026, **W5 4/4, G5 PASS на копии**, итоговый код64718cf: [протокол](../../installer/controlpanel/G5_ACCEPTANCE_2026-11-14.md). Полный pinned Go-набор с обоими сетевыми флагами PASS, 70SIGKILL/explicit SSH recovery, Python69(4skip)PASS, mod verify/go.sum PASS. Реальная RootDirectory5002 mutations/issuance/return PASS; RootDirectory5003 на6d31aca explicit rollback+complete+replay после SQLite-abort для всех mutation успешно завершилась, подтверждено systemd journal и read-only агрегатами SQLite: integrityok, active2/deleted1, installer_returned. Выходной SSH-транспорт5003 оставался открыт; успех подтверждён независимыми фактами, не молчанием. Последующий diff6d31aca..64718cf только users.go и его тест, реальный worker/probe неизменён; full suite повторён на64718cf. Нет production CRUD/deploy/restart, резерв/старые профили не тронуты.
**Первое следующее действие — W6/G6:** реализовать единый renderer/выдачу базового профиля и выключенной опции RU/Download Manager с exact-version gate1.15.0-alpha.13, immutable approved variants, без изменения выданных профилей; затем общий сеанс на OnePlus12 (обе сборки доступны) с отдельными результатами base1.14.4/basealpha13/optionalalpha13. После W6 — W7 API/CLI/UI через общую доменную очередь, CSRF/авторизация/secret boundaries и сквозной create→status→download. Работа продолжается до W7 по указанию владельца; остановка перед необходимой остановкой production или после4 неудачных исправлений одной ошибки.

### W6 · профили и совместимость

- [x] **1. Immutable варианты и единый renderer.** b54ceae: schema6, InstallRoutingVariants от явно одобренного source checksum; base без RU/DM и ru_download_manager с exact alpha13 gate/ack. Старые revisions/bindings/выданные файлы не меняются, credential не ротируется.
- [x] **2. Общая выдача и аудит.** API использует IssueProfile; before-send транзакция записывает client/variant/revision/profile SHA256. Strict unknown/duplicate/malformed options; несовместимые варианты422, без silent drop. Base по умолчанию, обе версии; optional только sfa-1.15-alpha13 + явный ack.
- [x] **3. Автоматическая проверка копии.** Full pinned Go-набор b54ceae с обоими Caddy/Naive флагами и обоими точными checker PASS. Base1.14.4/basealpha13/optionalalpha13 check PASS, capabilities пустые/PrivateNetwork для отдельной checker-матрицы. Официальный tar.gz alpha13 SHA256 bfc39f643a5ecc1b702c5723ff662e61dde813f12b3af0d0cfce4f629ff74047 сверён Windows/VPS с upstream release manifest; checker только в test-cache, рабочий sing-box1.14.4 не заменён.
- [ ] **4. Телефон и G6.** Три профиля подключаются, owner/panel через Wi-Fi и daria create/download/connect подтверждены. Остаток — фактическая Android DNS/IPv6/RU/app/network матрица и итоговый протокол; Download Manager со сбоями явно отложен владельцем. Не чинить его сейчас и не считать PASS. [Точный статус](../../installer/controlpanel/PROGRESS.md).

14.11.2026, **W6 3/4, G6 открыт**, b54ceae. Полный набор на /opt/empire-vpn/cache/w6-pinned-b54ceae PASS, go.sum прежний; server code/cert/client profiles production не менялись. [Routing policy](../../installer/controlpanel/PROFILE_ROUTING_POLICY.md) отражена в основной LLD §2/§7. Синтаксическая поддержка package_name/rule_set в1.14.4 подтверждается upstream; ограничение опции — продуктовая policy, не утверждение об отсутствии синтаксиса. Старые контролируемые G3/G4/G5 доказательства сохранены с версиями/границами.
**Первый открытый пункт W6 — телефонный сеанс/G6.** Пока общий сеанс ещё не подготовлен, продолжается независимая реализация W7 API/CLI/UI через уже проверенные queue/renderer, чтобы не дробить ручную приёмку телефона. G6 не отмечать завершённым до фактических результатов, W7/G7 также остаётся открытым.

14.11.2026, уточнение W6, код **f482bb6**: policy2 добавляет exact hosts DNS panel.home.arpa→192.0.2.119 и exact TCP443 /32 route по существующему relay allowlist; private routing не расширяется. Schema7 сохраняет все policy1 immutable rows/mappings; старые файлы/credentials не меняются. Full pinned Go с обоими сетевыми флагами PASS; Python69(4skip)PASS; mod verify/go.sum PASS. Отдельная exact-checker+реальная A/AAAA DNS-матрица с пустыми capabilities/PrivateNetwork PASS для base1144/basealpha13/optionalalpha13. G6 остаётся открыт до телефона.

### W7 · API, CLI и интерфейс владельца

- [x] **1. Общие owner API/CLI.** 28b80ec/f482bb6: owner session/Origin/CSRF/CAS/stable idempotency, API и CLI используют прежние queue/worker/renderer. Списки/карточки/история/операции/metadata credential/templates/audits/backups/system; private attachment/profile file, без secret в metadata/stdout. Root recovery явно отделён флагом installation. Значимые API/CLI negative/replay/file-boundary tests PASS.
- [x] **2. Встроенный UI.** Английские экраны users/ops/audit/backups/system; shared ApplyNotice, protected records, unknown state, повтор прежнего intent после потери ответа/перезагрузки; base по умолчанию, RU/DM выключен/недоступен1144. Только DOM textContent, profile bytes не проходят через JS/storage. Неподготовленные W8/W9 действия/измерения явно недоступны; полный E1 ещё не выпущен.
- [x] **3. Сквозная приёмка копии.** af63ab0: исправленный HTTPS sandbox PASS. cd3de10: полный pinned набор и новая root7202 real CLI/TLS репетиция PASS; browser7201 actual downloads всех3 вариантов/protection/version reset/hash-audit PASS с явно зафиксированной эквивалентностью product source. Подробнее — TEST_STATUS и W7_PACKAGE_RECEIPT. Это copy acceptance, G7 требует подключения/телефона.
- [ ] **4. Подключение и G6/G7.** Package/deploy/owner-phone create/download/connect выполнены. Остаток — целевые nonadmin/external наблюдения и совместный приёмочный протокол G6/G7 с разделением доказанного и отложенного. Нового deploy/повтора owner-сценария не требуется. [Точный статус](../../installer/controlpanel/PROGRESS.md).

**Первое следующее действие — W7/3:** завершить проверку исправленного Origin и HTTPS sandbox на новой изолированной копии; далее общий owner API/CLI/browser download, полный pinned набор. W6 3/4; W7 2/4. Production CRUD/deploy/restart не выполнялись. Остановка после4 неудачных поправок одной ошибки сохраняется; Origin исправляется первой поправкой, тестовая browser-download ошибка не объявляется успехом.
14.11.2026, **W7 2/4, остановка по условию четырёх попыток**, код8fc03c7. Исправление browser navigation Origin первой поправкой PASS: Referrer-Policy=same-origin, внешний/null Origin по-прежнему403; auth/API/CLI affected suite PASS. Новый pinned полный Go-набор с VPN_TEST_CADDY_ADAPTER=1/VPN_TEST_NAIVE_PROBE=1 и exact VPN_TEST_SFA_CHECK_1144/ALPHA13 +VPN_TEST_SFA_DNS=1 PASS, Python69(4skip)PASS, mod verify/go.sum прежний. RootDirectory7002 стартовал автономно, API/канонический worker доступны только на копии.

**Блокер W7/3 — frontend sandbox, G7 НЕ принят.** Проверочный runner TLS frontend ещё не готов: исходный + путь InaccessiblePaths в transient RootDirectory не смонтировался (226/NAMESPACE); минимальный вариант без+ запустился. После поправки типа PID frontend слушает18650 с UID981/CapEff0 в сети копии; TLS handshake с trusted synthetic CA/exact SNI состоялся, но GET/ вернул502. Проверка одинакового sandbox затем выявила читаемую secret boundary; конкретный путь ещё не установлен. Это FAIL, не доказанная изоляция и не разрешение снять защиту. Ни candidate unit, ни новый API/UI в production не развёрнуты. В candidate используется API UID981 с mount/seccomp denial, поэтому до доказанного vault/proc-root denial такой frontend не принимать.

Во время диагностики runner были последовательные поправки отображения mount-путей, типа PID, диагностики subprocess и корректности denial assertion (listdir вместо stat каталога). Автоматический approval review отклонил следующую попытку конкретизации пути как продолжение цикла сверх условия владельца. Отклонённый блок не выполнялся; обход/retry не предпринимался. Работа над ошибкой остановлена, нужна явная команда владельца возобновить. Незавершённый runner сохранён для воспроизведения, не для deploy.

**Первое следующее действие после разрешённого возобновления:** прочитать W7_COPY_STATUS_2026-11-14.md и установить конкретную нарушенную filesystem boundary/причину502 на копии; затем выбрать и доказать корректную identity/mount/socket policy. Не продолжать перебор прежних вариантов без новой причины. Owner CLI реального API/download, повтор browser alpha13/download, deploy/rollback package и телефон G6/G7 остаются открыты. Подключение потребует остановки production control plane и отдельного решения по явному условию владельца. Существующий transport/профили/сертификаты/owner credentials/резерв не менялись.
14.11.2026, **документальная передача после9b9ea35, без новых тестов/исправлений**. [Состояние тестирования](../../installer/controlpanel/TEST_STATUS_2026-11-14.md) отделяет PASS/PARTIAL/FAIL/OPEN и ревизии; [промпт передачи](../../installer/controlpanel/HANDOFF-W6-W7.md) содержит пути, коммиты, проблему502/изоляции, незавершённые проверки и границы работы.

Почему начат W7 при открытом W6: после автоматической части W6 агент интерпретировал разрешённую группировку ручных профильных/UI проверок и поручение продолжать доW7 как основание независимой подготовки API/CLI/UI на копии. Это решение о порядке разработки, не закрытие G6 и не отдельное разрешение обходить gate или менять production. Следовало яснее отделить реализацию от приёмки. W6 остаётся первым незакрытым этапом; G6 требует телефона. Галочки W7/1–2 отражают реализованные части, не принятие G7.

**Состояние сохранено:** W5 4/4/G5 copy PASS, W6 3/4/G6 OPEN, W7 2/4/G7 BLOCKED. Full product suite8fc03c7 PASS; frontend isolation FAIL; browser download/alpha13 и real owner CLI E2E OPEN; deploy/rollback package не готов. Проблема sandbox не исследовалась повторно. Cleanup предыдущего хода удалил marker собственного7002 и завершил loopback helpers; стенд не считать живым без новой проверки.

**Первое следующее действие:** прочитать протокол/промпт и получить явное возобновление расследования после остановки. Текущий запрос владельца — объяснение и фиксация состояния, не разрешение продолжить неудачные попытки. После возобновления — установить точный failed path и причину502 на копии, доказать защиту; телефон G6 остаётся обязательным до приёмки. Не запускать production deploy/CRUD/restart.
14.11.2026 — расследование явно возобновлено владельцем; W7/3 frontend harness исправлен.
Новая синтетическая копия: w7-pinned-8fc03c7/rehearsal-root-7101; продуктовые бинарники 8fc03c7.
Диагностика: читаемы /var/lib/vpn-control и /etc/empire-vpn; API connect возвращал ENOENT.
Mountinfo подтвердил отдельный tmpfs /run у frontend с LoadCredential. Без префикса +
InaccessiblePaths адресовали host paths, а не нужные пути RootDirectory. Это дефект harness,
не установленная утечка production. +/run/caddy-admin отсутствовал именно в новом /run.
Исправление pilot/panel_frontend_rehearsal.py: root-relative masks, узкий read-only bind
каталога API в /api (bind под приватным /run также отказал NAMESPACE), синтетический config
с /api/api.sock, RuntimeDirectory для HOME, уникальные transient names, точный failed path.
До запуска проверяется наличие обоих исходных socket. ENOENT допустим только для скрытого
admin socket; secret directories/proc-root требуют PermissionError. Защиты не снимались.
Два последовательных итоговых запуска PASS: UID981/CapEff0/same isolated netns,
vault/proc-root/admin denial, private API socket connect, trusted synthetic CA/exact SNI,
HTTPS login200, no-store/same-origin, unauthorized users401, admin route404.
Полный продуктовый набор повторно не запускался: продуктовый код/unit не менялись,
G6/G7 не принимаются. W6 3/4; W7 2/4, завершён только подшаг HTTPS sandbox W7/3.
Следующий шаг: real owner CLI/browser downloads/alpha13, deploy/rollback package;
production switching требует отдельного согласования, затем телефон G6/G7.
14.11.2026, подшаг W7/3 **real owner CLI + browser profiles PASS**, продуктовые бинарники8fc03c7, исходникиaf63ab0, новый root7201. CLI→real API→общая очередь/worker: create/replay(прежняя квитанция)/confirmed active/rename/stale CAS/protected denial; выдача base1144/basealpha13/optionalalpha13 в0700/0600, no-overwrite, несовместимая опция1144 отвергнута, VPN/session secrets отсутствуют в захваченных stdout/stderr. Из выданного профиля свежие TCP/UoT через настоящую synthetic Naive stack PASS. Test-runner исправлял ожидания parent mode/error-envelope/hosts scalar и paths/NetNS только тестовой fixture; продуктовый код не менялся.

Браузер Root7201 через loopback HTTP test bridge: owner sign-in, protected master_user (нет mutation actions/rename disabled), exact alpha13 opt-in/warning, переход1144 сбрасывает и блокирует опцию, actual downloads всех3 вариантов PASS. Скачанные JSON проверены без печати реквизитов, SHA256/client/variant совпали с profile_issuance через user_profiles; SQLite integrityok. HTTP bridge не выдаётся за phone/production HTTPS. Synthetic скачанные файлы и loopback helpers удалены после сверки; root7201 остановлен собственным marker, ActiveState=inactive/MainPID=0 подтверждены.

Подготовлен offline package builder prepare_panel_upgrade.py и W7_UPGRADE_WINDOW.md: versioned helper paths, фактический private socket, reuse owner/key, read-only-first start, два ограниченных rollback режима без stale-auth restore. Trial bundle33.3MB/hash/mode verify и systemd-analyze verify candidate PASS (посторонние CPUAccounting warnings), установка не выполнялась. Это ещё не весь switch/rollback rehearsal и не G7.

**Первое следующее действие:** зафиксировать текущий source/checker runner/package, запустить обязательный полный набор на этой ревизии и проверить финальный bundle, включая отрицательные integrity assertions/readonly replay syntax. Затем передать конкретный scope подключения на согласование; production switch/CRUD/stop пока запрещены. W6 3/4, W7 пока2/4 до завершения copy acceptance; телефонG6/G7 открыт.
14.11.2026, **W7 3/4 на копии; G7 по-прежнему OPEN**, sourcecd3de10. Полный pinned Go без cache(-count=1) со всеми Caddy/Naive/exact SFA/DNS флагами PASS, Python69/4skip PASS, mod verify/go.sum прежний. Финальные compiled binariescd3de10 проверены в НОВОМ root7202: real owner CLI/create/replay/rename/CAS/protected/profile0600/no-overwrite/no output secrets/freshTCP+UoT PASS; runneraf63ab0/privateAPI/vault/proc-root/admin denial +HTTPS exactSNI/trustedCA/login200/no-store/same-origin/401/404 PASS. Browser variants/protection/root7201 результаты выше переиспользованы: diff8fc03c7..cd3de10 по product cmd/internal/migrations/systemd/frontend template пуст, менялись tests/docs/package tooling.

Offline packagecd3de10:17 files/33,295,255 payload bytes, hash/mode/symlink/unlisted-file negative checks PASS; public template содержит placeholders, systemd syntax и readonly replay sh-n PASS. Approved production source checksum совпал с package source (read-only); integrityok, unfinished0, generation2. Это не production switch. Добавляются к payload существующие совместимые g3_snapshot/g3_restore_runtime рядом с inspector/return, чтобы окно не импортировало исторический schema-limited helper. Новый окончательный payload требует финального pinned прогона/manifest.

**Первое следующее действие:** проверить окончательный payload на зафиксированном source commit и сохранить manifest, затем остановиться перед production control-plane stop/deploy и запросить scope по W7_UPGRADE_WINDOW.md. W6 3/4/телефон OPEN; W7/4 и G7 OPEN. Transport/WG/firewall/routes/owner credentials/реальные профили/резерв не менялись. Действующий код всё ещё69e4708+unit6621689; новый UI не подключён.
14.11.2026, **финальный offline payload ad6b653 проверен**: [receipt](../../installer/controlpanel/W7_PACKAGE_RECEIPT_2026-11-14.md), [публичный manifest](../../installer/controlpanel/W7_PACKAGE_MANIFEST_ad6b653.json), [порядок окна/отката](../../installer/controlpanel/W7_UPGRADE_WINDOW.md).19 файлов/33,306,900bytes; manifestSHA256 e512a536a57256dbaff7025991621551cda11687b14423ebb9ce5abb281b6ba0. Hash/modes + tamper/symlink/unlisted-file rejection PASS; systemd verify/replay-only sh-n PASS. Go binaries побайтно совпали с проверенными cd3de10; diffcd3de10..ad6b653 по product/tests/deps/helpers пуст, повтор полного Go ради packaging-only изменений не выполнялся. Full pinnedcd3de10 остаётся применимым доказательством; добавлены только существующие совместимые snapshot/return helpers в payload.

Root7202 завершён штатно: inactive/MainPID0/Resultsuccess. Production read-only preflight: approved source checksum match, integrityok, unfinished0, generation2. **W7 3/4; W7/4/G7 OPEN, W6 3/4/G6 OPEN.** Package не заменяет ещё не выполненный полный production switch/rollback/телефон.

**Первое следующее действие — согласовать конкретное окно W7_UPGRADE_WINDOW.md для API/worker/private frontend.** До остановки — свежий root-only+encrypted/decrypt/hash-verified snapshot, capture/replay current transient unit и сравнение policy/identity/paths. Нового production deploy/CRUD/stop не было. Без согласования остаёмся на copy; transport/WG/firewall/routes/резерв/пароли/ownerCA не менять. После отдельно согласованного подключения — общий фактический телефонный сеанс G6/G7.
14.11.2026, **согласованное production-подключение W7 выполнено**, [протокол](../../installer/controlpanel/W7_PRODUCTION_WINDOW_2026-11-14.md). Разрешение владельца «действуй» относится к описанному API/worker/private frontend окну. Packagead6b653/Go buildcd3de10 deployed; versioned helper directoryad6b653; worker unit6621689/default root identity сохранён. Schema7/integrityok/active4/gen2/unfinished0; owner/key/credential fingerprints и старые profile/auth/config bytes/owners/modes/xattrs сохранены. API/panel/timer активны, новый frontend enabled, прежний readonly endpoint заменён.

Fresh core+control pre и corepost root-only, Windows encrypted/decrypt/hash-verified прежним owner recipient; ни ключи, ни пароль не пересозданы. Read-only-first owner/API проверки, actual frontend mount/UID981/CapEff0/proc/vault/admin denial, owner/nonadmin/Origin401/403/404, external privateport/Host/SNI denial, existing canary freshTCP/UoT/TLS/site/control до/после PASS. Новые SSH обеих нод PASS; transport PIDs/restarts/config/gen unchanged. Guard завершён/отменён, windowcomplete. API/readonly были остановлены примерно10:34:48–10:37:20МСК; transport не останавливался. Технические поправки installer/test harness описаны в протоколе; private backup не перезаписывался.

Агент production CRUD/rotate не выполнял. После закрытия окна выданы3 новых phone files существующего canary с ПРЕЖНИМ credential; checker3/3/Windows private ACL PASS, старые файлы не менялись. Temporary verification admin sessions отозваны, scratch helpers/резервная SSH-сессия очищены. Public window/check scripts сохраняются в pilot; raw snapshots/profiles/passwords вне Git.

**Первое следующее действие — телефон OnePlus12 с владельцем.** У него есть точные локальные пути новых профилей и логинowner; импорт/VPN3–5мин/panelTLS/admin login на1144 ещё не подтверждены, затем basealpha13/optionalalpha13 и Wi-Fi/mobile/RU/реальныйDM. Вопросы о пути/логине не засчитывать как PASS. **W6 3/4/G6 OPEN; W7 3/4/G7 OPEN, E1 не выпущен.** До фактических результатов не закрывать этапы и не делать новых production CRUD/transport/network/restart действий вне согласованного scope.
14.11.2026 — телефонная проверка владельца: первый base-профильSFA1.14.4 импортирован, VPN подключился, вход в новую панель успешен; владелец сам создал daria, скачал её профиль и подключился через него. Это фактическое owner phone create→result→download→connect, не агентский CRUD. Android build/тип сети/точное время стабильности пока не сообщены. Read-only подтверждение сервера: daria active/version2, user.create succeeded, выдача записана; active5, generation3, integrityok.

Снимки окна до daria теперь исторические: полный rollback старого SQLite/auth запрещён без CURRENT active-user export/fresh snapshot. Control-only recover сохраняет текущий registry/credentials при несовпадении baseline. Пользователи/пароли не откатывались.

Дальше — basealpha13/optionalalpha13, RU/domain/IP и реальный Download Manager. Предложена внешняя проверенная Cloudflare20MiB ссылка (HTTP200/application/octet-stream/Content-Length20971520); она проверяет не-OpenAI DM/direct. Загрузку ChatGPT/OpenAI черезVPN требуется подтвердить отдельно, локальный файл/переход по ссылке не доказывает это. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN; недостающие телефонные измерения не закрыты.
Уточнение запроса тестового файла: владелец требует20MB пустышку, размещённую во внутреннем хранилище ChatGPT с HTTPS attachment link. В данном сеансе доступен Windows workspace, но tool для произвольного file attachment/upload в ChatGPT не предоставлен. Проверенная внешняя Cloudflare-ссылка и локальный file link не заменяют OpenAI download; эта часть проверки не выполнена. Никакая локальная ссылка не объявлялась OpenAI attachment. Инструменты publication/production для обхода этого ограничения не использовались.
14.11.2026 — владелец подтвердил: «все3 профиля проверил, подключаются работают». Записан PASS подключения и базовой работы на телефоне для base1144, basealpha13 и optionalalpha13. Ранее отдельно подтверждены owner login/создание daria/download/подключение её профиля. Это не самостоятельное доказательство маршрута Download Manager/RU, DNS/IPv6 leak, Per-App или работы Wi-Fi+mobile; Android/точная строка сборки/сеть/длительность пока не сообщены. Production изменений агент не выполнял. Первое следующее действие — уточнить фактически проверенные сеть/панельalpha13/RU-DM маршруты. G6/G7 не объявлять полностью принятыми по одному факту подключения.
14.11.2026 — актуализация по последним сообщениям владельца: owner/panel наalpha13 работают черезWi-Fi. Скачивания ChatGPT: сбои наa13/Wi-Fi+mobile; daria/Wi-Fi PASS, mobile FAIL; степень охвата остальных профилей не уточнялась. Владелец явно отложил эту старую отдельную проблему и поручил не разбирать бэклог и не блокировать дальнейшую разработку. Диагностика/правки профилей не проводились; полного PASS G6 для загрузок не ставить.

Новый текущий запрос — ТОЛЬКО инвентаризация и первый план перехода на Lead+2 SOL Subagents. [Предложение и инвентаризация](../../installer/controlpanel/PARALLEL_PLAN_2026-11-14.md), baseline5cb0600. Подтверждены существующие W0–W7 артефакты, неполнота общего W8 backup/restore/audit workflow и G8 resource proof. RAM≤500MB — новое отдельное ограничение владельца в дополнение к прежнему disk≤500000000bytes; caps не заменяют замеры. Рабочая nonproduction Linux-среда пока не подтверждена; существующие копии наhh-entry физически наproduction и не разрешены Subagents.

**Первое следующее действие — получить согласование PARALLEL_PLAN_2026-11-14.md.** До него агентов не запускать, worktrees/implementation не начинать, production не менять. После — Lead owns common contracts/migrations/integration; SOL-A backup/restore proof, SOL-B independent security coverage/review, disjoint files и checkpoint перед merge.3 неудачные поправки сложного бага→ASTRA в свободный слот; прежний4-attempt stop не сбрасывается. W6/G6 и W7/G7 формальные статусы этой инвентаризацией не переоформлялись; полный E1 не выпущен.
14.11.2026 — владелец согласовал первый параллельный план и автоматическую ASTRA-эскалацию с обязательным включением случаев и поагентных шагов/статусов в отчёты. Baseline84c5262; созданы два отдельных worktrees, запущены SOL-A backup/restore и SOL-B SEC/review. [Журнал агентов](../../installer/controlpanel/PARALLEL_STATUS.md), [границы интеграции W8](../../installer/controlpanel/W8_INTEGRATION_CONTRACT.md). Найден и исполнен bundled Python3.12.14/SQLite3.53.1/cryptography50.0.2 без установки; Linux runtime gate остаётся непроверенным. Первое следующее действие — независимое review кандидатов и контракта, затем последовательная интеграция с checkpoint и portable тестами. W6/G6 и W7/G7 не закрыты, production не затронут.

14.11.2026 — первый согласованный parallel round интегрирован. Lead4/4; SOL-A3/3 portable (source6dde629, integrated7e0d761); SOL-B3/3 + SEC mapping2/2 (source2ba7245/7fdb84e, integrated7ff71f5/4d64384). Общее targeted Python tests/test_w8_*.py на4d64384: Ran13 OK/no skips, Python3.12.14/SQLite3.53.1/cryptography50.0.2. B независимо проверил A, A проверил B, оба проверили Lead contract; review fixes применены до интеграции. Полный продуктовый набор не запускался, новый gate не принимается. Artifact inspector read-only/streaming, возвращает только artifact_check_passed с registry_consistency=not_run; не новый backup/crypto/journal и не пригодный restore. Ограничения PAX/xattrs/private immutable staging/DB binding/живой restore/ресурсы явные. Найдены пробелы текущего SEC collector; не исполнялся. [Поагентный статус/ASTRA](../../installer/controlpanel/PARALLEL_STATUS.md), [отчёт backup](../../installer/controlpanel/reports/W8_BACKUP_CANDIDATE.md), [SEC review](../../installer/controlpanel/reports/W8_SECURITY_REVIEW.md).

Владелец сообщил об отсутствии отдельного Linux и поручил выбрать среду. Lead выбрал локальный WSL2 перед production: Windows19045/виртуализация/SLAT подходят, WSL и VirtualMachinePlatform disabled; включение требует Windows admin/UAC и ручной перезагрузки. [Конкретные команды и порядок возврата](../../installer/controlpanel/LOCAL_LINUX_RUNNER.md) подготовлены; ничего не устанавливалось/не перезагружалось. Первое следующее действие — выполнить local administrator enable с -NoRestart и согласовать удобную ручную перезагрузку, затем подтвердить отдельный Linux/systemd runner и продолжить W8 integration/runtime proof. До того portable пакеты завершены, Linux proof NOT_RUN. Production не читался/не менялся, BACKLOG не трогался. ASTRA0, неудачных исправлений0. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN, G8 не принят, E1 не выпущен.

14.11.2026 — владелец явно согласовал локальное развёртывание WSL2. Lead выполнил проверенный SOL-B1/1 скрипт через Windows UAC: Microsoft-Windows-Subsystem-Linux и VirtualMachinePlatform Disabled→Enabled, оба RestartNeeded=true; отдельный CIM подтвердил InstallState1, helper завершён. -NoRestart соблюдён, автоматической перезагрузки нет. Receipt и SHA/порядок продолжения — [LOCAL_LINUX_RUNNER.md](../../installer/controlpanel/LOCAL_LINUX_RUNNER.md), raw receipt вне Git в worktrees/wsl-setup-20261114/receipt.json. Lead local runner1/3 (компоненты), distro/systemd и runtime tests ещё не выполнены; SOL-A3/3 portable завершён/idle, SOL-B3/3+mapping2/2 завершён, дополнительное review установки1/1 PASS; ASTRA0/failedfix0. Production не затронут. Первое следующее действие — владельцу сохранить работу и вручную перезагрузить Windows, затем сообщить о возврате; Lead проверяет WSL engine/distro и продолжает стенд. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN, G8 не принят.

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

14.11.2026 — local runner3/3 квалифицирован, [полный протокол](../../installer/controlpanel/W8_LAB_QUALIFICATION_2026-11-14.md). Pinned78515f4: полный Go с Caddy/Naive/двумя SFA/DNS в PrivateNetwork PASS, Python82/skipped4 PASS, RootDirectory frontend8202 UID981/CapEff0/denials/privateAPI/TLS PASS, actual ownerCLI/3privateprofiles/freshTCP-UoT PASS. Полная mutation/rollback/reconcile/installer-return копия8204 PASS. Go mod verify и go.sum repo hash PASS. Интегрирован независимо проверенный raw-tar guard2ae9706; полный Linux Python84/skipped4 PASS, Goкод/deps785..2ae не менялись (reuse, не новый прогонGo). Копии8201/8202/8204 inactive/MainPID0;8201 прерван и не PASS,8203 частичный после преждевременной подготовки/ETXTBSY сохранён. Нет оставшихся продуктовых процессов. Локальная identity981 provisioned locked/nologin; все защиты сохранены. Подробные причины/первые успешные исправления/WSL keeper и ограничения в протоколе. Caddy локально побайтно совпал с историческим hash; read-only scp attempt был отклонён publickey, production не менялся.

Lead3/3; SOL-A inventory3/3+singbox2/2+Caddybuild3/3+rawguard3/3 завершены; SOL-B portability3/3+suite2/2+Caddyreview1/1+rawreview2/2 завершены. ASTRA0/failedcorrections0. Первое следующее действие — W8 canonical snapshot/DB-generation/vault binding и совместимый producer/restore proof через существующие механизмы. Прототип не ставит verified; PAX/ACL/envelope streaming/usablebackuprestore/полныйdisk+RAM gate открыты. W6 3/4/G6OPEN, W7 3/4/G7OPEN, G8OPEN, E1 не выпущен. Приёмка локального runner не закрывает продуктовые gates.

### Текущие продуктовые пункты W8 (детализация прежней очереди)

- [ ] **1. Общий backup workflow.** Canonical consistent SQLite/WAL/generation/vault snapshot, encrypted create/verify/restore-plan/prune через прежние operations/API/CLI. PARTIAL: helpers/prototype/metadata есть, пользовательский workflow не готов.
- [ ] **2. Security.** Полный secret inventory/SEC audit/hardening/master-key rotation. PARTIAL: gap matrix/synthetic checks/frontend denials есть, полная реализация/приёмка нет.
- [ ] **3. Restore drill.** Encrypted backup->isolated restore->owner login->active old profile PASS/revoked FAIL; rollback/current-user preservation. Не заменять installer return или tar check.
- [ ] **4. Resources и G8.** Полные disk/RAM/backup-restore-retention peaks и security/restore acceptance на pinned ревизии.

### Текущие продуктовые пункты W9 (детализация прежней очереди)

- [ ] **1. Release candidate компонентов.** Кандидат компонентов панели после G6–G8 и выпускной pinned E2E/security/recovery набор.
- [ ] **2. Load/soak.** Capacity12/50/100+master,5 UI observers,30 изменений,24часа.
- [ ] **3. Rollout/coexistence.** Canary/installerCLI coexistence/cold reboot/rollback в отдельно согласованной целевой среде.
- [ ] **4. G9 компонентов.** Финальные runbooks/приёмочный отчёт/согласование компонентов панели. Общий выпуск E1 требует G9.1.

14.11.2026 — исправлено представление общего прогресса, без кода/тестов/production изменений. Единый [PROGRESS.md](../../installer/controlpanel/PROGRESS.md) отделяет6/10 закрытых этапов, продуктовые W8/W9 пункты и подготовку стенда3/3. Старые формулировки W6/4 «измерений нет» и W7/4 «подготовить deploy» актуализированы: телефонные подключения/owner/daria и deploy уже выполнены. Gates не закрывались автоматически; G6 недостающая Android route/network matrix и отложенный DM; G7 целевые nonadmin/external наблюдения+итоговый протокол. W8/W90/4 означает отсутствие полностью закрытых верхних пунктов, не отсутствие частичных наработок. Первое следующее действие — W8/1 canonical consistent backup/DB-generation/vault binding. Агенты последние пакеты завершили; ASTRA0.

### W9.1 · интеграция в общий установщик (после W8/W9)

Контракт985e04a: [W9_1_INSTALLER_INTEGRATION.md](../../installer/controlpanel/W9_1_INSTALLER_INTEGRATION.md).
- [ ] **1. Пакет.** Состав runtime/совместимость/checksums, единая версия bootstrap Windows/macOS.
- [ ] **2. Чистая установка.** Штатный мастер новой VPN-пары вместе с приватной панелью/owner bootstrap.
- [ ] **3. Существующая пара.** Legacy подключение и идемпотентное обновление принятой панели с сохранением данных/профилей.
- [ ] **4. Восстановление.** Прерывание/сверка/повтор/возврат через принятые механизмы; сохранить актуальные credentials.
- [ ] **5. Публикация.** README/GUIDE/команды/версия/release notes и проверенный опубликованный пакет.
- [ ] **6. G9.1.** Полная матрица опубликованных команд Windows/настоящий macOS/legacy/existing panel/interrupt/security/reboot/resources.

14.11.2026 — прочитан и сохранён пользовательский985e04a, включая обновлённые Architecture/LLD v1.1 в родительской папке вне Git. Оба SOL-агента уведомлены: W8→W9→W9.1, G9 принимает только компоненты панели, общий E1 дополнительно требует G9.1; нумерация W10+ сохраняется. Единый progress теперь6/11, W9.1 0/6. Текущий кодовый приоритет прежний W8/1, W9.1 не реализуется досрочно. SOL-A продолжил raw-tar boundary fixtures; SOL-B — canonical SQLite/WAL/generation/vault inventory. Production не менялся; ASTRA0. Следующее действие — закончить эти независимые W8-пакеты/проверки и зафиксировать canonical snapshot контракт Lead.

14.11.2026 — продолжены именно W8-задачи после roadmap985e04a: SOL-A raw count/size/end fixtures3/3 sourcefa6c55a→d576dcc, target11testsPASS на bundledPython3.12.14 после интеграции; SOL-B canonical binding inventory2/2 source6d92468→8202ed1, source-backed report-only. Lead уточнил W8_INTEGRATION_CONTRACT: общей scalarDBgeneration нет, manifest/peruser/pernode версии различны, Open мигрирует, auth/session/issuance не считать остановленными одним installationflock; callback/onlinebackup/проверки остаются реализацией W8/1. Новых BKP endpoint/verified/acceptance не заявлять. W9/G9 принимает компоненты, общийE1 требуетG9.1. Первыми по-прежнему W8/1 и связанные проверки, не installerW9.1. W6 3/4 · W7 3/4 · W8 0/4 fullyclosed(partial1–2) · W9 0/4 · W9.1 0/6. ASTRA0/failedfix0, production не менялся. Полный productнабор не повторялся для test/report/contract-only группы; прежние квалификационные результаты774c07a сохранены.

14.11.2026 — ПАУЗА по явному запросу владельца (лимиты). [Точка возобновления](../../installer/controlpanel/RESUME_W8_2026-11-14.md). WIP fcea3d4 сохраняет Registry.InspectSnapshot + shared vault/migration refactor; НЕ скомпилирован/НЕ протестирован/не к deploy. SOL-B review emptyownID blocker исправлен первой попыткой, повторное review PASS. Независимые SOL-A tests3a1882c/2596b40 сохранены в restorebranch, НЕ интегрированы/НЕ запускались; перед запуском нужны fixture corrections(master отсутствует в mutationFixture, CHECK/FK corruption setup, согласование typederror). Агент A прерван, B idle, новых заданий/прогонов до возобновления не запускать. Первое следующее действие после нового транша — исправить эти fixtures, определить ErrSnapshotState wrapping, составить pinned candidate+tests и выполнить targetstorage/общиепотребители на локальной копии. GoWIP не покрыт прежним полным набором. E1 6/11; W6 3/4 · W7 3/4 · W8 0/4fullyclosed · W9 0/4 · W9.1 0/6. ASTRA0/failedcorrections0. Production не менялся.

14.11.2026 — возобновлено по запросу владельца, глобальный C:/Users/a.filatov/.codex/AGENTS.md прочитан. Tool-presets подтверждают explorerLunaHigh/coderSolLow/lead_coderSolMedium/architectAstraMedium; coder и lead_coder реально запущены для текущих независимых задач, explorer/architect без необходимости не запускались. Настройки модели главного чата инструмент не раскрывает/не менялись. Новая маршрутизация coder2неудачныхfix-validation→lead_coder, lead_coder3→architect; старое ограничение владельца4неудачныхисправления однойпроблемы сохраняется как stop, счётчики не обнулять между ролями. Без nestedagents, минимальные контексты/непересекающиесяфайлы; сейчас2субагента.

Кодер snapshot_fixtures_resume исправил тестовыеfixtures master/CHECK/FK/tombstone, source84e70f5→fa803e8; Lead отформатировал c4bf7bb. Ошибки credential проверки классифицированы черезerrors.Join(ErrSnapshotState,err) b50cd99, независимоеlead_coder reviewPASS. Первые Snapshot target tests наc4bf7bb в локальномPrivateNetwork PASS (8именованныхтестов+subcases,1.422s). Код/тесты прежнегоWIP впервые скомпилированы. Сейчас Go-потребители общейvault/migrationлогики запущены; полныйPython/исследования неизменённой среды не повторялись. Production не менялся. Snapshot helper НЕ создаётbackup и не повышаетverified, общийDBgenerationне введён; следующийшаг после потребителей — actualonlinebackup/stagedDB+file binding подпрежнимlock. W8 0/4fullyclosed; G6/G7/G8/G9/G9.1 открыты, E1 6/11. Architect/ASTRA0, неудачныхfix-validation0.

14.11.2026 — завершён проверенный подшаг W8/1 snapshot inspection. [Протокол](../../installer/controlpanel/W8_SNAPSHOT_INSPECTION_2026-11-14.md), pinnedc4bf7bb: targetSnapshot8именованных+subcasesPASS; все затронутые Goпотребители ./...count1 сCaddy/Naive/обеимиSFA/DNS вPrivateNetworkPASS. Старый WIPfcea теперь покрыт этими тестами. Кодер3/3fixtures послеLeadintegration/validation; lead_coder1/1independentsecurityreviewPASS; orchestratorintegration/target/consumersPASS. Роли explorer/coder/lead_coder/architect подтверждены tool-presets, запущены только необходимые coder/lead_coder; mainmodelsettingsнеподтверждаем/неменяем. Не повторяли прежние исследования/Python/неизменённые runtimeсценарии; consumerповтор нужен иззаобщегоvault/migrationrefactor. Productionне менялся, architect0, failedfix-validation0. Следующее действие — actualSQLiteonlinebackup/capturedDB+managedfilebinding под прежнимwriter, не считатьpreflight гарантирующим будущуюкопию. W6 3/4·W7 3/4·W8 0/4fullyclosed(partial1–2)·W9 0/4·W9.1 0/6. E1 6/11, все последующиеgatesостаютсяOPEN.

14.11.2026 — завершён подшаг W8/1 SQLiteonlinecapture. [Протокол](../../installer/controlpanel/W8_ONLINE_CAPTURE_2026-11-14.md). lead_coder3/3 one-file implementation62d44b3→e0eef09, coder3/3 independentfixtures0760583/ebc33e8→c065132/5b01836, orchestrator review/integration/actualLinux testsPASS. Initialtargetadd2d78PASS; finalpinned5b01836 fullaffectedstoragePASS5.297s includingexternalWALwriter+20MiBcut, standaloneimmutableDB/SHA/size/permissions/uniqueoutputs, cancel/unfinished/unsafeparent/oversizecleanup. No newcapturetestskips; storage-onlyrun skipped3unconfiguredSFAchecker subcases+subprocessguard, notnewfull-engineproof. Priorc4bf7bb exactengineconsumerresults reused for unchangedcode, no routinePython/fullGo/runtime repeats. Productcode/dependencies/units outside newfiles unchanged. Capture validates copiedDB, notlivepreflight; outputprivateplaintextstaging only, no backupverified/API/queue/restore claim. PrimarySQLiteAPI semantics documented; tests firstattemptPASS, failedfix-validation0/architect0. Новые правила эффективности приняты: focusedreads/output, no unnecessaryagents/retests. Production не затронут. W8 0/4fullyclosed(partial1–2); E1 6/11, W6 3/4 W7 3/4 W9 0/4 W9.1 0/6. Первое следующее действие — capturedDB+managedfile hashes/generation/owner-run под существующимwriter, затем encryptedartifact/operationmetadata через прежние механизмы.

14.11.2026 — W8/1 binding подшагPASS, [протокол](../../installer/controlpanel/W8_BINDING_2026-11-14.md), pinnedbf04c54. СуществующийwithOwnedInstallation/lock переиспользован1раз, actualcopiedDB проверяется с observedvaultkey иcanonicalowner-run; boundedSHA observations manifest/auth/manifest.Files/key до/после, отказpending/prepared/unsafe/drift, удаление толькоnewchild сошибкамиcleanup. ОбщийverifyOwnedFiles потоковый, без snapshot32MiBpolicy дляобычныхmanagedfiles;33MiBcompatregressionPASS, typedLegacyDrift сохранён. Targetcmd2.495sPASS +5directstoragekey/owner casesPASS; fullaffectedGo ./...count1 сCaddy/Naive/обеимиSFA/DNS вPrivateNetworkPASS (CLI85.931s,storage7.334s). Первыйtargetb511failed иззаневерногоfixturebasename; coder5cb43c2→bf04c54 исправилпервойпопыткой безослабленияguard. lead_coder3/3, coder3/3, orchestratorreview/integration/validationdone; architect0/failedfix-validation0. ФайлыmanagedещёНЕскопированы/НЕзашифрованы, liveCaddyfreshness/backupverified/endpoint не заявляются. SourcecanonicalOpen сохраняетсвоюmigrationполитику, неиспользоватькакpre-upgradelegacybackup. Следующее действие — copyingobservedfiles+existing_envelope sealing втомжепрежнемwriter callback, проверитьcopiedbytes; не nestedflock и неcopyafterunlock. W8 0/4fullyclosed, E1 6/11; W6 3/4·W7 3/4·W9 0/4·W9.1 0/6, G8 не принят. Productionне менялся; Python/неизменённыеruntimeпроверкинеповторялись.

14.11.2026 — W8 integration checkpoint b67290b (не G8). Schema8/maintenance f9f579c+297d770, streaming JWE 4b0f37e/7f7305f, writer-bound archive90f30fa, canonical readonly verifier fafc865, safe inventory be625db. Target integration on pinned b67290b in local VPNControl-Lab / PrivateNetwork PASS: storage Maintenance/admission1.454s, CLI archive/snapshot/owner targets1.080s; API compiled, selected pattern matched no API tests (not endpoint acceptance). Separate SOL tests: maintenance0.472s PASS, archive targeted PASS, safe Python collector12tests PASS. Both admission orderings + separate SQLite connections covered; immutable per-attempt owner attestation preserves earlier successful restore proof. All22 audit checks normalized, unknown/not_run and destructive skips remain honest; safe inventory alone is not full audit PASS. Archive currently refuses xattrs/ACL explicitly, restore support remains open. API/CLI/worker create/verify/download/cancel/prune wiring requires actual runtime proof; no verified artifact/restore/G8 claim.

Lead integration in progress. SOL-A streaming3/3+archive3/3 done, offline restore verifier in progress. SOL-B maintenance3/3+safe inventory3/3 done. Planned ASTRA case W8-SEC-001 reviewed crypto/schema/CAS/restoreprep; review corrections applied (immutable evidence, reverse admission, bounded helper stdout). Debugging escalations0, failed corrective attempts0. Production untouched. W8 0/4 fully closed (partial1–2), W6 3/4 G6OPEN, W7 3/4 G7OPEN, W9 0/4, W9.1 0/6; E1 6/11 and unreleased. FIRST NEXT ACTION: authenticated offline restore verifier and NEW-root normalization, actual owner API/CLI encrypted backup roundtrip, copy-only vault rotation, resource/identity matrix and required pinned full suite. Continue through W8 per owner; no pause/checkpoint-as-completion.

## 15.11.2026 — PAUSED: актуальная точка передачи

Владелец явно остановил разработку 14.11; новых разработок/тестов 15.11 не запускали. Сохранение точки после остановки было прервано лимитом automatic approval review; теперь незавершённые файлы сохранены: main bf6f693 (vault rotation WIP, НЕ compiled/tested) и отдельный c99e9b0 (API/worker tests WIP, итоговый PASS не получен). Последняя функциональная интеграция fc2ec74. Полная передача: [HANDOFF_W8_2026-11-15.md](../../installer/controlpanel/HANDOFF_W8_2026-11-15.md); готовый [промпт продолжения](../../installer/controlpanel/CONTINUE_W8_PROMPT_2026-11-15.md). Эта запись отменяет прежнее указание продолжать без паузы до нового разрешения владельца.

Дополнительно подтверждено до остановки: pinned b67290b Python18tests PASS2.556s; SOL-A verifier0bc5513→fc2ec74 targeted PASS, интегрированный full suite ещё не запускался. W8 0/4 fully closed, G8OPEN; E1 6/11, W6 3/4/G6OPEN, W7 3/4/G7OPEN, W9 0/4, W9.1 0/6. Lead остановлен; SOL-A streaming/archive/verifier по3/3, ACL/xattrs ещё не реализованы; SOL-B maintenance/inventory по3/3, новые API/worker tests WIP; ASTRA1 planned case W8-SEC-001, debugging escalations0/failed corrective attempts0. Остаточные тестовые процессы WSL не считать подтверждённо остановленными: финальная read-only проверка до обрыва не вернула наблюдение. Production не менялся, push не выполнялся, BACKLOG не затронут.

FIRST NEXT ACTION после явного возобновления: читать состояние собственных тестовых units, review двух WIP testfiles c99e9b0, подготовить новый pinned candidate и выполнить целевые API/worker tests; параллельно независимый ACL/xattr пакет по HANDOFF. Не начинать с повторного исследования/переустановки стенда. Restore preparation/rotation/version handling/prune/audit/full restore/resources/полный G8 остаются открыты.

## 15.11.2026 — W8 возобновлён, локальная разработка до W9.1

Новое разрешение владельца отменяет паузу разработки; production остаётся вне разрешения. Чтением VPNControl-Lab: собственных w8-* units и оставшихся тестовых процессов нет. HEAD исходной точки9c2e032/worktrees соответствуют HANDOFF; BACKLOG не читался/не менялся.

Проверенный подшаг: два testfiles c99e9b0 перенесены отдельно b1e8a67; после исправления fixtures9c197d7 настоящий owner API target PASS0.550s в PrivateNetwork/offline, mod verify PASS/go.sum unchanged. Worker выявил fixture mode0664 helper, исправлениеc006bc8 пока ожидает повтора. Компиляция bf6f693 подтверждена, поведение ротации не принято.

В работе: ACL/xattrs SOL-A; copy-only rotation/version corrections SOL-C; offline encrypted verification CLI Leadc392022/09bd461 (crypto roundtrip test ещё не выполнен). ASTRA W8-SEC-002: условный design review, реализация требует устранения UID/ACL-principal/defaultACL замечаний и тестов. G8OPEN/W8 0/4; E1 6/11. Первый следующий шаг — pinned targeted ACL, затем общий API/worker/rotation/offline CLI target на новом source. Далее restore preparation/plan, prune/audit, actual isolated restore/resources и pinned full suite. Старые доказательства не распространяются на новый код.

15.11.2026 — pinned4dd8956, VPNControl-Lab, отдельный PrivateNetwork unit w8-rotation-4dd8956-20261115: rotation5named storagePASS0.513s; offline encrypted roundtrip/parent-ownership + actual maintenance worker CLI PASS4.171s; ownerAPI PASS0.460s. go.sum d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825, go mod verify PASS. Это первый фактический PASS прежнего vault WIP после fixes492da0b/406f88b; copy-only, без activation/swap и postcommit crash claim.

SOL-A ACL pinnedcdb3d82 + format ebd28cd target ManagedArchive PASS3.417s/PrivateNetwork; actual binary user attr + POSIXACL readback/UID65534 read allowed write denied; negative defaultACL/unapproved ACL hash/metadata failures PASS. Review ASTRA W8-SEC-002 findings addressed in code. Fourfiles integrated6f89bfb with shared trustedRecoveryParent guard; integrated target still pending. Staging remains0600/noACL; explicit destination policy required for new-copy metadata application. W8 0/4/G8OPEN. FIRST NEXT ACTION: finish reviewed restore preparation NEW copy, target it plus integrated archive/offline tests; actual restored stack login/profile/revoked/Caddy/rollback still required before gate/resource/full suite.

15.11.2026 — restore-copy integration: b0dbd99 actual13scenarios PASS1.584s (exact captured target/intent/owner/request mismatch, other unfinished, session removal/owner+intent history/audit binding, transaction abort/source unchanged, copy-SHA before normalization). 03bb43f real encrypted worker→offline CLI --prepare-parent→canonical prepared DB PASS2.025s; private recovery fixture corrected first attempt, product parent checks unchanged. Linux PrivateNetwork/offline, mod verify/go.sum PASS. ASTRA no blocking code defects under authenticated immutable-source contract. Product runtime restore still not PASS. Inner fe84121/c73fdae + host2df0c9a drill now assigned SOL-C for actual second RootDirectory/source rollback verification. First next action: observe actual runtime outcome and fix concrete failures within budgets; then restore-plan/prune/audit/resources/full pinned suite. G8OPEN/W8 0/4.

15.11.2026 — actual source runtime checkpoint: pinned0c05a61, VPNControl-Lab run851541 source unit success/inactive/MainPID0; real ownerCLI/commonworker produced encrypted backup and removed plaintext work. Owner session fixture now private0700; previous UUID/private-parent refusals were genuine CLI guard behavior. Full historical mutation matrix run851521 passed before backup fixture failed; future backup branch reduced to required create/revoke to avoid repeating that matrix. Loader umask fixture issue fixed (one failed corrective attempt, secondPASS); CLI fixture issue fixed (one failed correction, secondPASS). No production.

Offline real archive rejected member_policy: managed manifest includes /usr/local/bin/vpn-add-user0755 rootroot, producer captures it but caller roots lacked explicit wrapper policy. W8-SEC-003 conditionally approved exact trusted path+SHA, rootroot0755/noattrs; main2c5733e adds explicit CLI/source-root policy, default denial retained. Runtime continues from preserved ciphertext/source with NEW destination, not repeated backup. Wrapper targets and resumed restore still pending. Readonly PlanRestore849edc8 targetPASS0.334s; caller fresh manifest/CLI wiring still needed. Prune/audit WIP is not compiled/tested or accepted. W8 0/4/G8OPEN; next actual result is recovery-only restored runtime with wrapper policy, followed by CAS prune/audit and remaining resource/full-suite matrix.

15.11.2026 — continuation interrupted by agent usage limit, not four-fix failure. Latest code8708435, exact continuation [HANDOFF_W8_CONTINUED_2026-11-15.md](../../installer/controlpanel/HANDOFF_W8_CONTINUED_2026-11-15.md). Source851541 real encryptedbackupPASS; restored runtime851571 owner/oldprofile/revoked/CaddyPASS, source rollback scratch failure;8708435 fix NOT rerun. Prune/audit remains uncommitted/uncompiled/untested and implementation review incomplete. Readonly WSL check after interruption0 own units/no product processes. First next action recovery-only latestcontroller+preserved source+NEW destination, then review/pin/target pruneaudit WIP. W8 0/4/G8OPEN, E1 6/11; production/BACKLOG untouched.

## 15.11.2026 — W8U investigation / activation approval boundary

Baselinef75d135 clean, no laterchanges. U-first queue adopted; Eprune/rollback not resumed. W8U0/4, W8E3/8E_PASS_REUSED unchanged. Existing ownerbackup/create/download+crypto/verifier remain reused partial evidence.

Storageprototype d326bcd + independentfixtures697adc2/d57b85b/86932c8/e88b182 preserved on branch wip/w8u-portable-adapter-20261115, removed from functional main pending review/completion. NOT user-ready or testedPASS. Target first hung due fixture nestedquery with MaxOpenConns1; test corrected. Last target86932c8 failed testsyntax setup; correctede88b182 not rerun. Ownunits inactive/MainPID0. Publicclean rejection currently CODE REVIEW evidence only: InstallInitialSFA generates variants rejected by prototypeguard. No product acceptance inferred.

Actual missingglue bigger than simple CLIcall: legacy handoff compares destination snapshot credentials and requires provisioning/v1; existing finalizer activates ALL records. Portable disabled/status semantics need explicit samejournal beforeimage/afterimage branch and portable finalizer, plus owner CLI + oneclean-installE2E. Candidate-only import is not W8U completion. Concrete bounded plan [W8U_PORTABLE_ACTIVATION_PLAN.md](../../installer/controlpanel/W8U_PORTABLE_ACTIVATION_PLAN.md); additional activation group not started because user requires approval for newlarge implementation/testcycle. Firstnextaction approve that group; then restore prototype on ownbranch, fix canonicalbootstrap guard and validate, implement samejournalactivation, one targeted localacceptance. No schema/daemon/paralleljournal/Ecycle proposed. Production untouched.

## 15.11.2026 — approved W8U completion resumed

Owner explicitly approved W8U_PORTABLE_ACTIVATION_PLAN.md in full (portable existingjournal/cutover branch, CLI, fixtures and targetedacceptance); routine necessaryfixes/tests need no newapproval. Production remains excluded; U-first/E-second queue unchanged. W8U0/4 pendingend-to-end, W8E3/8E_PASS_REUSED.

Actual firstaction:650c93c realTestPortable rerun reproduced publicclean routingcatalog conflict. Fixedexactcanonicalbootstraprecognition824f9a9, targetedPASS1.145s; modverify/go.sum preserved. NewCLI/cutover48a9042 compiledall3packages, storagePortablePASS0.688s (caddy/CLI selected no tests, not acceptance). a2dc7c1 storagePortable incl failed-final-check/status/boundresumePASS1.199s.

Independentreview found firstPrepare absence, completedcleanupreplay and postimport→intentdrift defects;5305938 corrected them with poststate txdigest/explicitprivateopdir/boundlivehash+probes replay. Actualtarget PrivateNetworkPASS storagePortable1.745s, FULLinternal/caddy installedadapter0.328s, Pythonownedauth9tests1.642s; CLIcompiledonly.6fec19b additional exactrowCAS/probereplayhardening reviewed;66e97ff checks actualregistry/state/authFS freebytes beforeimport. Userspreview exposes exactlogin/status/protected/profilecount withoutsecrets. Finalruntimeharness provesfaultboundaryexactly, explicitresume, completedreplay, independentdestinationkey/admin and semantic equality.

Pinned66e97ff project /opt/vpn-control/src-portable-66e97ff-20261115125000 run851701 actualforegroundbuild+oneportableE2E started; modverifyPASS, outcomePENDING. Sourcephase shall be reused if complete, NEW receiver onfix, no fullDRrollback/prune/Ecycle. Nextaction observeactualruntime, fixconcretefailures/escalatebudgets, independentfinalreview then record W8U results+verifiedcommands. No U closure from startedtest/compile.

15.11.2026 — freshprioritydeliverable: localcandidate v0.4.0-rc1 code08be0c3. F1/F2/F4 readylocal, F3NOTRUN awaitingNEWpairpermission; userallowedthisfallback. Report FRESH_INSTALL_CANDIDATE_2026-11-15.md includesouter/innerhashes, oneWindowscommand,63PASS4skip+engines/bootstrap evidence and exactlimits. Packetdist/w95-fresh-08be0c3-candidate.zip, no publication. Existingproduction unchanged; portable/export/import stopped and not in runtimepayload. Nextfirstaction: owner-providedNEWentry+exitSSH/domain, read-onlytargetverification then authorizedfreshF3; do notresumeoldW8/Equeue.

15.11.2026 — GitHub publication COMPLETE: annotated tag v0.4.0-rc1 peeled commit713a2ebaee5eb89f7cd1208685fc026d56ddcd2d (remote refs verified). Public HTTPS Windowsbootstrap downloaded and matched exactlocalSHA; publicdist/installer.zip fullydownloaded22,761,364bytes and SHA256 f5e8b7344945e067e1a85635a7a5c07a98e58e530b7096701a4f6f0ce85a1e6b matched. DefaultGitHubonecommand published (noBundlePathneeded). Q13JSON→registrylocaltarget8a164c9PASS;63releasechecksPASS4skip. Ownerconfirmedcurrentverifiedexportinclmaster_user exists; no cleanup/reinstall permission foragent. F3 remainsOPEN forOWNERmanualcheck oncurrentnodes afterOWNERcleanup, no extra pair/stand request. VPSnotaccessed. Checklist FRESH_OWNER_ACCEPTANCE.md, READMEtagcontainsonecommand+firstlogin/importsteps. Portable remainsSTOPPED. Approvalreviewquotainterrupted firstHTTPattempt, laternormalauthorizedretry succeeded; no bypass.
