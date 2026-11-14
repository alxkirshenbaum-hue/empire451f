# VPN Control — инвентаризация и первый план Subagents

Дата:14.11.2026. Статус: СОГЛАСОВАН владельцем 14.11.2026; автоматическая эскалация ASTRA и поагентный отчёт обязательны.
Lead: SOL. Subagents не запускались. Код/миграции/units/production не менялись.
Инвентаризация основана на исходниках, истории и протоколах; полный набор
тестов и новый опрос VDS в рамках этой подготовки не выполнялись.

## 1. Источники и фактическая контрольная точка

- Ветка feature/controlpanel-pilot, HEAD5cb0600 на начало инвентаризации.
  Локальная ветка ahead23 относительно локального origin ref; fetch/push
  не выполнялись. Tracked tree чистое.
- controlpanel/BACKLOG.md — чужой untracked файл; не редактировать,
  не добавлять в коммит, не включать его задачи в текущие пакеты.
- [Architecture & Roadmap](../../controlpanel/VPN_Control_Architecture_Roadmap_Agent_v1.1.md):
  внутри файла концепция0.2, комплект1.1. Файл с суффиксомv1.md — старая0.1.
- [Обязательная LLD1.1](../../controlpanel/VPN_Control_LLD_Spec_Agent_v1.1.md),
  [PLAN](PLAN.md), [test status](TEST_STATUS_2026-11-14.md),
  [последнее production-окно](W7_PRODUCTION_WINDOW_2026-11-14.md).
- Последняя полностью проверенная продуктовая сборкаcd3de10; deployed payload
  ad6b653, binary-identical cd3de10. Deployment evidencefff4517, phone
  evidencebc006a4/5cb0600. Более поздние записи не означают rebuild/deploy.

| Этап | Подтверждено | Остаток / граница |
|---|---|---|
| W0/W0a/W0b | Инвентаризация, приватный route/DNS/TLS pilot, Caddy strategy | Исторические доказательства в pilot/README.md, caddy-apply.md; не перезапускать старые deploy scripts |
| W1 | Legacy reconcile/writer/lock, ограниченная recovery rehearsal | Старый опыт с небольшой synthetic fixture не заменяет общий W8 restore/ресурсный пик |
| W2/G2 | Схема, AEAD, immutable migration checksums, CAS/idempotency/journal/exact case | Accepted2754adc; дальнейшие расширения схемы до7 |
| W3/G3 | 5/5, production MIG-05/shared writer/worker/старые профили | Accepted G3, исходный код69e4708 и worker-unit6621689; повтор cutover не нужен |
| W4/G4 | 4/4, общий Prepared/UnixRuntime, validate/apply/verify/rollback | G4 matrix; не второй adapter и не auto restart |
| W5/G5 | 4/4, create/disable/enable/rotate/delete/reconcile;70SIGKILL | 64718cf, G5_ACCEPTANCE; real copy probes/recovery и защита100+master/CAS/secret replay |
| W6 | 3/4 по PLAN: единый renderer, immutable policy2, выдача/audit, exact engine/DNS tests | Три phone профиля подключаются; ChatGPT/DM известная проблема отложена владельцем. Полного G6 PASS не утверждать |
| W7 | 3/4 по PLAN: API/CLI/UI, deployment, security и phone owner E2E | Вход owner на14.4/alpha13 черезWi-Fi; user-created daria/download/connect. Lead оформляет оставшуюся формальную приёмку в своих границах; старую DM-проблему не расследует |
| W8/G8 | Есть отдельные snapshots/encryption/rollback helpers и backup metadata | Общий backup/verify/restore-plan workflow, unified security coverage, master-key rotation drill, retention и ресурсная приёмка ещё не завершены |
| W9/G9 | Есть прежние controlled tests, не release новой панели | Финальный pinned release, load/soak/coexistence/cold reboot/runbook и отдельное production approval; E1 не выпущен |

Последнее проверенное production-состояние: API981/CapEff0/private Unix socket,
frontend981 в naive; transport Caddy982, relay999:986. Registry schema7.
После пользовательского daria: active5, generation3, integrityok.
Это последняя подтверждённая точка, не новый live inventory. Старые pre-daria
снимки не разрешено восстанавливать поверх текущих пользователей/паролей.
Новый deploy/production CRUD/restart/сетевые изменения требуют отдельного
подтверждения; не брать его из согласования организационного плана.

## 2. Проверки и зависимости

Полный pinnedcd3de10: Go -count=1 с Caddy/Naive флагами, exact SFA1.14.4/
1.15.0-alpha.13 checker и DNS; Python Ran69/skipped4, mod verify/go.sum PASS.
G5:70 именованных SIGKILL=5операций×14границ; отдельные реальные Caddy/Naive
и explicit recovery proofs. Не выдавать synthetic70 за70 real network runs.
W7: copy7201/7202, corrected harnessaf63ab0, actual production identity/mount/
private API/owner/Origin/external Host/SNI checks и owner phone E2E.

Основные потребители общего механизма:
- internal/storage: users/credentials/operations/schema1–7, profile renderer;
- internal/caddy и cmd/vpnctl: общий lock/Prepared/worker/reconcile;
- owned_auth.py, create_probe.py, inspect/handoff/return helpers;
- cmd/vpn-control + cmd/vpnctl/panel.go + internal/auth: owner API/CLI/UI.

Уже есть:
- g3_snapshot.py: online SQLite backup, generation/file checks, protected archive;
- pilot/g3-owner-snapshot.ps1: existing recipient + RSA-OAEP-256/A256GCM,
  decrypt/hash verification, private Windows ACL;
- pilot/recovery_rehearsal.py/recovery_probe.py: synthetic recovery/Naive proof;
- g3_restore_runtime.py: возврат installer-specific runtime ПОСЛЕ journaled
  return. Это НЕ готовый универсальный restore панели;
- security_audit.py и controlled_audit.py: существующие проверки. Первый
  строит reference nft rules в isolated unshare namespace; второй исполняет
  controlled outages. Не запускать их вслепую как “полностью read-only”;
- backups/audit_runs/audit_checks уже есть в schema1. W7 предоставляет
  metadata/list; backup_creation_available=false. Это не готовый BKP workflow.

Зависимости: Go module1.24, mattn/go-sqlite3 (CGO/compiler), x/crypto/x/sys.
Известный Linux toolchain1.27.3 + файловый proxy из прежнего стенда — факт
протоколов, не подтверждение нового независимого runner.
На Windows проверены Git, PowerShell7.6.9/.NET10.0.14; go в PATH не найден.
Python найден как WindowsApps alias, работа runtime/cryptography не проверялась.
wsl.exe существует, но --list --quiet не дал рабочего списка дистрибутивов.
Не установлены и не подтверждены новые Linux/CGO/systemd runners.

## 3. Ресурсы и запреты

Сохраняются ДВА отдельных требования:
1. Disk ≤500,000,000 bytes дополнительного места панели суммарно на обеих VDS,
   включая WAL, old version, backups, temp peak, retention и открытые удалённые
   файлы; baseline/общие caches — по LLD2.4.
2. Новое явное ограничение владельца: RAM панели ≤500MB. Планировать
   aggregate500,000,000bytes для API/frontend/worker/helper jobs, с memory.current/
   peak и RSS/PSS; child процессы не уходят из учёта. Caps не являются замером.
   Исходный документ требует наблюдать RAM, не подменять им дисковый gate.

UI redesign, новые nodes/roles/metrics из бэклога и DM/ChatGPT диагностика
НЕ входят в первый раунд. W9 может требовать builtin observations из LLD,
но это не разрешение автоматически разбирать пожелания владельца.

Субагенты не получают SSH к production, доступ к owner-materials/реальным
профилям/сырым снимкам/ключам. Даже “изолированный /run-каталог” на hh-entry
физически находится на production VDS; это не отдельный безопасный runner.
Не запускать на нём агентские тесты и не считать ресурсы бесплатными.
Lead сначала подтверждает отдельную nonproduction Linux-среду. Новая установка
WSL/VM/ПО или новый внешний сервис не выполнялись в рамках инвентаризации.
До наличия среды можно готовить код/fixtures и статические проверки, но не
объявлять Linux security/restore tests пройденными.

## 4. Первый раунд после согласования

Первые W8-пакеты — независимая подготовка следующего этапа; они не закрывают G6/G7 и не разрешают приёмку G8 в обход порядка PLAN. Lead сначала фиксирует границы оставшейся приёмки W6/W7.

Ровно два активных Subagents на SOL. В tool schema доступен gpt-6.1-sol;
планируем его для обоих. SOL Lead остаётся архитектором/интегратором.
Фактический запуск/доступность проверяется после approval. Задачи выдаёт Lead,
отдельных пользовательских промптов не требуется.

### Lead: общие контракты, среда, gate status, интеграция

1. Зафиксировать baseline commit и отдельные worktrees. Сверить git status,
   не включать чужой BACKLOG. Оформить подтверждённые phone/W7 результаты и
   явное отложенное ограничение G6, без ложного полного PASS.
2. Подготовить воспроизводимый nonproduction Linux runner: systemd, CGO,
   exact Caddy/Naive/checkers, pinned proxy/go.sum. Если среды нет — это реальная
   зависимость, а не основание тихо использовать production host.
3. Зафиксировать минимальный W8 contract: consistent generation/WAL snapshot,
   envelope/manifest/key custody, created vs verified vs restored,
   read-only restore plan и re-enable risk, bounds/retention, operation admission.
   Переиспользовать формат/библиотеки, не создавать новый crypto protocol.
4. Только Lead меняет SQL migration registry/новую миграцию, общие Go contracts,
   storage transaction boundaries, worker dispatch/policy, API/CLI/UI wiring,
   существующие common harness/scripts и systemd units. Проверить inherited
   flock: нельзя повторно взять свой lock новым fd и повиснуть.
5. Сериализовать audit/backup/apply и измерения пиков в общей копии. Встраивать
   модули двух агентов в существующий RootDirectory harness.

### SOL-A: W8 backup/restore proof

Владение НОВЫМИ файлами:
- pilot/w8_recovery_check.py;
- tests/test_w8_backup_artifacts.py;
- controlpanel/reports/W8_BACKUP_CANDIDATE.md.

Задача: модуль проверки consistent snapshot/encrypted artifact/restore в НОВУЮ
synthetic staging directory, опирающийся на существующие snapshot/envelope/
recovery компоненты. Нужные изменения общих helpers предлагает Lead, сам
их не коммитит. Не использовать настоящие recipient/private owner keys.
Не вызывать существующий SelfTest, если он обращается к hh-entry.

Обязательные результаты:
- WAL/поколение/drift и незавершённые состояния: пригодная копия либо отказ;
- tamper/wrong key/missing refs/schema mismatch/path traversal/symlink отказ;
- сохранение credential binding/master/protected/current vs revoked semantics;
- общий сценарий restore -> owner login -> fresh old-profile connection
  через реальный copy stack. Для callback в existing harness нужен Lead;
- точки пиков файлов/RAM для backup/restore, счёт занятых блоков, не только
  logical size; ресурсные результаты только на подтверждённом Linux runner;
- bounded I/O/size и работа при нехватке места, без объявления “verified” по
  одному успешному tar/decrypt. Не вводить новый backup daemon/journal.

DoD: commit+diff, baseSHA, targeted tests/logs/env, sanitised report, список
непроверенного. “Модуль готов, Linux прогон pending” не равно G8 PASS.

### SOL-B: независимый security inventory/coverage

Владение НОВЫМИ файлами:
- pilot/w8_security_check.py;
- tests/test_w8_security_fixtures.py;
- controlpanel/reports/W8_SECURITY_REVIEW.md.

Задача: классификатор секретных поверхностей и gap/coverage matrix по SEC
из LLD, safe synthetic checks и проверяемый список remediation.
Переиспользовать существующий audit; не писать второй framework/daemon.
Не читать действующие owner files/VDS и не выполнять controlled outages.

Проверить на fixtures и затем через Lead staging:
- auth/clients/profiles/exports/DB/WAL/vault/snapshots/temp/backup/log surfaces,
  owners/modes/ACL/namespace и root/API/frontend/Caddy/relay identities;
- чужой UID/ссылки/proc-root/файловые обходы, redaction, no credentials in
  stdout/stderr/URL/argv/report. Оценивать операции, не только docstrings;
- key custody/pairing, decrypt vs usable restore, expiry/retention, current
  master-key rotation runbook/test gaps;
- TLS renewal/expiry по известному состоянию (leaf до25.11), не менять CA;
- memory/cgroup coverage и unit limits vs measured usage, disk budget gaps.
  Никаких новых hardening patches в shared units без Lead/review.

DoD: risk/coverage report с severity/evidence/unknown/not_run, targeted
negative tests, предложения минимальных правок. Затем независимое review
стабильного commit SOL-A: security/restore semantics; не собственного diff.

## 5. Владение общими файлами и изоляция

После approval создать два worktrees от ОДНОГО baseline:
worktrees/w8-restore и worktrees/w8-security, уникальные ветки work/w8-*.
Если имя/путь занят — не затирать, выбрать новый. Реальные secrets/archives
не переносить в worktrees. Агентам давать baseSHA и точный allowlist файлов.

Только Lead:
controlpanel/PLAN.md, normative spec/addenda, migrations/*, go.mod/go.sum,
internal/storage/registry.go и shared contracts, cmd/vpn-control/*,
cmd/vpnctl/*, auth UI, g3_snapshot/restore и общие envelope helpers,
full_worker_rehearsal.py/prepare_rehearsal_root.py, systemd/*.

Агенты не cherry-pick/merge/rebase main, не правят PLAN/Git refs чужой ветки.
Изменение вне allowlist — запрос Lead и пересогласование границы между
агентами; пока можно продолжать независимую часть. Один файл не принадлежит
двум исполнителям одновременно. Общие SQL номера выдаёт только Lead.

## 6. Интеграция и контроль качества

1. Checkpoint Git перед каждой интеграцией (commit/tag/backup branch),
   tracked baseline чистый. Чужой untracked BACKLOG не stash/delete/add.
2. Агент передаёт baseSHA/headSHA/allowed files/tests/evidence/known gaps.
   Lead проверяет diff на область/секреты/compatibility, не доверяет одному
   сообщению “готово”. Интегрирует последовательно, по одному commit.
3. Независимый reviewer не автор проверяемого security/migration/rollback diff.
   A-review выполняет B; Lead migration/unit/contract patches проверяет B
   или освобождённый A. Если B сам реализовал security fix, его проверяет A.
   No merge до решения review findings; Lead единственный принимает gate.
4. Targeted tests после группы. После shared механизма — storage/caddy/worker/
   API/CLI/profile и Python consumers. Полный pinned Go/Python перед G8/G9,
   exact flags/checkers, mod verify, repository go.sum. Новые ограничения
   прав/units/identity снова проверять actual staging identities.
5. Единая связная copy acceptance: encrypted backup -> restore -> owner login
   -> old profile positive/revoked negative -> диск/RAM peak. Проверять
   baseline vs mutation expectations, no stale auth/current-user loss.
6. Не параллелить тяжёлые runtime сценарии на одной копии: audit/backup/apply
   допускаются по контролируемой очереди. Создание независимого кода/portable
   fixtures может идти параллельно; ресурсный gate — последовательный.
7. PLAN обновляет только Lead после проверенного результата:
   SHA/среда/наблюдение/остаток/первое действие. Agent reports не gates.
   Push/deploy/production tests не следуют автоматически из локального merge.

## 7. Следующие раунды, без новых организационных согласований

- После ядра A: B-review, Lead подключает BKP-* к существующей очереди/
  registry и API/CLI; A получает recovery integration/retention negatives.
- После inventory B: Lead реализует общие hardening/coverage исправления
  на copy; независимый агент review. A/B могут меняться ролями по готовности.
- Затем completed backup/restore UI wiring и AUD-* coverage/report/export,
  master-key rotation technical runbook/test. Пакеты разрезает Lead по
  стабильным contracts; не менять сейчас UI design/backlog.
- После G8 — независимые W9 copy load/soak и installer coexistence/runbook,
  Lead release integration. Production rollout/reboot/failure injection —
  только после отдельного подтверждения, не по этому плану.

## 8. Три попытки и ASTRA

Считать неудачные ИСПРАВЛЕНИЯ одной причины централизованно, а не выдавать
каждому агенту новый лимит. Третья неудачная SOL-попытка: остановить новые
поправки, сохранить minimal repro,3 diffs, expected/observed и sanitised logs;
передать ASTRA (tool model gpt-6-astra) в ОСВОБОЖДЁННЫЙ слот.
Не добавлять третьего одновременно работающего Subagent.

ASTRA даёт независимый анализ/направление, Lead решает и интегрирует.
Прежнее ограничение владельца “после4 неудачных исправлений остановиться”
не отменено: ASTRA-analysis сам по себе не обнуляет счётчик и не разрешает
бесконечные retries. Если наступает четвёртое неудачное исправление — остановка
на этом блокере и отчёт владельцу. Ни эскалация, ни approval плана не дают
ASTRA/Subagents права менять production.

## 9. Условие старта

До явного согласования ЭТОГО первого плана:
никаких spawn, worktrees/implementation или production changes.
После согласования Lead сам выдаёт и переставляет пакеты двум агентам,
готовит context/instructions, интегрирует и тестирует. Отдельные промпты
владельцу и разрешения на каждый следующий запуск не нужны.
