# Общий прогресс VPN Control

**16.11.2026 — актуально:** ночная U-очередь владельца, [проверенные подшаги и остатки](U_NIGHT_RESULTS_2026-11-16.md).
U: W8U0/4 · W9U0/5 · W10U0/4 · W13U0/4 · W14U0/4 fully accepted;
реализованы и целево проверены пять подшагов: PROF-03, AUTH-04, AUTH-03,
local resources и stored timestamps. Final code `8c0309b`, full auth7.251s PASS.
E: W8E3/8 reused, новых закрытий нет. F1/F2/F4 подготовлены/опубликованы,
F3 OPEN до ручной установки владельцем; portable migration deferred.
Ночные изменения отсутствуют в опубликованном rc1, production не менялся.
Старые заявления о паузе/очереди ниже — исторические.


**Уточнение владельца15.11.2026:** [единый вход и точная приёмка F1–F4](INSTALLER_ENTRY_CONTRACT.md). Сейчас реализуется только новая пара VPN+панель через автоматически загружаемую команду из GitHub и общий мастер. F4 закрывается после публикации и проверки из пустой локальной папки; локальный ZIP недостаточен. Доустановка и обновление панели в будущем идут через тот же мастер, оба сценария сейчас DEFERRED_BY_OWNER. Исторические заявления F4 ready ниже относятся к локальной подготовке.

**Последнее решение владельца15.11.2026:** [W9.5U-Fresh — установить VPN+панель одной командой](PRIORITY_FRESH_INSTALL.md), 0/4, выполнять сразу. Portable export/import и его тестовые расширения отложены; предыдущие зависимости от W8U/G9 ниже отменены для fresh-install. Будущий минимальный перенос допускает plaintext JSON с паролями; сейчас на него время не тратить. Сохранять существующие PASS и WIP.

15.11.2026 — W8U [░░░░] 0/4 U_PASS; W8E [███░░░░░] 3/8 E_PASS_REUSED. [Ledger](W8_UE_EVIDENCE.md). W9U0/5, W9.5U0/5; W10U–14U INCOMPLETE; W15U DEFERRED_BY_OWNER до выбора. [Порядок](UE_BACKLOG.md). Ниже история parent-gates. Около500МБ — ориентир дополнительного диска; RAM наблюдается без фиксированного порога500МБ.

15.11.2026 — старое 0/4 отражает расширенные критерии. По уточнённой цели экспорта/импорта подтверждены encrypted export, offline verification и restored runtime. G8 открыт: пользовательский импорт в чистую установку и завершающий rollback требуют проверки. [Точная матрица и минимальный план](W8_TRANSFER_SCOPE.md). Исторические PASS сохраняются.
> **PAUSED 15.11.2026.** Актуальная передача: [HANDOFF_W8_2026-11-15.md](HANDOFF_W8_2026-11-15.md), [промпт продолжения](CONTINUE_W8_PROMPT_2026-11-15.md). Функциональный HEAD fc2ec74; bf6f693 — непроверенный rotation WIP, c99e9b0 — отдельный test WIP. W8 0/4 полностью закрытых пунктов, G8 OPEN. До нового разрешения владельца разработку/тесты/агентов не запускать. Старые записи ниже являются историей.

> Возобновлено14.11.2026. Snapshot inspector c4bf7bb: целевые тесты и Go-потребители PASS. Online SQLite capture 5b01836 также проверен (W8_ONLINE_CAPTURE_2026-11-14.md). Привязка capturedDB/owner/key/file hashes bf04c54 также проверена (W8_BINDING_2026-11-14.md). Это частичный W8/1, не готовый encrypted backup.

Дополнение 14.11.2026 — **W9.1 [░░░░░░] 0/6**, интеграция панели в общий установщик и публикация. [Подробный план/G9.1](W9_1_INSTALLER_INTEGRATION.md). Текущие W8/W9 выполняются в прежнем порядке. Общий счётчик ниже уже включает W9.1: 6/11 закрытых этапов. Общий выпуск E1 требует G9.1 после приёмки компонентов G9.

Актуально14.11.2026, доказательства до774c07a. Это продуктовый прогресс;
задачи агентов и готовность стенда учитываются отдельно.

**E1 [██████░░░░░] 6/11 этапов закрыты: W0–W5. G9 принимает компоненты; общий E1 требует G9.1.**
Это количество этапов, не оценка оставшегося времени/трудоёмкости.

| Этап | Закрытые верхние пункты PLAN | Приёмка / остаток |
|---|---|---|
| W0–W5 | Закрыты в своих границах | G0–G5 доказательства исторические, W8 ими не заменяется |
| W6 профили | [███░]3/4 | G6 OPEN: автоматическая часть готова, телефонная матрица частичная |
| W7 API/CLI/UI | [███░]3/4 | G7 OPEN: реализация/copy/deploy/owner-phone выполнены, совместная приёмка не завершена |
| W8 безопасность/backup | [░░░░]0/4 полностью закрытых; пункты1–2 частично | Есть прототип/инвентаризация, нет готового общего backup/restore workflow и G8 |
| W9 приёмка компонентов панели | [░░░░]0/4 | Приёмка компонентов не начата; повторные тесты разработки не равны G9 |
| W9.1 общий установщик/публикация | [░░░░░░]0/6 | После W8/W9; общий E1 дополнительно требует G9.1 |

## W6 / G6 — что уже есть и что действительно открыто

ГОТОВО: один renderer/immutable варианты, общий путь выдачи и аудит, обе точные
версии и DNS на Linux, три профиля подключаются на OnePlus12. Владелец подтвердил
панель/owner на1.14.4 иalpha13 черезWi-Fi, создал daria, скачал и подключил профиль.

ОТКРЫТО: измеренная Android-матрица DNS/IPv6/маршрутов RU domain+IP и
приложений/сетей для заявленных вариантов, где наблюдение не было сообщено.
Не объявлять Wi-Fi+mobile/DNS leak/RU direct доказанными по одному подключению.
Точная версияAndroid и длительность стабильности также не зафиксированы.
ChatGPT/Download Manager имеет сообщённые сбои; владелец явно отложил исправление.
Эту проблему сейчас не расследуем и не идём в backlog. Она не превращается в PASS:
полный исходный G6 остаётся OPEN; согласованную разработку W8 это не останавливает.

## W7 / G7 — нет повторного блока deploy или owner login

ГОТОВО: API/CLI/UI, copy security/browser download/protection/version gates,
конкретный package и согласованное production-подключение, owner login на телефоне,
реальный create(daria)->download->connect. Последняя локальная квалификация
повторно подтвердила API/frontend/CLI/изоляцию. Sandbox502/ENOENT исправлены.

ОТКРЫТО: оставшиеся фактические наблюдения nonadmin/external на целевом
подключении из W7/4 и отдельный итоговый протокол совместной G6/G7 приёмки,
с явным разделением подтверждённого и отложенного. Owner-сценарий не открыт
заново; deploy заново не нужен. Это не новый дефект API/UI, а незавершённая
приёмочная матрица. Проверки отрицательных сценариев на копии уже PASS;
они не выдаются за отсутствующий целевой телефонный/external сеанс.

## W8 — четыре продуктовых пункта

1. **Общий encrypted backup/verify/restore-plan/prune workflow — ЧАСТИЧНО.**
   Есть исторические snapshot/envelope helpers, metadata schema/list,
   read-only inspector + bounded raw-tar guard, negative tests; canonical Registry.InspectSnapshot c4bf7bb проверен на Linux (см. W8_SNAPSHOT_INSPECTION_2026-11-14.md). Нет подключённого
   BKP workflow с согласованной SQLite/WAL/generation/vault моделью, retention
   и доказанной совместимостью GNUtar/PAX/ACL. backup_creation_available=false.
2. **Полный secret inventory/security audit/hardening — ЧАСТИЧНО.**
   SEC22 coverage/gap matrix, synthetic checker и реальные API/frontend denials
   готовы; полный аудит всех поверхностей/ролей, исправление найденных пробелов,
   master-key rotation и их доказательства не завершены.
3. **Пробный restore backup — НЕ ЗАВЕРШЁН.** Требуется encrypted backup->restore
   в отдельную копию->owner login->старый active profile PASS/revoked FAIL.
   Installer return, worker rollback и проверка tar это не заменяют.
4. **Ресурсы/retention и G8 — НЕ ЗАВЕРШЁН.** Пиковые disk<=500000000bytes на
   обеихVDS и panel aggregateRAM<=500MB, включая backup/restore/temp/retention,
   ещё не доказаны. Один cgroup peak не является полным gate.

Локальный WSL/systemd runner3/3 ГОТОВ — обеспечивающая работа для этих пунктов,
не отдельная завершённая четверть W8. Go full78515f4 PASS, Python2ae9706
84/skipped4 PASS, RootDirectory/HTTPS/CLI/canonical mutations/return PASS.

## W9 — четыре открытых пункта приёмки компонентов

1. Зафиксировать кандидат компонентов панели после G6–G8, выполнить его полный
   полный E2E/security/recovery набор. Сейчас есть тесты разработки, не release.
2. Capacity/load/soak (12/50/100+master, наблюдатели UI,30 изменений,24часа).
3. Выпускная canary/coexistence/cold reboot и проверенный rollback на целевой
   инфраструктуре в отдельно согласованном scope. Старые network/G3/W7 окна
   не подменяют это и не дают разрешения на новый downtime.
4. Финальные runbooks компонентов и отчёт/согласование G9. Общий E1 выпускается только после G9.1.

## W9.1 — интеграция установщика и общий выпуск, 0/6

После W8/W9: пакет компонентов; чистая установка; подключение/обновление
существующей пары; прерывание/повтор/возврат; инструкции/публикация;
приёмка опубликованных команд Windows и настоящего macOS (G9.1).
Панель nh1 распознаётся как существующая установка. Все шесть пунктов OPEN;
реализация не начата. W10 и дальнейшая нумерация не изменены.
[Полный контракт и матрица](W9_1_INSTALLER_INTEGRATION.md).

## Следующее действие и агенты

Следующий кодовый пакет: W8/1 — canonical consistent backup/DB-generation/vault
binding; Lead общие контракты/интеграция, агенты независимые части и review.
Не возобновлять отложенную DM диагностику и не повторять выполненные deploy.

SOL-A: последние raw guard3/3, Caddybuild3/3 завершены.
SOL-B: raw review2/2, Caddyreview1/1 завершены.
Lead: local runner3/3, integration/qualification завершены. ASTRA0.
Подробные шаги: PARALLEL_STATUS.md. Их счётчики не прибавляются к Wn-прогрессу.

Во всех следующих итоговых отчётах сначала единый E1 bar и таблица W6–W9.1,
затем только изменения текущего этапа и короткий поагентный статус.

15.11.2026 — local development resumed by owner through W9.1, production excluded. Actual evidence is collected in W8_RESUMED_VALIDATION_2026-11-15.md and latest PLAN entries. Pinned4dd8956 API/crypto-worker/offline/rotation targets PASS; integrated ACL6a525bc targets PASS; b0dbd99 restore13scenarios PASS;03bb43f encrypted worker→offline preparedDB PASS. Runtime restored stack still pending, G8OPEN/W8 0/4. Active package: existing RootDirectory vertical encrypted backup/restore/rollback, no nested agents. ASTRA W8-SEC-002 code findings addressed under explicit source/principal trust contracts; runtime acceptance not inferred. Previous pause is superseded by new user authorization.
