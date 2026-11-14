# Общий прогресс VPN Control

Актуально14.11.2026, доказательства до774c07a. Это продуктовый прогресс;
задачи агентов и готовность стенда учитываются отдельно.

**E1 [██████░░░░] 6/10 этапов закрыты: W0–W5.**
Это количество этапов, не оценка оставшегося времени/трудоёмкости.

| Этап | Закрытые верхние пункты PLAN | Приёмка / остаток |
|---|---|---|
| W0–W5 | Закрыты в своих границах | G0–G5 доказательства исторические, W8 ими не заменяется |
| W6 профили | [███░]3/4 | G6 OPEN: автоматическая часть готова, телефонная матрица частичная |
| W7 API/CLI/UI | [███░]3/4 | G7 OPEN: реализация/copy/deploy/owner-phone выполнены, совместная приёмка не завершена |
| W8 безопасность/backup | [░░░░]0/4 полностью закрытых; пункты1–2 частично | Есть прототип/инвентаризация, нет готового общего backup/restore workflow и G8 |
| W9 выпуск E1 | [░░░░]0/4 | Выпускная приёмка не начата; повторные тесты разработки не равны G9 |

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
   read-only inspector + bounded raw-tar guard, negative tests. Нет подключённого
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

## W9 — четыре открытых выпускных пункта

1. Зафиксировать окончательный E1-кандидат после G6–G8, выполнить его выпускной
   полный E2E/security/recovery набор. Сейчас есть тесты разработки, не release.
2. Capacity/load/soak (12/50/100+master, наблюдатели UI,30 изменений,24часа).
3. Выпускная canary/coexistence/cold reboot и проверенный rollback на целевой
   инфраструктуре в отдельно согласованном scope. Старые network/G3/W7 окна
   не подменяют это и не дают разрешения на новый downtime.
4. Финальные runbooks, отчёт/согласование G9 и выпуск E1. E1 не выпущен.

## Следующее действие и агенты

Следующий кодовый пакет: W8/1 — canonical consistent backup/DB-generation/vault
binding; Lead общие контракты/интеграция, агенты независимые части и review.
Не возобновлять отложенную DM диагностику и не повторять выполненные deploy.

SOL-A: последние raw guard3/3, Caddybuild3/3 завершены.
SOL-B: raw review2/2, Caddyreview1/1 завершены.
Lead: local runner3/3, integration/qualification завершены. ASTRA0.
Подробные шаги: PARALLEL_STATUS.md. Их счётчики не прибавляются к Wn-прогрессу.

Во всех следующих итоговых отчётах сначала единый E1 bar и таблица W6–W9,
затем только изменения текущего этапа и короткий поагентный статус.
