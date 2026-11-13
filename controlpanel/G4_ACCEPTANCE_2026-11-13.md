# G4: безопасное применение Caddy · 13 ноября 2026

**PASS на стенде, W4 4/4.** Зафиксированный код `c8880b0`, полный модуль из git-архива. Рабочая nh1 остаётся на принятом G3: Go/Python `69e4708`, worker unit `6621689`. Новый CLI notice на nh1 в этом шаге не развёртывался.

Спецификация: v1.1, §6.2 и W4-Caddy-adapter. Переиспользованы [G0b](../pilot/caddy-apply.md), [общая репетиция](G3_REHEARSAL_2026-11-13.md) и [рабочий G3](G3_ACCEPTANCE_2026-11-13.md); адаптер, файловый журнал, worker и процедуры проб не создавались повторно.

| Критерий | Доказательство и граница |
|---|---|
| Только управляемый auth | TestManagedOnlyAndRecovery удаляет добавленный credential из кандидата и сравнивает весь JSON с исходным, включая unknown directives/числа >2^53. Installed-Caddy тест сохраняет сайт/контрольного пользователя. В G3 подтверждён baseline live↔adapted files до/после изменения |
| Поколение/операция/дрейф | ReadPrepared отвергает чужую generation, Prepare не заменяет existing snapshot; TestAdapterStopsOnDriftAndValidationFailure и TestVerifyFailureAndConcurrentChange запрещают load/rollback при постороннем изменении до/во время пробы |
| Validate/apply/verify/rollback | TestInstalledCaddyUnixAdapter на установленном Caddy/forwardproxy: validate→load→новый/контрольный CONNECT, отказ неверному, неизменный сайт; recovery без второго load; rollback подтверждает старого и отказ новому. Реальный TLS/Naive/TCP/UoT проверен общей RootDirectory-репетицией |
| Сбой между Caddy/файлами/SQLite | Общие saga/owned_auth-тесты, pinned full suite и прежние 4 аварийные замены; ошибка commit создания и потеря ответа повторяют сверку прежнего кандидата/секрета. Unknown/reconcile_required блокирует конфликтующие изменения; конкретное восстановление CRUD расширяется W5, не подменяется новым процессом |
| Закрытый socket | Стенд отвергает mode0666; G3 на nh1 фактически0200/parent0700, Caddy982, relay999, API981, actual frontend denied. Proxy2019 и публичный HTTPS не раскрывают admin; API только Unix0600/parent0700. Caddy/relay в прежнем naive, права разделены |
| Стратегия/влияние | G0b измерил restart≈90с, reload0,06–0,18с с сохранением контрольных длительных TCP/UoT на стенде. G3 фактически restart90,38с; затем успешный create через load. UnixRuntime не реализует restart fallback. Новый shared caddy.ApplyNotice выводится CLI в stderr **до queue**: нет обещания непрерывности; отзыв запрещает новые подключения, прежние туннели могут жить; restart прерывает VPN и требует отдельного согласования |

## Приёмочный прогон

`c8880b0` передан git-архивом в новый `/run/vpn-w3-worker-tests/pinned-c8880b0`, без рабочего auth/ключей/профилей. Go1.27.3, установленный Caddy SHA256 `7509cd6b38a5da3324a08f32f62a7000237e5e1f6ccfb58e818bf730de58d30c` / forwardproxy e747854e7874, sing-box1.14.4. Полный `go test -count=1 ./...` с VPN_TEST_CADDY_ADAPTER=1 и VPN_TEST_NAIVE_PROBE=1 — PASS. Старые consumers, в том числе migration/stage/return, очередь и скачивание, прошли. go mod verify — PASS, репозиторный go.sum не изменён. Использованы прежнее file-proxy с проверкой go.sum, GOSUMDB=off, GOTOOLCHAIN=local, GOFLAGS='-p=1 -mod=readonly'. Отдельный systemd-run: PrivateNetwork/PrivateTmp/ProtectSystem=strict.

Бинарники пересобраны из этого архива. RootDirectory35/lo-only/ProtectSystem=strict: настоящий init→stage→MIG-05→vpn-add-user→worker→новый/контрольный TLS/TCP/UoT→сессия владельца/выдача→return→runtime restore и оба профиля — PASS. Источники Python/templates/harness побайтно совпали с pinned revision; ошибки секретов/профили не попадали в вывод. Код изменения — только единый English notice и вызов перед CLI queue; общий механизм применения совпадает с проверенным G3, кроме уже принятого unit fix6621689.

В рамках W4 рабочие службы не перезапускались, новый код не развёртывался; G3 остаётся действующим. UI ещё не подключён: W7 использует тот же notice, W5 должен использовать его в mutating CLI и общий apply для disable/enable/rotate/delete. Полная семантика каждой операции и все14 именованных fault points — критерий G5. Обе SFA, W8/дисковый бюджет и G9 сохраняются в объёме; G4 не означает выпуск E1.
