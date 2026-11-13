# G3: приёмка рабочей nh1 · 13 ноября 2026

**PASS, W3 5/5.** Пользователь согласовал [пакет](G3_CUTOVER_PACKAGE.md) ответом «начинай». Go/Python и бинарники — замороженный `69e4708`, unit worker — `6621689`. Ветка feature/controlpanel-pilot; `71451ad` сохранён. Ручного присвоения verified_cutover не было.

## Рабочий результат

До изменений: 19/19 tracked hashes совпали, три существующие записи, admin off, Caddy/sing-box active evpn:evpn/naive, нет pending/старых писателей, UID/GID981/982 свободны. Проверены сайт/TLS, общий lock и новые SSH входа/выхода. Защищённый pre-snapshot создан до установки, передан владельцу и проверен после encrypt/decrypt/hash на Windows.

Созданы evpn-caddy982:982 и evpn-panel981:981 без входа и дополнительных групп. Caddy переведён с evpn на evpn-caddy; auth/Caddyfile остались0640 root:982, ACME —982:982 с прежними файлами/режимами. Изменение Caddyfile ограничено admin off → закрытый Unix socket. Основной unit, транспорт/HTTP CONNECT, sing-box, WG, firewall, DNS/IPv6-политики, SSH и резерв не менялись. Caddy остаётся в naive с единственной CAP_NET_BIND_SERVICE; relay — прежний999:986.

Начальный restart Caddy занял **90,38 с**, включая установленное90-секундное ожидание остановки. Это фактическое влияние согласованного окна; обычное создание ниже выполнено через admin load без restart службы.

Штатные registry init/owner bootstrap/inspect/plan/stage/MIG-05 прошли. Передача удерживала общий lock и проверила исходные секреты, tracked-файлы, обёртку, полный live JSON и свежие master/контрольные подключения через exit_https и DNS/UoT. Повтор MIG-05 вернул ту же квитанцию. SQLite verified_cutover, прежние три пользователя active с прежними паролями.

Штатный `/usr/local/bin/vpn-add-user` создал user.create для одного нового `G3-Canary`. Настоящий **systemd worker** под общим lock выполнил validate/apply/verify, затем зафиксировал active/succeeded. Выдача из сессии независимого владельца: до active404, без сессии401, после200/no-store и одна PROFILE_ISSUED. Файл сохранён в закрытом каталоге владельца вне Git.

Исходные профили побайтно совпали с pre-снимком. Старый и скачанный новый JSON прошли установленный sing-box check; их Naive реквизиты — свежие доверенные TLS/TCP exit_https с выходом85.155.184.194, DNS/UoT, контрольного пользователя, отказ неверному паролю и неизменный сайт. Повтор исходного CLI-запроса сохранил nonce/ciphertext и одну запись пользователя/операции, следующий worker idle. Итого4 active, panel_generation2, SQLite integrity_check=ok, нет незавершённых операций, файловых pending и prepared-секретов.

## Приватность и доступ

- Caddy admin: владелец982, фактический socket0200, parent0700. Прямой connect как API981, relay999 и действующий DynamicUser frontend получил именно PermissionError. Через VPN proxy TCP2019 не вернул HTTP admin-данных; HTTPS `/config/` не раскрывает config.
- Новый Go API: Unix socket0600, parent0700, UID/GID981, CapEff0. Публичный listener для него не создавался. Действующий приватный frontend не заменялся.
- Через новый профиль `panel.home.arpa` предъявил доверенный TLS и вернул401 без реквизитов панели. Прямой Windows curl на публичный IP с SNI panel.home.arpa, с доверием настоящему panel CA, получил отказ TLS. Публичный сайт/TLS — PASS.
- После переключения открыты **новые SSH** к hh-entry и hh-exit через прежний ProxyJump; обе успешны. Caddy/sing-box/прежний frontend/API/timer — active. API и timer включены для штатного старта; холодный reboot этим не проверялся.

## Исправление при рабочем запуске

Первый systemd worker завершился до какой-либо user.create. В обычном root SSH тот же worker возвращал idle. Сравнение изолированных transient units показало: при явном `User=root` эффективный CAP_SETUID отсутствовал, при стандартной root-идентичности systemd — присутствовал; bounding set и NoNewPrivileges сохранялись. Отказ был именно setpriv setresuid EPERM при непривилегированном adapt.

`6621689` удаляет из worker template избыточный User=root, оставляя стандартный root и прежний sandbox. Проверены настоящий oneshot idle, create/apply/probes/commit и повторный idle через исправленный unit. Validator по-прежнему переходит в982 с пустым capability bounding set. Caddy повторно не перезапускался ради этого исправления. Новый отдельный адаптер/daemon/journal не добавлялся.

В проверочном сценарии была исправлена только ошибочная SQL-проверка аудита: profile_issuance хранит profile_id, а не user_id. К тому моменту создание/выдача/оба профиля и первое сравнение ciphertext уже прошли; после исправления отдельно повторены тот же запрос, ciphertext/единственность/одна выдача/no-pending/idle. Рабочая схема и данные не изменялись для обхода проверки.

## Снимки и откат

Pre/post snapshots находятся в закрытом `/root/vpn-control-g3/<window>/`; window/run и точные пути — в root-only квитанциях `/root/g3-pre-receipt.json`, `/root/g3-post-receipt.json` и window.json. Секреты/архивы/профили в отчёт и Git не включены. Обе копии на Windows зашифрованы, расшифрованы для проверки и сверены по SHA; исходные tar на Windows удалены после проверки. Ключ получателя остаётся только на Windows. Post содержит online SQLite backup и vault key под шифрованием владельца.

Откат **не применялся**. До изменения runtime сохранён и синтаксически проверен root-only `<window>/rollback.py`, который использует существующие return/handoff/runtime helpers и общий lock. После пользовательских изменений сначала возвращает актуальный экспорт установщику; старый auth из pre не восстанавливается. При незавершённой/неоднозначной операции остановится для SSH-сверки. Команда для оператора через root SSH: прочитать directory из `/root/g3-pre-receipt.json`, взять его родительский каталог и выполнить `python3 -B <window>/rollback.py`. Затем обязательны старый/новый профиль, сайт, приватность и новые SSH обеих нод. Проверки самого возврата/прерываний выполнены на копии `69e4708`, не на рабочей паре.

Дополнительный SSH-канал сохранён до итоговых проверок. Факт рабочего G3 не заменяет W4/G4, матрицу обеих SFA/W6, новый web UX/W7, полный backup/restore+disk budget/W8 и выпуск/G9. Первый следующий шаг — остаток W4: сверить критерии адаптера с переиспользованными G0b/G3, закрыть контракт предупреждения о влиянии применения.
