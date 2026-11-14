ИСТОРИЧЕСКИЙ ПРОМПТ. af63ab0 устранил sandbox blocker; cd3de10 проверил CLI/browser/full suite; ad6b653 подготовил окончательный payload. Актуальны PLAN.md, последние дополнения TEST_STATUS/W7_COPY_STATUS и W7_PACKAGE_RECEIPT_2026-11-14.md. Ниже сохранена прежняя передача, её требование возобновлять старое расследование больше не применяется.

Продолжаем проект персональной VPN-панели. Сначала прочитай текущее состояние,
не возобновляй неудачные sandbox-пробы автоматически: предыдущая работа
остановлена по лимиту четырёх попыток; эта передача сама по себе не даёт нового
разрешения на расследование. Сначала сообщи, что прочитано и какой блокер остаётся.
Явное возобновление владельцем снимает именно эту остановку; лимит четырёх
неудачных исправлений одной проблемы после возобновления сохраняется.

Работай в PowerShell:
$repo = 'C:\AllFiles\SoftWare\VPN\Amnezia\CodexVPN\installer'
git -c safe.directory=C:/AllFiles/SoftWare/VPN/Amnezia/CodexVPN/installer -C $repo status --short --branch
git -c safe.directory=C:/AllFiles/SoftWare/VPN/Amnezia/CodexVPN/installer -C $repo log -8 --oneline
Get-Content -Encoding utf8 "$repo\..\AGENTS.md"
Get-Content -Encoding utf8 "$repo\controlpanel\PLAN.md" -Head 12
Get-Content -Encoding utf8 "$repo\controlpanel\PLAN.md" -Tail 55
Get-Content -Encoding utf8 "$repo\controlpanel\TEST_STATUS_2026-11-14.md"
Get-Content -Encoding utf8 "$repo\controlpanel\W7_COPY_STATUS_2026-11-14.md"

Ожидается feature/controlpanel-pilot. Последний код/остановка9b9ea35,
после него возможен отдельный документационный коммит этой передачи.
Перед ним дерево чистое, ahead15 к локальному origin ref; новые коммиты текущей
сессии не push. Если ветка продвинулась, сохранить чужие изменения и прочитать
последнюю запись плана. Статус удалённой ветки не предполагать по старому ref.

Состояние:
- W3/G3 приняты на nh1, W4/G4 и W5/G5 приняты на копии.
- W6 3/4, G6 открыт: отсутствует фактический OnePlus12-сеанс.
- W7 2/4 — реализована часть API/CLI/UI; сквозная приёмка и подключение открыты.
  G7 НЕ принят; E1 не выпущен; W8/W9 не закрыты.
- Разработка W7 началась независимо на копии после автоматической части W6,
  чтобы объединить ручные профильные и UI-проверки. Это интерпретация агента,
  а не закрытие G6. W6 остаётся первым незакрытым этапом.

Коммиты:
- 64718cf — итоговый W5/G5 код; 7c6667c — протокол G5.
- b54ceae — immutable routing variants/общий renderer и issuance.
- dbf07ac — W6 автоматические доказательства, телефон открыт.
- 28b80ec — owner API/CLI/embedded UI через общие доменные операции.
- f482bb6 — policy2/schema7, сохранение policy1 history, exact panel DNS/route.
- 8fc03c7 — same-origin для browser form, регрессионные проверки,
  кандидат TLS rehearsal; последний полностью проверенный продуктовый код.
- 9b9ea35 — фиксация sandbox-блокера и остановки, незавершённый runner.

Опорные файлы (пути относительно installer):
controlpanel/PLAN.md — последняя запись определяет порядок.
controlpanel/TEST_STATUS_2026-11-14.md — PASS/PARTIAL/FAIL/OPEN, ревизии/среды.
controlpanel/W7_COPY_STATUS_2026-11-14.md — копии, блокер, production факты.
controlpanel/PROFILE_ROUTING_POLICY.md — окончательная продуктовая policy.
controlpanel/G3_ACCEPTANCE_2026-11-13.md — принятая production миграция/возврат.
controlpanel/G4_ACCEPTANCE_2026-11-13.md — прежние доказательства adapter.
controlpanel/G5_ACCEPTANCE_2026-11-14.md —70SIGKILL и реальные auth/recovery.
controlpanel/WORKER.md — fixed policy/shared executor/reconcile.
../controlpanel/VPN_Control_LLD_Spec_Agent_v1.1.md — обязательная внешняя LLD.
HANDOFF-W3-W4.md исторический; G3/adapter/worker заново не подключать.

Нерешённая проблема:
controlpanel/systemd/vpn-control-panel.service — кандидат TLS frontend Caddy
под UID981, как API, с пустыми caps; закрытый Unix socket0600.
Изоляция vault/DB/proc-root обеспечивалась предполагаемыми mount/seccomp
запретами, но НЕ доказана.
pilot/panel_frontend_rehearsal.py — незавершённый runner:
- RootDirectory7002/+InaccessiblePaths:226/NAMESPACE /run/caddy-admin ENOENT,
  хотя каталог в корне был. Минимальный вариант без+ стартовал.
  Причина различия путей не установлена.
- PID int/str runner исправлен.
- UID981/CapEff0, loopback18650 и namespace копии наблюдались.
- TLS trusted synthetic CA/exact SNI прошёл, GET / дал502; причина неизвестна.
- Probe того же sandbox сообщил "frontend secret boundary readable",
  но конкретный путь ещё не установлен; assertion listdir каталогов /
  stat proc-root/admin socket. Содержимое секретов не выводилось.
- Следующая диагностическая попытка отклонена auto-review по лимиту четырёх
  исправлений; она не исполнялась, обходов не было.
Не считать это доказанной утечкой production, исправленным sandbox или
готовностью к deploy. Не снимать защиты ради прохождения проверки.

После явного разрешения продолжить сначала установить конкретный failed path
и причину502 на новой изолированной копии; повтор старых вариантов без новых
фактов не нужен. Затем доказать identity/mount/socket policy, общий owner CLI
с real copy API/profile file, browser download/alpha13/default/protection,
подготовить и проверить конкретный deploy/rollback package. Не создавать
второй adapter/journal/worker; использовать существующие механизмы.

Что проверено:
Full pinned8fc03c7 Go с обоими сетевыми флагами и exact SFA check/DNS PASS.
Python69/4skip PASS; go mod verify PASS; go.sum прежний, hash в TEST_STATUS.
Браузер7001: owner login через HTTP test bridge, create→потерян202→reload→
исходный intent/тот жеoperation→active PASS, literal HTML имя безопасно,
RU/DM checkbox disabled для1144. Browser download wait инструмент оборвался;
download и последующие alpha13 действия НЕ засчитаны.
Форма no-referrer→Origin:null исправлена на same-origin, external/null403.
Bridge — только тестовый HTTP, не production TLS/SFA доказательство.

Профили:
base по умолчанию без RU/Download Manager для обеих версий.
Выключенная опция с English warning только точная SFA1.15.0-alpha.13,
не alpha.3 и не любая1.15. На1.14.4 опция rejected.
Upstream1.14.4 имеет package_name/rule_set синтаксис; ограничение optional —
продуктовая поддержка, не утверждение отсутствия синтаксиса.
Policy2 exact hosts panel.home.arpa→192.0.2.119 и exact /32 TCP443 Naive
route соответствуют существующему relay allowlist; generic private routing
не расширять. Старые immutable revisions/bindings/credentials не менялись.
OnePlus12: доступны обе сборки. Нужны отдельные base1144/basealpha13/
optionalalpha13 наблюдения с реальным DM/RU, Wi-Fi/mobile, DNS/TLS/panel,
owner/nonadmin/external. Linux checker не заменяет Android.

Среда:
Go /opt/empire-vpn/cache/toolchain/go/bin/go.
GOPROXY=file:///run/vpn-w3-worker-tests/proxy (наличие проверить),
GOSUMDB=off, GOTOOLCHAIN=local, GOFLAGS="-p=1 -mod=readonly".
Флаги exact checker и команды — TEST_STATUS.
Pinned /opt/empire-vpn/cache/w7-pinned-8fc03c7; root7002.
Dev /opt/empire-vpn/cache/w5-auth-XAtR3pjw; там последняя uploaded runner copy.
Старые pinned/root каталоги не затирать; для нового прогона новый каталог.
UI hold7002 удалён cleanup-командой, loopback helpers остановлены;
живой стенд не предполагать. Go cache держать на диске, не в /run.
Не считать успешное подключение SSH доказательством завершения длинного теста.

Production (только читать):
hh-entry85.155.185.169; hh-exit85.155.184.194 через вход.
Резерв193.233.22.78 не трогать. Старые профили/пароли не менять.
На момент последнего чтения API, timer, readonly frontend, Caddy, relay active.
КодGo/Python/binaries69e4708, unit6621689; W5–W7 не развёрнуты.
Фактический API socket /run/vpn-control-api/api.sock,981:981,0600,parent0700.
Generic CLI default /run/vpn-control/api.sock не подходит без VPNCTL_SOCKET.
API981 CapEff0; transport Caddy982 толькоCAP_NET_BIND_SERVICE; relay999:986;
namespace naive. Worker оставляет default root identity systemd:
не возвращать explicit User=root, он ломал effectiveCAP_SETUID/setpriv.
Old frontend transient nh1-panel-readonly.service, DynamicUser. Его stop
может убрать transient unit: до разрешённого переключения нужно root-only
сохранить точный unit и credential sources для реального rollback.
Существующий leaf valid до2026-11-25 11:19:54UTC. TLS/CA/owner credentials
не пересоздавать и не выводить. G3-Canary не пересоздавать и не ротировать.
Новый deploy/control-plane stop требует остановиться и согласовать по
условию владельца. Transport/WG/firewall/routes/restart вне нового разрешения.
Не запускать старые deploy/switch-скрипты. SSH внеWG/fail-closed сохранить.

Секреты и откат:
Root-only G3 snapshots + encrypted verified Windows copies уже существуют.
Пути в /root/g3-pre-receipt.json, /root/g3-post-receipt.json, private window.json.
Owner материалы внеGit в %LOCALAPPDATA%\EmpireVPN\G3-owner.
Перед возвратом после пользовательских изменений экспортировать текущих
активных пользователей; не восстанавливать устаревший auth из pre-архива.
Никаких secrets/profiles/archive вGit/отчёт/stdout.

Кратко по-русски, интерфейс/CLI по-английски. После каждого проверенного
результата обновлятьPLAN с commit/evidence/open/first next step.
Не отмечать G6/G7 принятыми до фактических измерений.
