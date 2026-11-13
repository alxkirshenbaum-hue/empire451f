# G3: пакет переключения nh1

Статус: подготовлен к одному согласованию, **на рабочей паре не выполнен**.
Код и команды данных: `69e4708`, ветка `feature/controlpanel-pilot`.
W3 — 4/5. После согласования и приёмки nh1 закрывается пункт 5; затем W4.

## Что согласуется

Окно 15 минут на hh-entry (`85.155.185.169`), hh-exit (`85.155.184.194`) используется для проверок. Создать две системные идентичности без входа: `evpn-caddy` 982:982 и `evpn-panel` 981:981; разделить их с существующим relay `evpn` 999:986. Открыть **только закрытый Unix admin socket** Caddy, изменить группу auth/Caddyfile и владельца ACME, установить проверенные CLI/API/worker и передать запись штатным MIG-05. Проверить создание одного нового пользователя `G3-Canary`, выдачу владельцу и оба профиля. Новый пользователь остаётся в реестре; его секрет не выводится в отчёт.

Один начальный restart Caddy: соединения могут оборваться. Ожидается несколько секунд, плановый верхний предел остановки текущей службы — 90 секунд плюс запуск/проверка. При откате нужен ещё один restart с таким же пределом. Создание после переключения использует Caddy load без restart службы. SSH хостов, WG, firewall, маршруты, sing-box и резерв не меняются. Предыдущие пароли/профили сохраняются.

Новый API доступен только через Unix socket и SSH владельца. Действующий приватный frontend `nh1-panel-readonly` сохраняется; подключение нового интерфейса и проверки обеих SFA остаются в W7/W6. Этот пакет не объявляет их завершёнными.

## Входные факты и доказательства

Сверка чтением 13.11.2026: все 19 tracked-файлов совпали с manifest; installation nh1, admin off ровно один; Caddy и sing-box active под evpn:evpn в naive. Auth/Caddyfile 0640 root:986, state 0700 root, общий lock 0600 root. `/var/lib/vpn-control`, `/etc/vpn-control`, оба новых бинарника/аккаунта отсутствуют; UID/GID 981/982 свободны. Новые SSH к обеим нодам успешны. Свободно 3299 МиБ. Эти условия повторно проверяются перед изменениями, отклонение останавливает пакет.

Репетиция `69e4708`: настоящий registry init/owner bootstrap → inspect/plan/stage → MIG-05 → штатный vpn-add-user → worker → Naive TLS/TCP/UoT нового и контрольного пользователей → отказ неверному паролю → выдача владельцу → возврат установщику → восстановление runtime и старый профиль. Проверены отказ пробы/commit MIG-05, дрейф до публикации, явная SSH-сверка, отмена неудавшегося MIG-05, отказ commit создания, потеря ответа и повтор с прежним секретом. Файлы восстанавливаются после обрыва между заменой Caddyfile и manifest.

В копии реальные предложенные UID/GID: Caddy 982:982, API 981:981, relay 999:986; CapEff=0, один lo-only namespace. Socket фактически 0200, parent 0700; API/relay отказаны; клиентский proxy и HTTPS `/config/` не дают admin. RootDirectory запускается с ProtectSystem=strict и root-relative ReadWritePaths. Это не исполнение точного production unit: на nh1 обязательна отдельная проверка установленного unit/идентичности/namespace после старта. Для production Caddy сохраняется только CAP_NET_BIND_SERVICE; CAP_NET_ADMIN не добавляется.

Копия использует echo TCP/UoT и тестовый CA. На двух существующих пользователях рабочей пары отдельно пройдены exit_https с выходом 85.155.184.194, DNS/UoT через 1.1.1.1:53, публичный TLS/сайт/неверный пароль. Эти рабочие проверки повторяются после переключения для старого и нового пользователя. Отключение WG в этом окне не выполняется; прежние результаты fail-closed переиспользуются.

## Снимок и подготовка

Все следующие изменения выполняются **после согласования**, без `set -x` и вывода конфигураций. Открыть два независимых SSH к входу, проверить новый SSH к выходу; закрыть старые сеансы установочного мастера/vpn-add-user. Не начинать при незавершённых pending/user-rollback/return-intent/panel-auth-pending. Зафиксировать UUID окна `WINDOW`, UUID плана `RUN` получается из inspect, не придумывается.

На входе исходники `69e4708` уже заморожены в `/run/vpn-w3-worker-tests/pinned-69e4708`; бинарники после приёмочной сборки — в `/run/vpn-w3-worker-tests/rehearsal-bin`. При утрате /run пересобрать из git-архива этой ревизии через прежнее file-proxy и повторить проверки; не брать произвольный HEAD.

```sh
umask 077
src=/run/vpn-w3-worker-tests/pinned-69e4708
WINDOW=$(python3 -c 'import uuid; print(uuid.uuid4())')
export WINDOW
python3 -B "$src/g3_snapshot.py" nh1 "$WINDOW" pre > /root/g3-pre-receipt.json
```

Снимок `/root/vpn-control-g3/$WINDOW/pre`: закрытые архив/flat import/квитанция, метаданные владельцев/режимов/xattr, auth/профили/manifest/обёртка/Caddy unit/dropins/ACME; SQLite при наличии — online backup + integrity_check. Лимит архива 32 МиБ; несогласованный/частичный снимок останавливает окно. Квитанция и её SHA остаются в закрытом файле, архив не прикладывать к отчёту.

На Windows, каталог **вне репозитория** с ACL только владелец+SYSTEM:

```powershell
$ownerDir = Join-Path $env:LOCALAPPDATA 'EmpireVPN\G3-owner'
& .\pilot\g3-owner-snapshot.ps1 -PrepareOwner -OwnerDirectory $ownerDir
# $receipt получают по SSH из /root/g3-pre-receipt.json, без печати архивов/секретов.
$receipt = (ssh -o BatchMode=yes hh-entry 'cat /root/g3-pre-receipt.json') | ConvertFrom-Json
$raw = Join-Path $ownerDir ($receipt.window + '-pre.tar')
scp ('hh-entry:' + $receipt.archive) $raw
if ($LASTEXITCODE) { throw 'Snapshot transfer failed' }
& .\pilot\g3-owner-snapshot.ps1 -OwnerDirectory $ownerDir -Source $raw -ExpectedSha256 $receipt.sha256
if ($LASTEXITCODE) { throw 'Owner snapshot verification failed' }
Remove-Item -LiteralPath $raw
```

До изменений обязательны успешные encrypt/decrypt/hash и сохранённая локальная квитанция. Ключ получателя остаётся на Windows. На VPS защищённый исходный снимок сохраняется для быстрого отката. Самопроверка Windows проверяет ACL, повтор без замены ключа/шифротекста, повреждение и совместимость с прежним W1 JWE provider. Полный восстановительный сценарий W8 остаётся отдельным критерием.

Установить только allowlist из этой ревизии в `/opt/empire-vpn/controlpanel/69e4708` (root:root, directory 0755, Python/template 0644). Скрипты: `owned_auth.py create_probe.py inspect_legacy.py handoff_legacy.py return_legacy.py render.py verify.py g3_snapshot.py g3_restore_runtime.py`; шаблон `templates/vpn-add-user` установить как `vpn-add-user.template`, `templates/sfa-profile.json` как `sfa-profile.json`. Сверить SHA каждого с замороженным источником. Бинарники установить root:root 0755 в `/usr/local/bin/vpnctl` и `/usr/local/bin/vpn-control`. Никаких исходных профилей в release.

```sh
release=/opt/empire-vpn/controlpanel/69e4708
export release
install -d -m 0755 "$release"
for name in owned_auth create_probe inspect_legacy handoff_legacy return_legacy render verify g3_snapshot g3_restore_runtime; do
  install -m 0644 "$src/$name.py" "$release/$name.py"
done
install -m 0644 "$src/templates/vpn-add-user" "$release/vpn-add-user.template"
install -m 0644 "$src/templates/sfa-profile.json" "$release/sfa-profile.json"
install -m 0755 /run/vpn-w3-worker-tests/rehearsal-bin/vpnctl /usr/local/bin/vpnctl
install -m 0755 /run/vpn-w3-worker-tests/rehearsal-bin/vpn-control /usr/local/bin/vpn-control
install -d -m 0700 /etc/vpn-control
/usr/local/bin/vpnctl registry init --installation nh1 --sfa-template "$release/sfa-profile.json" \
  --approve-sha256 "$(sha256sum "$release/sfa-profile.json" | cut -d' ' -f1)"
```

Bootstrap владельца — `vpn-control --bootstrap-owner owner --owner-password-stdin`, пароль передать по stdin SSH из закрытого Windows-файла владельца, без argv/журнала/вывода. Сгенерировать случайные 32 байта на Windows, сохранить с тем же приватным ACL. Повтор bootstrap при существующем владельце не сбрасывает пароль; не удалять DB/vault для обхода отказа.

```sh
SNAPSHOT=/root/vpn-control-g3/$WINDOW/pre/import
export SNAPSHOT
python3 -B "$release/inspect_legacy.py" "$SNAPSHOT" --registry /var/lib/vpn-control/state.db > /root/g3-inspect.json
RUN=$(python3 -c 'import json; print(json.load(open("/root/g3-inspect.json"))["run_id"])')
export RUN
python3 -B "$release/inspect_legacy.py" "$SNAPSHOT" --registry /var/lib/vpn-control/state.db --plan "$RUN" > /root/g3-plan.json
/usr/local/bin/vpnctl migration execute --approved-plan "$RUN" --staging-db /var/lib/vpn-control/state.db \
  --snapshot "$SNAPSHOT" --vault-key-file /var/lib/vpn-control/vault.key
```

Любой review_required/ненулевой exit — остановка до системных изменений. Initial SFA revision — только 1.14.4, её digest явно проверяется. Одобрение шаблона для 1.15 alpha13 этим не подменяется.

## Изменения в окне

Перед любым изменением повторить отсутствие/свободу имён и UID/GID. Создать через `/usr/sbin/groupadd --system --gid 982 evpn-caddy` и `--gid 981 evpn-panel`, затем `/usr/sbin/useradd --system --uid 982 --gid evpn-caddy --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin evpn-caddy` и аналогично 981/evpn-panel. Без дополнительных групп и паролей.

Под общим `/run/lock/empire-vpn.lock`:

1. Закрыть оставшиеся старые мастера; проверить исходное поколение против снимка. Заменить **одну** строку `admin off` на `admin unix//run/evpn-nh1-caddy-admin/admin.sock`; другие байты Caddyfile сохранить через `handoff_legacy.publish(...,preserve=True)` и fsync каталога. Установить развёрнутый `vpn-add-user.template` (STATE=/var/lib/empire-vpn/nh1, BASE=/etc/empire-vpn/nh1, PREFIX=evpn-nh1) root/0700; его hash будет подтверждён MIG-05.
2. Auth/Caddyfile: только chown root:982, режим 0640 сохранить. Существующий ACME `/var/lib/empire-vpn-acme`: проверить отсутствие symlink/спецфайлов, сменить владельца всех существующих файлов/каталогов на 982:982 с сохранением режима/xattr. Не копировать и не перевыпускать сертификаты.
3. Создать единственный новый dropin `/etc/systemd/system/evpn-nh1-caddy.service.d/80-controlpanel-g3.conf` root/0644:

```ini
[Service]
User=evpn-caddy
Group=evpn-caddy
RuntimeDirectory=evpn-nh1-caddy-admin
RuntimeDirectoryMode=0700
```

4. Записать root/0600 worker policy `/etc/vpn-control/worker-nh1.json`: installation=nh1, owner_run=$RUN, socket=/run/evpn-nh1-caddy-admin/admin.sock, helper=$release/owned_auth.py. `validate_command` — массив `/usr/bin/ip netns exec naive /usr/bin/setpriv --reuid=982 --regid=982 --clear-groups --bounding-set=-all /opt/empire-vpn/bin/caddy validate --config -`; `probe_command` — `/usr/bin/python3.14 -B $release/create_probe.py --policy /etc/vpn-control/probe-nh1.json`. Команды/пути фиксированы root policy, клиент их не задаёт.
5. Probe policy root/0600: address=85.155.185.169, port=443, domain=empire451f.duckdns.org, binary=/opt/empire-vpn/bin/sing-box, auth_file=/etc/empire-vpn/nh1/auth.caddy, canary_login=master_user, scratch_dir=/run/vpn-control/probes, tcp_mode=exit_https, expected_exit=85.155.184.194, udp_mode=dns, udp_host=1.1.1.1, udp_port=53, site_sha256=`187d60432a88797e5b066502a990d778efe802fd27cae3b31359dc6661198020`. Без ca_file: публичная TLS-проверка обязательна. Подтвердить site hash до окна; изменение сайта требует сверки, не подмены digest ради PASS.
6. Подготовить `/run/vpn-control` 0755 root, probes 0700 root; постоянное создание после reboot — tmpfiles.d с этими двумя точными путями. Registry directory/DB/key и существующие SQLite sidecars передать 981:981, directory0700/files0600; root worker сохраняет доступ. Prepared Caddy snapshots хранятся отдельно в root-only `/var/lib/empire-vpn/nh1/panel-operations`.
7. До restart выполнить Caddy adapt/validate непривилегированно в naive с XDG_DATA_HOME/XDG_CONFIG_HOME=/var/lib/empire-vpn-acme, результаты/JSON держать в закрытом scratch, stderr не выводить в отчёт. При отказе восстановить исходные Caddyfile/группы/ACME, убрать только созданный dropin; Caddy ещё не перезапускался.

Установить из ревизии service/timer (root/0644): `vpn-control-worker@.service`, `.timer`, `vpn-control-api.service`; worker-nh1.env root/0600 содержит только `OWNER_RUN=$RUN`, api.env — только `PROFILE_DOMAIN=empire451f.duckdns.org`. API socket=/run/vpn-control-api/api.sock, parent0700 evpn-panel. Timer пока **не запускать**.

```sh
systemctl daemon-reload
systemctl restart evpn-nh1-caddy.service
# Проверить active, реальный UID/GID, namespace, caps, socket и сайт.
XDG_DATA_HOME=/var/lib/empire-vpn-acme XDG_CONFIG_HOME=/var/lib/empire-vpn-acme \
 /usr/local/bin/vpnctl migration cutover --installation nh1 --approved-plan "$RUN" \
 --snapshot "$SNAPSHOT" --legacy-writers-stopped
systemctl start vpn-control-api.service
systemctl start vpn-control-worker@nh1.service
# После всех проверок G3 и idle:
systemctl enable vpn-control-api.service vpn-control-worker@nh1.timer
systemctl start vpn-control-worker@nh1.timer
```

MIG-05 сам сверяет staging, исходные секреты, новый wrapper, все tracked-файлы, полный live JSON и свежий доступ master+контрольного; только потом атомарно активирует пользователей и пишет verified_cutover/receipt. Ручной SQL для флага запрещён. Тайм-аут/потеря ответа: повтор сверяет факты и возвращает прежнюю квитанцию. `reconcile_required`: остановить timer, проверить status/files/live JSON/пробы по SSH; после доказанной согласованности только явный повтор той же команды `--reconcile`. Не генерировать новые секреты и не добавлять новый run для обхода блока.

## Приёмка и точки остановки

- Старый профиль побайтно прежний; свежие TCP exit_https, DNS/UoT, сайт/TLS и отказ неверному паролю до/после. Новый `G3-Canary` ставится штатным vpn-add-user в очередь; worker подтверждает live-кандидат, новое/контрольное подключение до active/succeeded. Повтор запроса сохраняет прежние ID/секрет, следующий worker idle.
- Вход владельца через приватный API/SSH; скачивание нового профиля: без сессии401, до active404, после200/no-store + PROFILE_ISSUED. JSON хранить только в защищённом каталоге владельца, проверить sing-box check и новые подключения обоих профилей. Сайт и прежний приватный panel endpoint проверить извне и через VPN; admin JSON нигде не опубликован.
- Проверить socket owner982, закрытый mode с owner-write, parent0700; прямой connect как API981, relay999 и actual frontend UID должен получить отказ. Через proxy TCP2019 проверять именно отсутствие HTTP-данных, SOCKS ACK доказательством не считать. Caddy в naive, без CAP_NET_ADMIN; sing-box/SSH/WG прежние.
- **Новые** SSH к hh-entry и hh-exit после изменений. Если для принятия нужен телефон: одно действие — импортировать выданный новый профиль в SFA 1.14.4 и открыть `https://api.ipify.org`; ожидаемый адрес `85.155.184.194`. Не удалять прежний профиль. Проверки alpha13/обоих клиентов по W6/W9 остаются отдельными.
- Любой конфликт поколения/manifest/live JSON, недоступность старого пользователя, неверный выход/DNS, раскрытие API/admin, потеря SSH или неуспех validate/probe/commit — остановка timer и конфликтующих изменений. Не считать частичный успех приёмкой.

После успешной проверки создать `post` snapshot тем же WINDOW, передать/зашифровать/проверить на Windows тем же способом, сохранить закрытые квитанции и результаты без секретов. PLAN: ревизия, факты рабочей пары, состояние возврата/снимков. Только теперь W3 5/5; первый следующий шаг — оставшиеся критерии W4/G4.

## Откат

Оператор держит второй SSH. Сначала остановить timer и дождаться завершения oneshot; API остановить, чтобы новые изменения/выдачи прекратились. Проверить status и pending-журналы. При незавершённой create-операции сначала штатная сверка **той же** операции/кандидата с прежним секретом. Если результат неоднозначен — сохранить снимки/журналы, оставить блокировку и восстанавливать по SSH; нельзя затирать auth старым архивом.

После verified_cutover, **как до первого нового пользователя, так и после изменений**, один путь сохраняет все актуальные активные учётные записи:

```sh
systemctl stop vpn-control-worker@nh1.timer
systemctl stop vpn-control-worker@nh1.service vpn-control-api.service
exec 9<>/run/lock/empire-vpn.lock
flock -x 9
python3 -B "$release/return_legacy.py" --installation nh1 --staging-db /var/lib/vpn-control/state.db \
 --approved-plan "$RUN" --vault-key-file /var/lib/vpn-control/vault.key --vpnctl /usr/local/bin/vpnctl --lock-fd 9
systemctl stop evpn-nh1-caddy.service
python3 -B "$release/g3_restore_runtime.py" --installation nh1 --snapshot "$SNAPSHOT" --approved-plan "$RUN" \
 --legacy-uid 999 --legacy-gid 986 --admin-socket /run/evpn-nh1-caddy-admin/admin.sock --lock-fd 9
# Сверить точное содержимое созданного выше dropin; чужие dropins не трогать.
rm -- /etc/systemd/system/evpn-nh1-caddy.service.d/80-controlpanel-g3.conf
systemctl daemon-reload
systemctl start evpn-nh1-caddy.service
flock -u 9
exec 9>&-
```

Если MIG-05 не завершился, но уже опубликовал передачу: вместо return выполнить существующий `handoff_legacy.py --installation nh1 --snapshot "$SNAPSHOT" --staging-db /var/lib/vpn-control/state.db --approved-plan "$RUN" --admin-socket /run/evpn-nh1-caddy-admin/admin.sock --wrapper-sha256 "$(sha256sum /usr/local/bin/vpn-add-user | cut -d' ' -f1)" --rollback --reconcile --lock-fd 9`, затем тот же runtime restore. Он допускается только при доказанно неизменённых provisioning-записях/исходных секретах. До публикации передачи исходный manifest ещё прежний: восстановить Caddyfile/обёртку и метаданные из pre/files; БД оставить закрытой для диагностики, новых данных пользователей ещё нет. При отказе до restart восстановление не требует restart; если restart уже был, выполнить указанный stop/start.

`g3_restore_runtime.py` не заменяет auth/clients/profile из pre: проверяет journaled return/abort, точные два допустимых образа Caddyfile, auth↔экспорт↔manifest, восстанавливает только admin off, legacy group и ACME owner, исправляет tracked Caddyfile/wrapper hashes. Оставляется проверенная исправленная обёртка установщика, которая пишет auth root:evpn. Повтор после сбоя между Caddyfile/manifest проверен. Системные аккаунты, release, DB/vault и snapshots не удаляются; остановленные новые службы отключить (`systemctl disable vpn-control-api.service vpn-control-worker@nh1.timer`).

После возврата проверить active/evpn:evpn/admin off, старый **и новый** профили, контрольный пароль и отказ неверному, сайт, приватность панели и новые SSH обеих нод. Установщик должен разрешить свою ветку; проверять отказом на подтверждении новой выдачи, без лишнего изменения пользователя. Факт отката и сохранения новых пользователей записать в PLAN. Возврат из неизвестного внешнего дрейфа не обещается автоматическим: требуется сверка по SSH.
