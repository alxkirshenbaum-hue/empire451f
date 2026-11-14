> Актуальный общий статус: [PROGRESS.md](PROGRESS.md); последняя полная локальная проверка: [W8_LAB_QUALIFICATION_2026-11-14.md](W8_LAB_QUALIFICATION_2026-11-14.md). Ниже сохранена хронология: ранние FAIL/OPEN не являются текущим состоянием исправленных sandbox/deploy/owner проверок.

# W6/W7 — состояние проверок на 14.11.2026

**Актуально: W6 3/4/G6 OPEN; W7 3/4/G7 OPEN. Старый sandbox FAIL устранён af63ab0; окончательные результаты — в последних дополнениях. Production switch/телефон не выполнены.**

Это журнал фактов, а не приёмка G6/G7. Новые проверки в рамках этой
документальной передачи не запускались. Последний полный проверенный
продуктовый код — 8fc03c7; 9b9ea35 фиксирует остановку и незавершённый runner.

| Область | Результат | Ревизия / среда / ограничение |
|---|---|---|
| W5/G5 | PASS на копии | 64718cf; [протокол G5](G5_ACCEPTANCE_2026-11-14.md). W5 4/4. Не повторять завершённый этап. |
| W6 immutable routing variants | PASS автоматически | f482bb6: policy2/schema7, исходные revisions/bindings/credentials сохранены. |
| Full Go | PASS | Pinned8fc03c7, отдельный systemd-run, PrivateNetwork/PrivateTmp/ProtectSystem=strict, оба сетевых флага. |
| Python | PASS, 4 SKIP | Pinned8fc03c7: unittest discover, Ran69/skipped4. Пропуски не являются положительными результатами. |
| Зависимости | PASS | go mod verify; SHA256 репозиторного go.sum: d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825. |
| Exact SFA check + DNS | PASS на Linux-копии | Base1.14.4/base1.15.0-alpha.13/optionalalpha13; реальные A/AAAA ответы, exact binary version, PrivateNetwork. Это не Android. |
| Owner API/CLI contracts | PASS целевых и полного наборов | Авторизация/Origin/CSRF, CAS/idempotency/replay, protected/case/capacity, private file/no-overwrite/no secret stdout. Файлы ниже. |
| Браузерный create/retry | PARTIAL E2E PASS | RootDirectory7001/f482bb6 с HTTP test bridge: потерян202, reload, исходный intent, прежний operation ID, active. Повторный секрет не создавался. Это не production HTTPS/SFA E2E. |
| Display name / UI default | PASS наблюдения | Literal HTML остался текстом; base1.14.4, опция RU/DM выключена и disabled. |
| Форма входа | Дефект исправлен | no-referrer давал Origin:null. same-origin проверен браузером через bridge, затем actual API собран в7002 на8fc03c7; null/external guard403 и full suite PASS. |
| Browser download / alpha13 toggle | НЕ ПОДТВЕРЖДЕНО | Инструмент ожидания download прервался: expired continuation. Последующие действия в том вызове не засчитываются. |
| Real frontend sandbox | FAIL / расследование остановлено | Детали ниже. G7 блокирован. |
| Owner CLI ↔ real copy API ↔ profile file | ОТКРЫТО | Unit/fake Unix API tests не заменяют незавершённую сквозную проверку. |
| OnePlus12 / G6 | ОТКРЫТО | Обе сборки доступны со слов владельца, новых измерений нет. W6 3/4. |
| Новая панель через SFA / owner/nonadmin/external | ОТКРЫТО | Старый readonly pilot и G0a не заменяют новую приёмку W7. W7 2/4 — реализация, не G7. |
| Deploy/rollback package нового UI | НЕ ГОТОВ | Production не обновлялся; сначала доказать изоляцию и подготовить конкретный пакет. |
| W8/W9 / полный E1 | НЕ ПРИНЯТО | Не реализованные действия/метрики в UI явно недоступны. |

## Нерешённая проблема фронтенда

Кандидат [vpn-control-panel.service](systemd/vpn-control-panel.service) запускает
TLS Caddy под API UID981, чтобы использовать закрытый API Unix socket0600.
Для этого решения обязательно доказать запреты чтения vault/данных/чужого
proc-root и межпроцессного доступа. Общий UID сам по себе такой защиты не даёт.

Проверка [panel_frontend_rehearsal.py](../pilot/panel_frontend_rehearsal.py)
в RootDirectory7002 дала следующие наблюдения:

1. InaccessiblePaths с префиксом+ не смонтировался:
   226/NAMESPACE, /run/caddy-admin: No such file or directory.
   Каталог существовал в синтетическом корне.
2. Минимальная проба без+ стартовала. Это наблюдение, а не установленная
   причина различия systemd-путей. Изменение перенесено только в runner.
3. Исправлен int/str PID в subprocess runner.
4. Frontend слушал127.0.0.1:18650, UID981/CapEff0, namespace копии.
   TLS с trusted synthetic CA/exact SNI прошёл, GET / вернул502.
   Причина502 не установлена.
5. Probe с одинаковыми свойствами sandbox сообщил
   «frontend secret boundary readable». После исправления assertion используется
   listdir для каталогов, stat для proc-root/admin socket. Сообщение не назвало
   конкретный путь. Содержимое секрета не читалось и не выводилось.
   Это не доказанная утечка production; это провал обязательного утверждения
   изоляции кандидата.
6. Следующий диагностический блок был отклонён автоматической проверкой как
   продолжение сверх лимита четырёх исправлений. Он не выполнялся.
   Не считать предложенную конкретизацию пути полученным результатом.

Были поправки путей, типа PID, диагностики subprocess и assertion.
Нельзя утверждать, что причина502 была четыре раза определена и исправлялась:
причина осталась неизвестной. Остановка применена к серии попыток проверки
sandbox согласно решению auto-review. Дальнейшая диагностика не разрешена
одной только передачей состояния; требуется явное возобновление владельцем.

## Файлы тестов и воспроизведения

- [Routing/checker/DNS tests](internal/storage/routing_test.go),
  [реальная DNS-проба](../pilot/profile_dns_check.py).
- [Owner API tests](cmd/vpn-control/download_test.go),
  [owner CLI Unix API tests](cmd/vpnctl/panel_cli_linux_test.go),
  [auth/form tests](internal/auth/auth_test.go).
- [Общая RootDirectory-репетиция](../pilot/run_full_worker_rehearsal.sh),
  [подготовка корня](../pilot/prepare_rehearsal_root.py),
  [общий сценарий](../pilot/full_worker_rehearsal.py).
- [HTTP browser test bridge](../pilot/ui_test_bridge.cjs) — только loopback,
  синтетические credentials, не компонент production. TLS/Origin rewriting
  и снятие Secure на HTTP fixture не являются доказательством production TLS.
- [Краткая передача и пути копий](W7_COPY_STATUS_2026-11-14.md).

## Зафиксированная среда

Pinned: /opt/empire-vpn/cache/w7-pinned-8fc03c7.
Синтетический root: rehearsal-root-7002; старые прогоны не затирать.
После остановки marker ui-hold удалён командой cleanup; loopback helper
processes завершены. Новый readiness-проверкой это не объявляется.

Go: /opt/empire-vpn/cache/toolchain/go/bin/go.
GOPROXY=file:///run/vpn-w3-worker-tests/proxy; GOSUMDB=off;
GOTOOLCHAIN=local; GOFLAGS="-p=1 -mod=readonly".
Флаги полного Go-прогона:
VPN_TEST_CADDY_ADAPTER=1, VPN_TEST_NAIVE_PROBE=1,
VPN_TEST_SFA_CHECK_1144=/opt/empire-vpn/bin/sing-box,
VPN_TEST_SFA_CHECK_ALPHA13=/opt/empire-vpn/cache/w6-checker-alpha13/sing-box-1.15.0-alpha.13-linux-amd64/sing-box,
VPN_TEST_SFA_DNS=1.
Команды внутри зафиксированной копии: go mod verify; sha256sum go.sum;
go test ./... из controlpanel; python3 -B -m unittest discover -s tests из installer.
Для следующего принятого результата нужен новый каталог прогона и точная
проверяемая ревизия, а не изменения в прежнем pinned-каталоге.

## Почему началась разработка W7

План разрешает объединить ручные проверки маршрута панели, импорта и RU/DM
в один сеанс на телефоне. После автоматической части W6 агент интерпретировал
это вместе с поручением продолжать до W7 как основание подготовить независимые
API/CLI/UI на копии до сеанса. Это решение о порядке разработки агента,
не отдельное разрешение принять G6, выдать непроверенную совместимость или
изменить production. W6 остаётся первым незакрытым этапом.

Правильный статус: W6 3/4, G6 открыт; параллельно подготовлен W7 2/4,
G7 открыт и заблокирован. Совместная приёмка телефона ещё не подготовлена.

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
## Дополнение: real owner CLI и browser — root7201

Продуктовый код8fc03c7, source baselineaf63ab0, новый root7201.
PASS CLI→real Unix API→canonical worker: create/replay/active/rename/CAS/
protected denial,3 private profiles, no-overwrite,1144 option rejection,
no secret/session stdout, fresh issued-profile TCP/UoT.
Runner: ../pilot/owner_cli_rehearsal.py.

PASS browser: owner sign-in, master_user mutation protection, alpha13 optional
warning, option cleared+disabled on1144, downloadMedia сохранил3 actual files.
JSON base/optional shape и API issuance client/variant/hash сверены, integrityok.
Base1144 и basealpha13 имеют одинаковые bytes при одинаковом credential — это
ожидаемо; issuance target записан отдельно. Профили не выводились и не вGit.
Тестовые скачанные файлы и bridge удалены; root7201 inactive/MainPID0 подтверждён.
Прежняя запись «download not confirmed» относится к7001 и этим дополнением
заменена для desktop copy. Android/G6 и owner/nonadmin/external G7 открыты.
Новая версия package/runner ещё ожидает полный pinned набор перед W7/3.
## W7/3 copy acceptance — cd3de10

Full pinned -count=1 Go/all flags PASS, Python69/4skip PASS, mod verify and
unchanged go.sum PASS. Root7202 with binaries BUILT oncd3de10: real owner CLI
and fresh profile TCP/UoT PASS; af63ab0 TLS/sandbox runner PASS. Browser
root7201 evidence is reused with explicit product diff8fc03c7..cd3de10 empty.
W7/3 checked; G7 still OPEN until connection and actual phone/security matrix.

Offline package17 files/33,295,255 bytes: verify/hash/modes and negative
tamper/symlink/unlisted-file checks PASS; readonly replay sh-n and systemd
verify PASS (unrelated host CPUAccounting warnings). Public source checksum
matches production approved source by read-only query; integrityok,
unfinished0, generation2. Adding reviewed snapshot/return helper files changes
package contents only; final revision/manifest recorded in the next checkpoint.
Entire production deploy/rollback execution remains unperformed and unclaimed.
## Final package checkpoint — ad6b653

See [package receipt](W7_PACKAGE_RECEIPT_2026-11-14.md) and
[public manifest](W7_PACKAGE_MANIFEST_ad6b653.json).19files/33,306,900bytes.
ManifestSHA256 e512a536a57256dbaff7025991621551cda11687b14423ebb9ce5abb281b6ba0.
Final verify/tamper/symlink/unlisted-file/unit syntax/replay sh-n passed.
Payload binaries are byte-identical to tested cd3de10; product/tests/deps/
shipped helpers diffcd3de10..ad6b653 empty. Full pinnedcd3de10 reused;
no redundant full Go run for packaging-only changes.
Root7202 inactive/MainPID0/Resultsuccess observed. No production deploy/CRUD/
stop/restart. Next action needs an approved control-plane window per
W7_UPGRADE_WINDOW.md, with fresh protected snapshots/transient replay capture
before stop. Entire production switch/rollback and phone remain unexecuted.
W7 3/4, G7 OPEN; W6 3/4, G6 OPEN. E1 not released.
## Approved production connection — 2026-11-14

Owner explicitly approved the stated window. See
[production protocol](W7_PRODUCTION_WINDOW_2026-11-14.md).
Packagead6b653/tested binariescd3de10 and versioned helpers are deployed;
schema7/integrityok/active4/gen2/unfinished0. API/new frontend/worker active.
Actual mount/UID/cap/secret boundary, existing owner/admin separation,
external privateport/Host/SNI, fresh existing-canary TCP/UoT/TLS/site/control
and new SSH before/after passed. Original profiles/users/credentials/key/
transport files and PIDs/restarts preserved. No agent production CRUD.
Fresh pre(core+control)/post snapshots encrypted/decrypt/hash-verified with
EXISTING owner recipient. Control-only guard canceled after window complete.
Whole-window rollback was prepared but NOT executed; no transport restart.
Three NEW private existing-user phone profiles issued without rotating creds;
exact check3/3 and private Windows ACL passed. Actual phone remains OPEN.
W6 3/4/G6 OPEN, W7 3/4/G7 OPEN. Earlier “not deployed” entries are historical.
14.11.2026 — телефонная проверка владельца: первый base-профильSFA1.14.4 импортирован, VPN подключился, вход в новую панель успешен; владелец сам создал daria, скачал её профиль и подключился через него. Это фактическое owner phone create→result→download→connect, не агентский CRUD. Android build/тип сети/точное время стабильности пока не сообщены. Read-only подтверждение сервера: daria active/version2, user.create succeeded, выдача записана; active5, generation3, integrityok.

Снимки окна до daria теперь исторические: полный rollback старого SQLite/auth запрещён без CURRENT active-user export/fresh snapshot. Control-only recover сохраняет текущий registry/credentials при несовпадении baseline. Пользователи/пароли не откатывались.

Дальше — basealpha13/optionalalpha13, RU/domain/IP и реальный Download Manager. Предложена внешняя проверенная Cloudflare20MiB ссылка (HTTP200/application/octet-stream/Content-Length20971520); она проверяет не-OpenAI DM/direct. Загрузку ChatGPT/OpenAI черезVPN требуется подтвердить отдельно, локальный файл/переход по ссылке не доказывает это. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN; недостающие телефонные измерения не закрыты.
Уточнение запроса тестового файла: владелец требует20MB пустышку, размещённую во внутреннем хранилище ChatGPT с HTTPS attachment link. В данном сеансе доступен Windows workspace, но tool для произвольного file attachment/upload в ChatGPT не предоставлен. Проверенная внешняя Cloudflare-ссылка и локальный file link не заменяют OpenAI download; эта часть проверки не выполнена. Никакая локальная ссылка не объявлялась OpenAI attachment. Инструменты publication/production для обхода этого ограничения не использовались.
14.11.2026 — владелец подтвердил: «все3 профиля проверил, подключаются работают». Записан PASS подключения и базовой работы на телефоне для base1144, basealpha13 и optionalalpha13. Ранее отдельно подтверждены owner login/создание daria/download/подключение её профиля. Это не самостоятельное доказательство маршрута Download Manager/RU, DNS/IPv6 leak, Per-App или работы Wi-Fi+mobile; Android/точная строка сборки/сеть/длительность пока не сообщены. Production изменений агент не выполнял. Первое следующее действие — уточнить фактически проверенные сеть/панельalpha13/RU-DM маршруты. G6/G7 не объявлять полностью принятыми по одному факту подключения.
## Inventory checkpoint — parallelisation proposal, 2026-11-14

[Inventory/plan](PARALLEL_PLAN_2026-11-14.md) prepared from source/evidence.
No tests rerun, no agents/worktrees started, no production access/changes in
this checkpoint. W7 alpha13 owner/panel Wi-Fi confirmed by owner.
ChatGPT download failures are explicitly deferred by owner; do not investigate
or classify them as passing. Backlog remains outside the current work.
Aggregate RAM≤500MB and separate disk≤500000000bytes both apply; complete
resource/restore gates remain unverified. Await first organisational approval.
14.11.2026 — первый согласованный parallel round интегрирован. Lead4/4; SOL-A3/3 portable (source6dde629, integrated7e0d761); SOL-B3/3 + SEC mapping2/2 (source2ba7245/7fdb84e, integrated7ff71f5/4d64384). Общее targeted Python tests/test_w8_*.py на4d64384: Ran13 OK/no skips, Python3.12.14/SQLite3.53.1/cryptography50.0.2. B независимо проверил A, A проверил B, оба проверили Lead contract; review fixes применены до интеграции. Полный продуктовый набор не запускался, новый gate не принимается. Artifact inspector read-only/streaming, возвращает только artifact_check_passed с registry_consistency=not_run; не новый backup/crypto/journal и не пригодный restore. Ограничения PAX/xattrs/private immutable staging/DB binding/живой restore/ресурсы явные. Найдены пробелы текущего SEC collector; не исполнялся. [Поагентный статус/ASTRA](PARALLEL_STATUS.md), [отчёт backup](reports/W8_BACKUP_CANDIDATE.md), [SEC review](reports/W8_SECURITY_REVIEW.md).

Владелец сообщил об отсутствии отдельного Linux и поручил выбрать среду. Lead выбрал локальный WSL2 перед production: Windows19045/виртуализация/SLAT подходят, WSL и VirtualMachinePlatform disabled; включение требует Windows admin/UAC и ручной перезагрузки. [Конкретные команды и порядок возврата](LOCAL_LINUX_RUNNER.md) подготовлены; ничего не устанавливалось/не перезагружалось. Первое следующее действие — выполнить local administrator enable с -NoRestart и согласовать удобную ручную перезагрузку, затем подтвердить отдельный Linux/systemd runner и продолжить W8 integration/runtime proof. До того portable пакеты завершены, Linux proof NOT_RUN. Production не читался/не менялся, BACKLOG не трогался. ASTRA0, неудачных исправлений0. W6 3/4/G6 OPEN, W7 3/4/G7 OPEN, G8 не принят, E1 не выпущен.

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
