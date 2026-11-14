# W6/W7 — состояние проверок на 14.11.2026

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