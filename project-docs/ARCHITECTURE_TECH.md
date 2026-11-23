# Техническая архитектура CodexVPN

Обзор подтверждённых контрактов; точная доказанность релиза — CURRENT.md и release report.
Историческую схему нельзя применять на серверах как deploy-инструкцию.

## Компоненты и сетевые границы

Клиент SFA → HTTPS/Naive входа → Caddy forwardproxy → локальный HTTP CONNECT
127.0.0.1:1081 → sing-box HTTP inbound/UoT v2 → WireGuard → exit NAT → Интернет.
HTTP upstream нужен для служебного sp.v2.udp-over-tcp.arpa:0; SOCKS dialer отвергает порт0.
Изолированный namespace naive, непривилегированные сервисы, DNS только через WG,
запрет fallback и IPv6 пользовательского выхода; host default route/SSH отдельно.
Исторический fixed TCP relay/systemd sockets и veth описаны в [runbook](NETWORK_RUNBOOK.md);
фактические адреса/units новой пары сверять перед операциями, а не копировать старые.

Текущая принятая пара: hh-entry85.155.185.169 / hh-exit85.155.184.194.
В rc10 Caddy/sing-box/API/frontend/worker timer активны; SSH publickey-only.
Приватные listeners/TLS и admin access подтверждены в [rc10](../controlpanel/RELEASE_RC10_2026-11-22.md).
Веб-сайт старой KVMka-схемы не является компонентом, опубликованным текущим fresh.

## Control plane и владение записью

Общий installer/SSH-master готовит и проверяет VPN, затем передаёт владение панели.
Общий lock, manifest/panel_generation и журнал не допускают конкурирующих writer.
CLI vpnctl, API и frontend используют общий реестр/операции; worker применяет изменения
Caddy и проверяет результат. Обычный installer writer guard сохраняется после handoff;
rc10 разрешает только ограниченную проверенную SSH-транзакцию, не обход всех guards.
Q27 preflight обеих нод → exit apply → entry apply → новые SSH → commits → новые SSH.
Q28/ProxyJump отдельны и пока не приняты в этой топологии.

## Данные и безопасность

Go-модуль: installer/controlpanel, команды cmd/vpn-control и cmd/vpnctl;
пакеты internal/storage, auth, vault, caddy, status. SQLite/WAL/foreign keys,
миграции и проверки версии/хешей; схема принятого rc10 — 9.
Реквизиты шифруются AES-256-GCM; vault key вне SQLite/репозитория.
Идемпотентные операции и CAS привязаны к точным пользователю/версии/intent/generation.
Lifecycle provisioning→active↔disabled→deleting→deleted; неопределённость — reconcile_required.
master_user защищён; exact-case login/credential/status сохраняются при импорте и восстановлении.
Профиль выдаётся активному пользователю по approved revision, выдача аудируется;
скачивание не доказывает импорт/подключение. Revoke новых соединений не гарантирует
разрыв уже существующего туннеля. Файлы экспорта с секретами — вне Git.

## Контракты и подробности по необходимости

- [W5 contracts](../controlpanel/W5_CONTRACTS.md), [renderer policy](../controlpanel/PROFILE_ROUTING_POLICY.md).
- [Storage/CLI детализация](../controlpanel/README.md): содержит ранние version/stage описания; их не считать текущим статусом релиза.
- [Worker](../controlpanel/WORKER.md), [U acceptance](../controlpanel/U_ACCEPTANCE_2026-11-16.md).
- [U/E strategy](../controlpanel/UE_STRATEGY.md) и [W8 ledger](../controlpanel/W8_UE_EVIDENCE.md): helpers/targeted PASS не доказывают полноценный DR/portable workflow.
- [Исторический сетевой контекст](archive/2026-11-22/logs_project_context.md), [контролируемые тесты 10 ноября](CONTROLLED_TESTS_2026-11-10.md).

Неизвестное live-состояние, полная DR, macOS/Android матрицы и новые security changes
не выводятся из этого обзора. Подробные спецификации изменения хранятся отдельно в plans/.

## Публикация статического сайта (S1)

Q25 использует существующую SCP/SSH-доставку и controller publish-site, включая режим панели. ZIP/TAR проверяются без extractall: запрет опасных путей, ссылок, special/sparse, дубликатов и недопустимых типов; лимиты 200 MiB архива, 400 MiB содержимого, 4096 записей. Staging в site-releases и атомарный symlink site-current; существующая обычная папка не мигрируется. Приватный случайный путь панели не меняется. Серверная приёмка S1 не выполнена.
