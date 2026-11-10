# Персональная VPN: установщик v0.1.1

Две Ubuntu 24.04 amd64 VDS: **Naive/HTTPS Caddy → HTTP CONNECT/UoT sing-box → WireGuard → Интернет**. Поддерживаются новая установка, замена входа и замена выхода. Код готовится к первой практической приёмке; результаты — в [TEST_RESULTS.md](TEST_RESULTS.md).

Нужны адреса VDS, первоначальный root-доступ из панели провайдера и домен. Откройте аварийные консоли обеих VDS. Архив старого сервера не требуется. Для переноса действующего входа сначала используйте отдельный тестовый домен.

**Windows 10/11 x64**, терминал **Windows PowerShell 5.1 или PowerShell 7** — одна команда:

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.1.1/bootstrap/windows.ps1').Content))
```

**macOS 11+ Intel/Apple Silicon**, Terminal с **zsh или bash** — одна команда; PowerShell не нужен:

```sh
/bin/bash -c 'set -e; f=$(mktemp); trap '\''rm -f "$f"'\'' EXIT; curl -fsSL --proto "=https" https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.1.1/bootstrap/macos.sh -o "$f"; /bin/bash "$f"'
```

Загрузчик получает небольшой комплект **исходников установщика v0.1.1**, сверяет закреплённый SHA256 и запускает мастер. Go, Caddy, sing-box и пакеты Ubuntu скачиваются **на VPS**, не через компьютер пользователя. При отсутствии локального Python3.12+ предлагается официальный установщик; Windows также помогает установить OpenSSH Client. Ручное клонирование, скачивание модулей и редактирование конфигураций не нужны. Первое скачивание доверяет HTTPS GitHub; хеш комплекта закреплён в загрузчике. Не используйте команду с `main` вместо версии.

Следуйте вопросам **Q01–Q22**. До `APPLY` показываются адреса и изменения. Пароли вводятся скрыто, приватный SSH-ключ остаётся на компьютере. Установщик не переключает DNS. Неизвестные настройки и незавершённая транзакция останавливают применение.

- [Подробная инструкция и все вопросы](GUIDE.md)
- [Формат переноса клиентских учётных данных](CLIENT_EXPORT_V1.md)
- [План первой приёмки: новый вход HostHatch](MIGRATION_TEST.md)
- [Что действительно проверено](TEST_RESULTS.md)

Повторный запуск установленного комплекта: Windows `powershell -NoProfile -ExecutionPolicy Bypass -File "ПУТЬ\Install-Vpn.ps1"`; macOS `/bin/bash "ПУТЬ/Install-Vpn.sh"`. Путь показывает загрузчик. Для сохранённых параметров Windows добавьте `-Action preview -Config "$HOME\.config\empire-vpn\ID\deployment.json"`; macOS — `preview --config "$HOME/.config/empire-vpn/ID/deployment.json"`. Аналогично доступны `apply`, `verify`, `rollback`, `acceptance`, `reboot-test`. Последние два действия отдельно спрашивают разрешение на отказ WG и reboot.

**Статус:** локальная разработка не означает успешную установку на чистую VDS. Полная приёмка нового входа с Windows, Linux-системные проверки и запуск на настоящем macOS отмечаются отдельно. Рабочие серверы и DNS в этой итерации не менялись.
