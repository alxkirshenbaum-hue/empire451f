**17.11.2026: реальная техническая приёмка fresh rc4 прошла на hh-entry/hh-exit.** Опубликованная команда → VPN+панель → owner login → create → download → TCP/UoT PASS. [Доказательства и границы](https://github.com/alxkirshenbaum-hue/empire451f/blob/feature/controlpanel-pilot/controlpanel/REAL_F3_2026-11-17.md). Прежние пометки F3 OPEN ниже описывают состояние до приёмки.

## Fresh VPN + VPN Control: v0.4.0-rc4

rc4 исправляет fresh writer cutover/откат с Unix admin socket и согласует окружение validator/готовность служб. Публикуется по просьбе владельца для ручной приёмки; полный сквозной fresh PASS пока не получен.

Для новой чистой установки **VPN вместе с панелью** используйте этот
предварительный выпуск для ручной приёмки. Старый стабильный VPN-only v0.3.6 сохранён ниже.
Windows PowerShell5.1/7, одна команда:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.4.0-rc4/bootstrap/windows.ps1')"
```

[Полная инструкция rc2: подготовка, JSON-импорт и первый вход](https://github.com/alxkirshenbaum-hue/empire451f/blob/v0.4.0-rc4/README.md).
[Проверки пакета и ограничения](https://github.com/alxkirshenbaum-hue/empire451f/blob/v0.4.0-rc4/controlpanel/RELEASE_RC4_2026-11-16.md).
Общий мастер устанавливает VPN, затем приватную панель. В Q13 выберите локальный
JSONv1 с нужными активными пользователями: регистр логинов и пароли, включая
master_user, сохраняются. JSONv1 не переносит disabled-статусы. В P01–P03 задайте
отдельного владельца панели и сохраните/проверьте публичный CA для первого входа.
Включены управление пользователями/профили, смена owner-пароля и показатели
ресурсов с источником/временем/обновлением. Это fresh, не обновление действующей пары.

**F3 — реальная установка на двух очищенных VDS — пока OPEN:** её выполняет
владелец. До очистки обязательно перепроверьте актуальность сохранённого экспорта.
Не запускайте fresh на действующих нодах для обновления панели.

---

# Персональная VPN — v0.3.6

**Установщик работает на VPS; диалог — в вашем терминале через SSH.** На компьютер не скачиваются комплект, шаблоны или сборки; локальный Python и Git не нужны. Короткий запускающий текст выполняется в памяти штатной оболочки. Обе VPS сами получают закреплённый комплект из Git, проверяют SHA256 и устанавливают компоненты из официальных источников.

Нужны две VDS **Ubuntu 24.04/26.04 amd64**, первоначальный root-доступ/консоли провайдера и домен. Поддерживаются новая пара, замена входа и замена выхода. Архив старого сервера не требуется. Приватные SSH-ключи остаются на компьютере; ssh-agent на VPS не перенаправляется.

Откройте обычный PowerShell под своей учётной записью. Windows отдельно запросит повышение прав при установке OpenSSH Client или запуске системной службы ssh-agent.

**Windows10/11**, Windows PowerShell5.1 или PowerShell7 — одна команда:

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.6/bootstrap/windows.ps1').Content))
```

**macOS11+**, Terminal с zsh или bash — одна команда, без PowerShell:

```sh
/bin/bash -c 'set -e; code=$(curl -fsSL --proto "=https" https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.6/bootstrap/macos.sh); /bin/bash -c "$code"'
```

### Повторный запуск сразу в меню Q00

Если обе VDS уже настроены, используйте те же SSH-алиасы и ID установки. В примерах это `hh-entry`, `hh-exit` и `nh1`. Команда использует ключи и ProxyJump из пользовательского SSH-конфига. Для защищённого ключа предварительно разблокируйте его в ssh-agent. Мастер проверяет доступ и сохранённые роли обеих нод, затем открывает меню. Экспорт клиентов повторно не нужен.

**Windows PowerShell**

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.6/bootstrap/windows.ps1').Content)) -EntryAlias hh-entry -ExitAlias hh-exit -DeploymentId nh1
```

**macOS, zsh или bash**

```sh
/bin/bash -c 'set -e; code=$(curl -fsSL --proto "=https" https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.6/bootstrap/macos.sh); /bin/bash -c "$code" -- --resume "$@"' -- hh-entry hh-exit nh1
```

**[Пройти установку шаг за шагом](GUIDE.md)** — от первого подключения до проверки VPN на телефоне. Для реальной замены входа выберите Q00 → 2 и Q01 → 2. Для просмотра плана выберите Q00 → 1. Чтобы сменить домен действующей установки, выберите Q00 → 3. [Переход с тестового домена на рабочий](GUIDE.md#как-сменить-тестовый-домен-на-рабочий).

После успешного входа по IP мастер предложит сохранить короткое SSH-имя на этом компьютере (Q23). Например, имя `nnh1` позволит подключаться командой `ssh nnh1`. Enter пропускает этот шаг.

Сначала укажите SSH входа/выхода и выберите/создайте ключ. Windows при необходимости предложит системный OpenSSH Client. Затем серверный мастер в том же окне спросит режим, адреса и домен, покажет конкретные изменения и запросит `APPLY`. Непонятный вопрос найдите по **Qxx** в [подробной инструкции](GUIDE.md).

Повторные проверки и откат запускаются **той же командой**: в серверном меню Q00 выберите `apply-saved`, `preview`, `verify`, `rollback`, `acceptance` или `reboot-test` и прежний ID. Редактировать конфигурационные файлы вручную не требуется. DNS установщик не переключает.

- [Защита SSH после установки — Q26–Q28 или пункт 8](GUIDE.md#защита-ssh-после-установки)
- [Аудит безопасности после установки — команда PowerShell](GUIDE.md#аудит-безопасности-после-установки)
- [Вопросы, подготовка доступа и восстановление](GUIDE.md)
- [Формат импорта/экспорта учётных данных](CLIENT_EXPORT_V1.md)
- [Первая приёмка: новый вход HostHatch](MIGRATION_TEST.md)
- [Фактически выполненные проверки и ограничения](TEST_RESULTS.md)

**Статус: кандидат для испытания на новой VDS.** Локальные проверки не заменяют первую установку с Windows. Настоящий macOS и Linux/systemd/netns пока не испытаны. Рабочие серверы и DNS при разработке не менялись.

После успешной установки мастер выводит пароль VPN-пользователя `master_user`. Q24 сохраняет JSON для импорта в [sing-box for Android](https://sing-box.sagernet.org/clients/android/). Q25 предлагает опубликовать готовый ZIP со статическим сайтом. [Скачать ZIP-заготовку с заданием для агента](https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.3.6/dist/site-handoff-example.zip). Передайте агенту ZIP и тему, затем выберите возвращённый им архив в Q25.

- [Выдать пользователю профиль VPN по SSH](GUIDE.md#выдача-профиля-по-ssh)
