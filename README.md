**Текущая приёмка OPEN:** rc8 не включает резервный CA без contact email в Caddy2.11.9. Текущий домен упёрся в LE429; обе ноды откатились, VPN/панель пока недоступны, SSH сохранён. Optional email кандидат локально проверен, но ещё не опубликован; ждём адрес владельца или снятие лимита.

**rc8:** штатный публичный CA fallback Caddy сохранён: Let's Encrypt → ZeroSSL. Исключены private CA и обход TLS. rc7 чистый прогон остановился до панели из-за внешнего LE429 (5 сертификатов/168 часов), затем штатно откатился; код master/schema9 не менялся.

# VPN + VPN Control — v0.4.0-rc8

Одна защищённая учётная запись **master_user** для VPN и панели, один пароль. Если она есть в JSON-экспорте, реквизиты сохраняются; иначе установщик создаёт её. Отдельный скрытый owner не создаётся. Обычные VPN-пользователи видны в Users и не могут войти в панель; master отмечен Protected / Panel owner. Импортированный VPN-пользователь с именем owner остаётся обычным пользователем.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.4.0-rc8/bootstrap/windows.ps1')"
```

1. До очистки сохраните проверенный актуальный JSON вне Git: `empire-vpn-clients`, schema_version1, username/password включая master_user. JSON v1 импортирует включённые записи активными; не включайте отозванные записи. Не отключайте SSH host-key checking.
2. Две подготовленные Ubuntu24.04/26.04 amd64 VDS, root SSH-ключ, домен на вход. Мастер: new → fresh, прежние домен/адреса для сохранения VPN-реквизитов, Q16 ready. Q13 — локальный JSON (имя произвольное).
3. После VPN commit master_user автоматически становится владельцем панели. Отдельных P01–P03 нет. Мастер печатает логин/пароль, готовую HTTPS-ссылку и команду скачивания JSON.
4. Q24.1: **1 Download JSON now** (по умолчанию), **2 Later**. Для1 подтвердите предложенный приватный новый путь или укажите свой. Для2 сохраните напечатанную команду: она работает после завершения установщика. Ошибка SCP не повторяет установку и не меняет реквизиты.
5. Импортируйте JSON в SFA, подключите VPN, откройте выданную ссылку `https://<VPN-domain>/<случайный-путь>/`, войдите как master_user с тем же VPN-паролем. Создайте пользователя, скачайте профиль под выбранную версию. Исправлена404 для импортированных пользователей, включая1.15.0-alpha.13+RU/DM.

**Не передавайте master JSON:** он содержит пароль владельца панели. Раздавайте отдельные профили обычных пользователей. Независимая смена только панельного пароля отключена; общая смена master-пароля пока вне этого выпуска. Protected master нельзя отключить/удалить обычной операцией.

Панель доступна через VPN и использует основной автоматически продлеваемый публичный сертификат (Caddy: Let's Encrypt / ZeroSSL). Отдельный поддомен/CA/ручная установка сертификата не нужны. Публикация сайта после fresh пока отложена; через VPN основной домен вне пути панели возвращает404. Случайный путь не заменяет аутентификацию.

Только fresh, не in-place upgrade/portable. Существующие registry/key/units требуют отдельного плана; при частичном отказе сохраните сообщения/journal и не сбрасывайте ключи. Runtime core d94a4e7121c41bb9157e7c14d457365c7abd99d6/schema9 исключает portable/prune WIP. [Спецификация](https://github.com/alxkirshenbaum-hue/empire451f/blob/feature/controlpanel-pilot/controlpanel/MASTER_USER_OWNER_SPEC.md), [приёмка и ограничения](https://github.com/alxkirshenbaum-hue/empire451f/blob/feature/controlpanel-pilot/controlpanel/RELEASE_RC7_2026-11-17.md). Новые E/DR/reboot gates не заявляются.

macOS: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/alxkirshenbaum-hue/empire451f/v0.4.0-rc8/bootstrap/macos.sh)"`. Syntax проверен; реальная macOS-проверка не выполнена.

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
