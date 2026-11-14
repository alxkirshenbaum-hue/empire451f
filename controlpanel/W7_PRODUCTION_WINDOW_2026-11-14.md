# W7 — согласованное production-окно 14.11.2026

**Подключение выполнено. W7 3/4; G7 открыт до телефонной приёмки.
W6 3/4; G6 открыт. Полный E1 не выпущен.**

Владелец явно разрешил описанное обновление control plane сообщением
«действуй». Scope: API/worker/private frontend, необходимые проверки/снимки/
откат. Production user CRUD, смена паролей, transport restart, WG/firewall/
маршруты/reboot не выполнялись.

## Что работает теперь

- hh-entry85.155.185.169, выход85.155.184.194; резерв не затронут.
- /usr/local/bin/vpn-control и vpnctl — проверенные бинарники cd3de10.
  Пакет ad6b653, manifestSHA256:
  e512a536a57256dbaff7025991621551cda11687b14423ebb9ce5abb281b6ba0.
- Helpers: /opt/empire-vpn/controlpanel/ad6b6532ae75ec0720f692314f626e97524cc44d.
  Worker policy переключает только прежний directory prefix. Validator,
  namespace, UID/capability drop и admin socket сохранены.
- Прежний worker unit6621689 с default root identity сохранён;
  explicit User=root не добавлен. Таймер включён/активен, idle run success0.
- Новый vpn-control-panel.service включён/активен, UID/GID981, CapEff0,
  Seccomp2, namespace naive, TLS loopback127.0.0.1:18650.
- API активен; socket /run/vpn-control-api/api.sock0600 UID981,
  parent0700. Owner-run API drop-in установлен после read-only проверки.
- Registry schema_migrations max(version)=7, integrity_check=ok.
  PRAGMA user_version=0 не используется этим репозиторием как номер схемы.
- Действующие owner/password/vault key,4 active users и panel_generation2
  сохранены. Старые profiles/auth/manifest/transport files, их owners/modes/
  xattrs совпали между pre/post inventory.
- Owner login: owner, прежний пароль. Сертификат/CA сохранены побайтно;
  leaf действует до25.11.2026 11:19:54UTC.

## Порядок и фактическая недоступность

Новые Windows SSH entry/exit и независимая резервная SSH-сессия проверены.
Сняты свежие root-only core/control pre-снимки: SQLite, vault, private TLS,
старые binaries/policy/units/credential sources и transient unit. Через прежний
Windows owner recipient оба зашифрованы, расшифрованы и SHA256 сверены.
Ключи владельца не пересоздавались.

Worker timer приостановлен, oneshot дренирован, незавершённых операций0.
API и старая readonly-страница остановлены. По systemd:
14.11.2026 **10:34:48–10:37:20 МСК**, около2мин32с до старта нового frontend.
Готовность затем подтверждена HTTPS-проверками. При включении owner-run
API дополнительно перезапущен в10:44:42МСК.

Во время копирования installer встретил __pycache__, созданный проверочным
import без -B в исходном каталоге пакета. Остановка произошла до замены
бинарников. Чистый пакет пересобран в НОВОМ каталоге с ТЕМ ЖЕ manifest hash;
helper install ограничен manifest-listed файлами. При возобновлении учтено
исчезновение уже остановленного transient unit. Окно продолжено штатно.
Все дальнейшие imports запускались с -B. Оригинальный contaminated package
не считать готовым; использован upgrade-bundle-clean.

Registry init переиспользовал старый approved source и vault, применил schema7
и immutable policy2 варианты. Старые IDs/credentials/source bindings не
заменялись; импорт/MIG-05/owner bootstrap не повторялись.
Новая панель сперва проверена read only, затем включены owner capabilities и
существующий worker timer. Агент не выполнял create/disable/enable/rotate/delete.

Свежий post core snapshot также зашифрован/decrypt/hash-verified на Windows.
Guard20min защищал ТОЛЬКО control plane; после проверок штатно отменён.
Окно отмечено complete. Откат production не выполнялся.

## Проверки PASS

- Новый frontend: trusted existing owner CA/exact SNI, login page200,
  no-store/same-origin, signed-in owner/read API routes200.
  no-store может приходить дважды от API/proxy; проверка учитывает список
  заголовка, продуктовый код ради этого не менялся.
- Прежний owner password принят. Temporary verification sessions отозваны;
  сессии пользователя не затронуты.
- Без admin-session users401, admin/config route404, внешний Origin403.
  Действительные VPN credentials существующего canary не дают admin-login401.
- Из РЕАЛЬНОГО mount namespace frontend под UID981/cap0:
  vault/user files/proc-root/Caddy admin denied, только private API connect PASS.
  Namespace handle сравнивался по inode, не как symlink.
- Внешние probes с выхода: public18650 закрыт, forged Host на public443
  возвращает сайт200/route404, не панель; exact panel SNI с доверием owner CA
  на public443 отклонён. TLS verification не отключалась.
- Существующий G3-Canary до/после: fresh TCP/UoT/TLS/site/control PASS.
  Пароль не менялся; canary не создавался повторно.
- Data-plane Caddy и relay MainPID/NRestarts совпали с baseline, auth/config/
  vault/поколение неизменны. Не было load/restart transport или сетевых правок.
- Новый SSH entry/exit после switch PASS.
-4 active users, integrityok, unfinished0; user/credential/current-reference/
  owner fingerprints неизменны, в том числе после новой профильной выдачи.

## Снимки и восстановление

Закрытый указатель: /root/vpn-control-w7/current.json.
Он указывает на конкретный private window directory с window.json,
сохранёнными файлами/control archive и state-before-switch.db.
Pre-switch DB schema4/integrityok подтверждены; файл не перезаписывается
при возобновлении. Core pre/post receipts — в новом root-only G3 window.
На Windows encrypted/decrypt/hash-verified copies находятся в существующем
закрытом owner-каталоге вне Git. Private архивы/credentials не в отчёте.

Window executor и readonly replay сохранены рядом со снимками root-only,
а не только в build cache. В обычном complete состоянии guard rollback idle.
Явный recover требует SSH/решения администратора и конкретного WINDOW_UUID.
После пользовательских изменений default — сохранить CURRENT state/backend,
выключить новые owner mutations и вернуть readonly frontend.
Полный old-code/DB rollback требует равенства baseline; при неопределённости
не восстанавливать старый auth. Full legacy/runtime return при изменении
transport требует отдельного scope, не входит в это UI-окно.

## Что осталось

Для OnePlus12 выданы три НОВЫХ файла существующего G3-Canary, с одним и тем
же прежним credential: base1144/basealpha13/optionalalpha13.
Они прошли exact engine checker3/3, сохранены root0700/0600 и переданы в
существующий Windows owner-каталог с ACL только user+SYSTEM.
Старые файлы не заменялись, содержимое профилей не выводилось.
Это разрешённая защищённая выдача, не смена реквизитов.
Issuance audit/last_issued_at обновились ожидаемо; credential fingerprints те же.

Результаты телефона ещё НЕ получены: импорт/3–5мин стабильности/панель TLS/
owner login, Wi-Fi/mobile, обе версии; optional RU/domain/IP и реальные DM
(OpenAI черезVPN, другойDM direct) только точная1.15.0-alpha.13.
Доступность обеих сборок и вопрос владельца о логине не являются PASS.
Следующий шаг — фактические наблюдения владельца. G6/G7 не закрывать.
