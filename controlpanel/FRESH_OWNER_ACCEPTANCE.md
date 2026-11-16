# Ручная проверка fresh VPN + panel v0.4.0-rc1

## Current owner acceptance candidate: rc4

Use rc4 README command after BOTH OS reinstall tasks are completed. rc4 fixes
fresh cutover/restore admin socket and validator/readiness contracts. Local gate
is PARTIAL; owner explicitly requested publication for manual full fresh test.
[Evidence and limits](RELEASE_RC4_2026-11-16.md). F3 remains OPEN. Agent does not
wipe nodes or change services. Earlier rc3/rc2 candidate notes below are historical.


## Current candidate: rc3 after actual rc2 F3 failure

rc2 failed at panel registry init because installer created lock0644. rc3 fixes
that bug and names failed panel stages. rc3 is published: artifacta35f31d, main READMEbfbbeca; public fullZIP/hash and
actual command PS5.1/7 startup verified. Use the rc3 README command for the next
fresh run. Actual F3 remains OPEN for owner; agent does not
wipe/reinstall nodes. Checklist and rc2/rc1 receipts below are historical. No
manual server permission repair is required. Existing Q13/owner/CA steps apply.


rc2 publication PASS: artifactc5f74fc, public bootstrap/fullZIP/hash verified; actual command startup PS5.1/7 PASS before any SSH target. Main README now offers rc2. F3 OPEN, no agent node cleanup.

## Current release: v0.4.0-rc2

Use the rc2 command in [README](../README.md); runtime8d9b87c/schema8.
[Verified package and user values](RELEASE_RC2_2026-11-16.md).
The owner previously confirmed a checked current JSON including master_user.
Recheck freshness before wiping; agent cleanup/reinstall is not authorized.
Run the checklist below with **rc2**. F3 remains OPEN until the owner's real
installation and VPN/panel test. rc1 publication evidence below is historical.
After step7 also check System resources/refresh, owner identity, and (optionally)
owner password change followed by re-login. VPN passwords must stay unchanged.

## Retained rc1 checklist and evidence (apply the steps to rc2)

F3 остаётся открытой до проверки владельцем. Агент не очищает, не переустанавливает и не меняет текущие ноды. Отдельная новая пара/дополнительный стенд не требуются.

## Перед очисткой — обязательно

Владелец подтвердил 15.11.2026: актуальный проверенный JSON-экспорт, включая master_user, уже есть. Это подтверждение не является разрешением агенту очищать ноды. Перед фактической операцией повторно убедитесь, что файл не устарел после последующих изменений, есть защищённая резервная копия и сохранены прежние профили. При будущей просьбе к агенту о разрушительной операции он сначала уточняет наличие актуального проверенного экспорта.

## Проход

1. Владелец самостоятельно очищает/переустанавливает обе ноды; сверяет новые SSH host fingerprints с provider console. Старые domain/endpoint/порт сохраняются для старых профилей, DNS готов.
2. Из Windows PowerShell запускает единую команду README (GitHub tagv0.4.0-rc1, без BundlePath). Ожидается общий мастер, подтверждённый SSH обоих узлов и загрузка одного SHA-проверенного пакета.
3. new→fresh; Q13: локальный путь empire-vpn-clients-v1.json (имя условное). Ожидается использование импортированных логинов/паролей без генерации замены master_user. Форматv1 хранит толькоusername/password, все включённые пользователиactive; отключённые не должны попасть изстаройкопии.
4. Проверяет план обоих адресов, подтверждает APPLY. Ожидается VPNcommit послеfreshSSH иHTTPS/TCP/UoTпроверок, затем panelinit черезтотжеclientsреестр иexistingMIG05.
5. P01–P03: задаёт отдельные ownerlogin/passwordпанели. СохраняетVPNprofile иpublicPanelCA, сверяетfingerprintпоSSH, явно доверяетCAнаклиенте. Не отключатьTLSverification.
6. Подключается ПРЕЖНИМ профилем: обычныеTCP/UoT работают. Открываетhttps://panel.home.arpa, ownerloginуспешен. Безownerавторизации управлятьнельзя; публичногоadminsocket/порта18650нет.
7. Видитимпортированныхпользователей/master_user, создаётновогопользователя, дожидаетсяуспеха, скачиваетпрофиль, проверяетfreshTCP/UoT. Повторно проверяетстарыйпрофиль иSSH.
8. Передаёт итогF3 (PASS/шаготказа) безпаролей/privatekeys/cookies. ПриошибкепанелиcommittedVPNнеоткатываетсяавтоматически: сохранитьсообщения/journal; неперечищатьнодыповторно инеперегенерироватьключи дляобходаошибки.

Локально8a164c9 TestFreshInstallerJSONPreservesImportedMasterPASS1.006s: реальныйexistingcontrollerJSON→render→inspect/plan→StageLegacy→copyhandoff→MIG05storage, точныеAlice/masterпароли/роль, admin/key/sourceJSONсохранены. LiveCaddycallbackсмоделирован; это НЕ F3.63release regressionPASS/4platformskip, ZIPHTTPSloader/hash/PS/CAmocksPASS. НастоящийmacOSнепроверен. Corepanel0c05a61; portableнеиспользуется. Leafpanel365дней, autoprenewalнет; websitepublishпослеpanelотложен.

Пакетdist/installer.zip SHA256 f5e8b7344945e067e1a85635a7a5c07a98e58e530b7096701a4f6f0ce85a1e6b;22,761,364bytes. Sourceb86591d. Release-tagv0.4.0-rc1 публикуетпроверенныйпакет+bootstrap; coreбинарников0c05a61. НикакихоперацийнаVPSприэтихлокальныхпроверкахнебыло.

## Publication verified

GitHub tag `v0.4.0-rc1` points to commit `713a2ebaee5eb89f7cd1208685fc026d56ddcd2d`. Public Windows bootstrap and the full ZIP were downloaded over HTTPS after publication and matched the local checked files. ZIP SHA256: `f5e8b7344945e067e1a85635a7a5c07a98e58e530b7096701a4f6f0ce85a1e6b`.

Owner confirmed that a current verified export including `master_user` is available. No cleanup/reinstallation by the agent is authorized. F3 stays open for the owner's manual installation and connection check; no new server pair is requested.
