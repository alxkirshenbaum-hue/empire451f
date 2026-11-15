# SOL Lead / Subagents · U/E backlog

**Последнее решение владельца15.11.2026:** [W9.5U-Fresh — установить VPN+панель одной командой](PRIORITY_FRESH_INSTALL.md), 0/4, выполнять сразу. Portable export/import и его тестовые расширения отложены; предыдущие зависимости от W8U/G9 ниже отменены для fresh-install. Будущий минимальный перенос допускает plaintext JSON с паролями; сейчас на него время не тратить. Сохранять существующие PASS и WIP.

15.11.2026. [Стратегия и parent-gates](UE_STRATEGY.md). Все нижеследующие U-критерии INCOMPLETE до демонстрации; готовые части переиспользуются из ledger. Оценки — количество ограниченных рабочих пакетов, без обещаний часов. Схема/контракты/применение принадлежат Lead. Coder получает отдельные файлы и критерии; независимый reviewer проверяет security-critical изменения. Production исключён из текущего задания.

| Этап / source | Именованные U-критерии | Зависимость / владелец / остаток |
|---|---|---|
| W8U · BKP01/04–06,USR,CRED,PROF,MIG | 01 скачать переносимый encrypted bundle incl master/login/status/template; 02 verify/wrong key/corrupt отказ; 03 preview+import clean без silent overwrite; 04 old TCP/UoT PASS,disabled FAIL,ошибка безопасна | W3–7 core; Lead, coder только UX/тест с контрактом Lead; 2 пакета связка+E2E. 0/4 U_PASS;01/02/04 имеют partial evidence |
| W9U · §12–13 | 01 phone owner/TLS/nonadmin/external;02 CRUD/profile/контрольный пользователь;03 export/import+честный health;04 restart/data-plane+откат;05 pinned targeted regression+инструкция | W8U, критические остатки G6/G7; Lead; 2 пакета сверка+приёмка;0/5 |
| W9.5U · legacy W9.1 | 01 пакет и опубликованные команды;02 clean pair+панель;03 upgrade/migrate;04 повтор/critical failure+replace ingress сохраняет panel/users;05 E2E fresh/upgrade/import/startup/private access | W9U,W8U; Lead installer, coder упаковка/инструкции;3 пакета;0/5 |
| W10U · MET01–05,SYS,AUD | 01 live egress TCP/UDP/IP и службы;02 last local audit exit отдельно/stale;03 ingress metrics/backup timestamps по источникам;04 PASS и FAIL/stale в UI/CLI | W9.5U; Lead источники,coder UI;2 пакета;0/4 |
| W11U · ALT01–05 | 01 выбранный канал+test;02 sustained fail/recovery;03 cooldown/dedup+token safety;04 без канала локальное событие | W10U, выбор канала; Lead,coder канал;2 пакета;0/4 |
| W12U · PROF,TPL,§7/10 | 01 каталог approved;02 выбор+персональная выдача;03 старые профили сохранены;04 unsupported version отказ+импорт клиента | W9U, текущий renderer; coder/Lead;1–2 пакета;0/4 |
| W13U · DEP01–08,NMG01–04 | 01 allowlisted режим preview;02 approval+execute staging;03 status/error/recovery;04 command injection denied/ресурсы | W9.5U; Lead и review;2 пакета;0/4 |
| W14U · ROUTE01/02,E3-SC-01 | 01 точный план exit diff;02 swap+старые login/TCP-UoT;03 новая SSH до удаления доступа;04 критический failure→защищённый исход | W13U/existing CLI; Lead и review;2 пакета;0/4 |
| W15U · §11.1/2/5 | Выбрать одну историю и 2–5 критериев до реализации | U_DEFERRED_BY_OWNER. Варианты: второй ingress; замена exit; второй admin. Риск и зависимости оценить после выбора |

## Ограниченные E-пакеты

| Пакет | Критерии завершения / source | Статус |
|---|---|---|
| W8E01–08 | См. ledger: full restore;rotation;ACL/wrapper;restore-plan;prune;SEC;resources;canonical snapshot | 3/8 E_PASS_REUSED, остальные по ledger |
| W9E01–04 | Полная матрица кандидата;capacity/load/24h;расширенные rollout/reboot;полный runbook/report по G9 | E_NOT_RUN, исторические точечные PASS применять по фактической области |
| W9.5E01–05 | OS/package matrix;повторные fresh;legacy/downgrade;расширенные failure/topology;реальный macOS+полная матрица | E_NOT_RUN, legacy W9.1 трассируется в стратегии |
| W10E01–03 | MET02 bytes с доказанной user attribution;MET03 auth/history;MET04/05 trends/retention | E_NOT_RUN |
| W11E01–03 | ALT rules/history/multichannel;quiet hours/escalation;DIA01–03 ограниченные jobs | E_NOT_RUN |
| W12E01–03 | TPL04–06 editor/revision/promotion;BULK01/02;SUB01–03 opt-in/model threats | E_NOT_RUN |
| W13E01–03 | DEP full journal/approvals;resume/events;multi-hosters/resources/rollback matrix | E_NOT_RUN |
| W14E01–02 | hoster/IP/SSH/WG matrix;advanced topology/downtime optimization | E_NOT_RUN |
| W15E | ROUTE03/04,RBAC01–04,AUTO01/02,node_groups/assignments; определить ограниченные критерии только для выбранных функций | E_DEFERRED_BY_OWNER |

## Связь с пользовательским BACKLOG

BL001 дизайн → W9E UX либо отдельная согласованная задача.
BL002 Overview → W10U; BL003 multi-nodes → выбор W15; BL004 Infrastructure → W13U/14U, расширение W15.
BL005 активность → W10E02 с доказанным источником; BL006 mobile Open и BL007 имя профиля → W9U02 при проверке UX, без новой большой переработки.
BL008 network owner/manager → W15 design, текущий auth denial обязателен W9U01.
BL009 Download Manager остаётся отложенным владельцем; версии/ограничения показывать в W12U, исправление не объявлять выполненным.

Перед пакетом Lead фиксирует цель, файлы, критерии и reuse evidence. После1–2 непродуктивных итераций — конкретный блокер и безопасный вариант, без расширения scope. Роли/пороги эскалации AGENTS сохраняются. Отчёт: U-пункты, E-пункты, блокер, ближайший пользовательский результат.

