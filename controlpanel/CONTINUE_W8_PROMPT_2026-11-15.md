Продолжи VPN Control в C:\AllFiles\SoftWare\VPN\Amnezia\CodexVPN\installer с сохранённой точки W8. Это разрешение возобновить разработку на локальной копии до завершения W8; production не менять без отдельного согласования.

Сначала прочитай C:\Users\a.filatov\.codex\AGENTS.md, ..\AGENTS.md и:
- controlpanel/HANDOFF_W8_2026-11-15.md — актуальная передача, ревизии, результаты и точная очередь;
- controlpanel/PLAN.md, PROGRESS.md, PARALLEL_STATUS.md, TEST_STATUS_2026-11-14.md — последние записи;
- controlpanel/W8_INTEGRATION_CONTRACT.md и относящиеся к W8 контракты обязательного ..\controlpanel\VPN_Control_LLD_Spec_Agent_v1.1.md; Architecture/Roadmap также вне Git.

Проверь git status/log/worktrees. Основная ветка feature/controlpanel-pilot: последняя функциональная интеграция fc2ec74, затем bf6f693 — непроверенный WIP vault rotation, затем документационная передача. Push не выполнялся. Чужой untracked controlpanel/BACKLOG.md не читать/не добавлять/не менять.

Остановка была явной; сохранение точки затем прервалось из-за лимита automatic approval review. 15.11 WIP сохранены. Незавершённой неразрешимой ошибки после четырёх попыток нет. Не считать частичные функции или стартовавший тест доказательством приёмки.

Первое полезное действие: проверить оставшиеся собственные w8-* jobs в WSL чтением, затем review/integrate только два тестовых файла из коммита c99e9b0 ветки work/w8-maint-storage (worktree ..\worktrees\w8-maint-storage). Они написаны, итоговый PASS не получен. Не cherry-pick merge c9ae04f. Выполни целевые реальные owner API/worker crypto проверки на новом pinned source в VPNControl-Lab. WIP bf6f693 также ещё не скомпилирован/не протестирован.

SOL-A worktree ..\worktrees\w8-stream чистый, HEAD d0685cf: архив и offline verifier уже интегрированы, не дублировать. Следующий назначенный пакет — поддерживаемые ACL/xattrs и actual roundtrip, код ещё не написан. Можно параллельно отдать этот независимый пакет lead_coder, пока Lead/SOL-B проверяют API/worker, с непересекающимися файлами. Используй роли explorer/coder/lead_coder/architect по AGENTS; две полезные параллельные задачи, без nested agents. Не создавай агентов лишь для проверки доступности ролей. ASTRA автоматически для consequential security/rollback; уже был один плановый case W8-SEC-001, отладочных эскалаций0/неудачных исправлений0. Отчёт по каждому агенту: пакет, выполненные шаги, статус; после четырёх неудачных исправлений одной ошибки остановиться.

Далее по HANDOFF: ACL/xattrs; readonly restore-plan/offline verification CLI/report; reviewed restore preparation только НОВОЙ копии; finish/test copy-only vault rotation и version handling; фактический CAS prune/audit workflow; encrypted backup→isolated restore с owner login/старым профилем/revoked negative/Caddy/rollback; complete security identities/inventory и aggregate disk/RAM; обязательный pinned full suite перед G8. Переиспользуй queue/adapter/worker/renderer/journal и проверенные механизмы, не создавай параллельные.

Доказательства переиспользовать: b67290b target storage1.454s/CLI1.080s PASS; API тогда только compiled/no matching tests. Python18tests PASS2.556s на том же pinned source. Verifier source0bc5513→fc2ec74 target PASS по SOL-A, общий full набор после интеграции не запускался. Последний полный exact-engine Go bf04c54 предшествует schema8: нельзя объявлять новые функции покрытыми им.

WSL VPNControl-Lab уже настроен, ничего не переустанавливать и не включать /mnt/c/interop. Go /opt/vpn-control/toolchain/go/bin/go; offline GOPROXY=file:///opt/vpn-control/proxy, GOSUMDB=off, GOTOOLCHAIN=local, GOFLAGS="-p=1 -mod=readonly", явные HOME/GOMODCACHE/GOCACHE из HANDOFF. Сохранить go.sum/mod verify. Сетевые тесты отдельным systemd-run PrivateNetwork=yes. Новые каталоги прогонов, старые не затирать. Полные команды и ограничения RootDirectory/WSL keeper — в HANDOFF/W8_LAB_QUALIFICATION.

W8 0/4 полностью закрытых пунктов; W6 3/4/G6OPEN, W7 3/4/G7OPEN, W9 0/4, W9.1 0/6; общий E1 6/11. G8 не принят. После W8 — W9, затем шесть пунктов W9.1; G9 принимает компоненты, E1 дополнительно требует G9.1. Не закрывать G6/G7 без фактической матрицы. Проблему ChatGPT Download Manager владелец отложил; backlog сейчас не подключать. Интерфейс/CLI English, ответы кратко по-русски со строки прогресса. После проверенного результата обновляй PLAN с ревизией, доказательством, открытым и первым следующим действием.
