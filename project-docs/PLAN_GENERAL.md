# Общий план CodexVPN

Статусы отражают доказанную область, не готовность по наличию кода. Подробные критерии — [U/E backlog](../controlpanel/UE_BACKLOG.md), приоритеты и исключения — CURRENT.md.

| Этап | Статус и остаток |
|---|---|
| Сеть/Naive/TLS | Базовая схема и исторические fail-closed/recovery проверки выполнены; их результаты не переносить автоматически на новую пару/ревизию |
| W2–W5 реестр/ownership/Caddy/операции | Историческая приёмка сохранена; [прежний план](archive/2026-11-22/logs_panel_plan.md) содержит критерии и ссылки |
| W6/G6 профили | 3/4; целевые подключения подтверждены, полная Android DNS/IPv6/RU/app/network матрица и итоговый протокол открыты; BL-009 отложен |
| W7/G7 API/CLI/UI | 3/4; owner create/download/connect принято, остаток target nonadmin/external и совместный протокол G6/G7; повтор deploy не нужен |
| W8U перенос/backup | 0/4 целиком; partial evidence сохраняется, portable отложен владельцем |
| W8E | 3/8 reused; полный restore/rollback, rotation/SEC, ресурсы и остальные критерии — по ledger |
| W9U MVP панели | 3/5: 02 CRUD, 04 restart/rollback, 05 regression/guide; 01 phone/access и 03 export/import+health открыты |
| W9E | Расширенные candidate/security/recovery, capacity12/50/100+master, 5UI/30changes/24h, rollout/reboot/runbooks открыты |
| W9.5U-Fresh | F1–F4 4/4; rc10 fresh+Q27 принято в точной области протокола, не общий W9.5 |
| W9.5U/E, прежний W9.1/G9.1 | Частично; M2 доустановка/M3 upgrade и portable отложены; failure/topology/cross-platform матрицы не закрыты |
| W10U наблюдаемость | 1/4: 03 ingress resources/stored timestamps принято; live egress, exit audit/stale и UI/CLI PASS/FAIL открыты |
| W10E | User-attributed bytes, auth/history/trends/retention не приняты |
| W11U/E уведомления | Канал не выбран; health events/failure-recovery/cooldown/dedup/token safety и расширения открыты |
| W12U/E профили/шаблоны | Approved catalog/selection/personal issue/preservation/version checks и расширения — по backlog; целый этап не принят |
| W13U/E orchestration | 0/4 U; preview/approval/staging/recovery/injection/resources, полный journal и multi-hoster открыты |
| W14U/E topology | 0/4 U; diff/swap/credentials/new SSH/failure-safe outcome и расширения открыты |
| W15U/E | DEFERRED_BY_OWNER до выбора истории: второй ingress/exit/admin, RBAC/automation/topology |
| E1 общий выпуск | Не закрыт; fresh не заменяет исходную расширенную приёмку |

Нормативная детализация: [UE_STRATEGY](../controlpanel/UE_STRATEGY.md), [ledger W8](../controlpanel/W8_UE_EVIDENCE.md), [U acceptance](../controlpanel/U_ACCEPTANCE_2026-11-16.md), [installer entry](../controlpanel/INSTALLER_ENTRY_CONTRACT.md).
Около 500МБ — ориентир дополнительного ДИСКА, не фиксированный RAM-порог. Известная нехватка места блокирует опасную операцию; RAM/пики измерять по риску.
