# W8 U/E evidence ledger · 15.11.2026

База232aada, код WIP изолирован меткой wip-w8-prune-audit-20261115. Документальная сверка без повторных тестов. Source evidence: [валидация](W8_RESUMED_VALIDATION_2026-11-15.md), [handoff](HANDOFF_W8_CONTINUED_2026-11-15.md), [повтор rollback](W8_TRANSFER_SCOPE.md). Все сценарии локальные VPNControl-Lab, synthetic, не production.

| Проверка / source SHA | Результат и граница | U/E / reuse |
|---|---|---|
| Owner API9c197d7,4dd8956; crypto worker4dd8956 | PASS ownerAPI0.460s, encrypted roundtrip/ownership4.171s; source0c05a61/run851541 real encrypted archive+plaintext cleanup PASS | U01 partial; E01 evidence reuse yes. Чистый portable import не доказан |
| Offline/PrepareRestoreCopy6a525bc,b0dbd99,03bb43f | 8scenarios0.932s затем13scenarios1.584s; encrypted→preparedDB2.025s; session invalidation/history/binding/abort | U02/03 partial; E04 evidence reuse yes, CLI plan всё ещё открыт |
| Copy rotation4dd8956 | five tests0.513s,1→2→3,wrong pair/cancel/partial/source unchanged | E02 E_PASS_REUSED; только copy. Live key activation выделена в E06, не заявлена |
| ACL cdb3d82+ebd28cd; integration6a525bc |3.417s и integrated3.858s; UID65534 read allowed/write denied; trusted ACL policy/defaultACL refusal | E03 E_PASS_REUSED; независимый trusted destination contract обязателен |
| Wrapper2c5733e,d64e7b5,0a360f9 |8cases0.254s, exact path/hash/root0755/noattrs/default denial | E03 E_PASS_REUSED, общий критерий с ACL |
| Runtime controller7c6d0dd / destination851571 | Caddy/API/owner/старый профиль/TCP-UoT/revoked PASS; synthetic endpoint preserved by fixture | U04 partial, E01 часть PASS. Не импорт в независимую чистую установку |
| controller8708435 / destination851591 | restored runtime PASS; source rollback FileExistsError restore-api, scratch correction прошла | E01 E_INCOMPLETE, общий rollback FAIL; reuse успешной части yes |
| readonly restore-plan849edc8 | helper0.334s,owner/hash/stale/crossowner negative | E04 E_INCOMPLETE; caller fresh manifest/CLI не завершены |
| prune/audit WIP на базе8c20d6f | не скомпилирован, review не окончен; сохранены9файлов в stash+постоянная метка | E05 E_INCOMPLETE, reuse no |
| Независимые security reviews W8-SEC-002/003 | исправления в source/ACL/wrapper по caller trust constraints; полного runtime audit нет | E06 E_INCOMPLETE; review не равен общему PASS |
| Полная ресурсная/retention matrix | нет полного измерения | E07 E_NOT_RUN; disk safety отдельная U-проверка |
| Canonical snapshot c4bf7bb | Принятый Linux InspectSnapshot по W8_SNAPSHOT_INSPECTION_2026-11-14.md | E08 E_PASS_REUSED; schema/generation/vault checks. Сохранить при reuse unchanged code |

Счётчик W8E — **3/8 E_PASS_REUSED**: E02,E03,E08. E01/E04/E05/E06 INCOMPLETE; E07 NOT_RUN. E08 выделен для явного зачёта ранее принятого canonical inspection. U01–04 остаются U_INCOMPLETE (0/4 полностью закрытых), с перечисленными частичными доказательствами. Ни один старый PASS не аннулирован.

В E06 отдельно остаются activation/key-pair rollback из расширенной ротации и полный SEC22 аудит; это ограниченный список, без новых произвольных требований. Известный критический дефект сразу блокирует затронутый U. Применимость reused evidence пересмотреть только при изменении соответствующего кода/среды/контракта.

