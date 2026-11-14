# W7 copy status — not accepted, 2026-11-14

Do not deploy the candidate frontend. G6 and G7 are open.

## Verified revisions

- W5/G5 accepted on copy: 64718cf; G5_ACCEPTANCE_2026-11-14.md.
- W6 routing policy 2 and schema 7: f482bb6. Original immutable variants,
  source bindings and credentials remain intact. Exact hosts DNS for the
  panel and exact /32 TCP443 Naive route match the deployed allowlist.
- W7 owner API/CLI/UI: 28b80ec/f482bb6; browser form fix 8fc03c7.
- Full pinned 8fc03c7 Go suite passed with both network flags, both exact
  SFA checker variables and real DNS flag. Python69 tests/4skip passed.
  go mod verify passed; go.sum SHA256:
  d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825.
- Browser RootDirectory7001: independent owner login, create with deliberately
  lost 202 acknowledgement, reload, original-intent replay, one operation,
  confirmed active account; display-name HTML remained literal text.
  1.14.4 default and disabled optional checkbox observed. Shared notice shown.
- The first login failed because no-referrer made navigation POST Origin:null.
  Same-origin header fixed it in the browser fixture; production guard still
  rejects external/null Origin. Regression/consumer tests and pinned full suite
  passed. The second copy7002 uses the actual fixed API.
- Browser download wait tool failed with expired continuation. Do not count a
  successful browser download or alpha13 checkbox interaction.

## Isolated copies

Pinned source: /opt/empire-vpn/cache/w7-pinned-8fc03c7.
Binaries: rehearsal-bin/vpnctl and rehearsal-bin/vpn-control in that copy.
Synthetic root: rehearsal-root-7002; unit vpn-full-worker-root-7002.
The UI hold has a 30 minute deadline; its removal ends the loop and its context
cleans up all copy processes. No production unit is involved.
7001 is finished; SSH output transport reset after its deadline. Never interpret
the reset/failed outer runner as a completed acceptance result.

The unfinished frontend runner is pilot/panel_frontend_rehearsal.py.
Latest diagnostic version was uploaded only to the development copy:
  /opt/empire-vpn/cache/w5-auth-XAtR3pjw/pilot/panel_frontend_rehearsal.py
It takes an explicit project/run and requires active synthetic root markers.
The candidate unit itself is controlpanel/systemd/vpn-control-panel.service.

## Unresolved security blocker

Initial transient sandbox with + prefixed InaccessiblePaths failed
226/NAMESPACE for /run/caddy-admin although the directory exists in the copy.
A minimal transient unit without + started; that change was carried to the
runner, not the production service. A PID int/str bug was corrected.

The real Caddy frontend then listened on loopback18650 with UID981/CapEff0,
in the same isolated network. TLS succeeded with the synthetic trusted CA and
exact SNI, but GET / returned502. A probe using the same sandbox reported that
one secret boundary was readable. The current assertion checks listdir for
directories and stat for proc-root/admin socket. The specific failed path has
not yet been identified. The subsequent diagnostic attempt was rejected by
automatic approval review under the owner's four-attempt stop condition.
No bypass or further diagnostic attempt was made.

The same UID as the API was proposed so its private0600 socket can be reached;
vault paths/proc and cross-process debug syscalls must be denied demonstrably.
The current result does not establish that boundary. Do not remove those
denials, broaden private routes, publish the API, or call it accepted.
Reconsider the identity/socket policy only after determining the failed path
and the cause of502. No second journal/worker/daemon is needed for CRUD.

## Production facts, read only

API, nh1 worker timer, readonly frontend, Caddy and sing-box were active.
Actual API socket: /run/vpn-control-api/api.sock, 981:981 mode0600,
parent /run/vpn-control-api mode0700. Do not use the CLI's generic default path
without setting VPNCTL_SOCKET to the actual deployment path.
Database and vault.key: /var/lib/vpn-control, 981:981, private.

Old frontend: transient nh1-panel-readonly.service, DynamicUser, naive netns.
It uses the existing pilot certificate/key/config credentials. A stopped
transient unit cannot simply be assumed restartable: capture its exact unit
and credential sources root-only before any approved change.
Leaf certificate is valid through 2026-11-25 11:19:54 UTC. Do not regenerate
the owner's CA, credentials, keys or profiles.
No new production deploy/CRUD/restart occurred. Reserve remains untouched.

## Remaining work

1. Resume only after owner instruction following the four-attempt stop.
2. Prove private HTTPS frontend isolation and real owner API/CLI profile output.
3. Finish browser download/alpha13/default/protected/nonadmin observations.
4. Prepare a concrete tested deploy/rollback package. Preserve exact TLS and
   owner credentials; export current active users before a return, never use
   stale pre-auth. Reuse the existing G3 snapshot/journaled return mechanisms.
5. Stop before the required production control-plane shutdown per owner's
   exception. Main transport Caddy/relay/WG are not part of a UI switch.
6. After an approved connection, run the joint OnePlus12 session:
   base1.14.4, base1.15.0-alpha.13, optional alpha13 only.
   RU/DM is unchecked by default with an English warning and rejected on1.14.4.
   Actual Android/Download Manager/Wi-Fi/mobile evidence remains mandatory.
7. G6/G7 and full E1 must not be marked accepted prematurely. W8/W9 backup and
   measurement actions remain visibly unavailable pending their implementation.
## Documentation checkpoint after 9b9ea35

W6 remains the first unaccepted stage (3/4). Independent W7 implementation
(2/4) was prepared to combine a future manual phone session; this was the
agent's scheduling interpretation, not acceptance of G6. Neither G6 nor G7
has passed. The owner's request for an explanation/handoff does not restart
the blocked sandbox investigation.

See [test status matrix](TEST_STATUS_2026-11-14.md) for explicit
PASS/PARTIAL/FAIL/OPEN and [handoff prompt](HANDOFF-W6-W7.md).
No new tests were run for this documentation checkpoint. The previous cleanup
removed the synthetic7002 hold marker and stopped the local loopback helpers;
check state before any future use rather than assuming the copy is running.
The specific readable boundary and the cause of502 remain unknown.
14.11.2026 — расследование явно возобновлено владельцем; W7/3 frontend harness исправлен.
Новая синтетическая копия: w7-pinned-8fc03c7/rehearsal-root-7101; продуктовые бинарники 8fc03c7.
Диагностика: читаемы /var/lib/vpn-control и /etc/empire-vpn; API connect возвращал ENOENT.
Mountinfo подтвердил отдельный tmpfs /run у frontend с LoadCredential. Без префикса +
InaccessiblePaths адресовали host paths, а не нужные пути RootDirectory. Это дефект harness,
не установленная утечка production. +/run/caddy-admin отсутствовал именно в новом /run.
Исправление pilot/panel_frontend_rehearsal.py: root-relative masks, узкий read-only bind
каталога API в /api (bind под приватным /run также отказал NAMESPACE), синтетический config
с /api/api.sock, RuntimeDirectory для HOME, уникальные transient names, точный failed path.
До запуска проверяется наличие обоих исходных socket. ENOENT допустим только для скрытого
admin socket; secret directories/proc-root требуют PermissionError. Защиты не снимались.
Два последовательных итоговых запуска PASS: UID981/CapEff0/same isolated netns,
vault/proc-root/admin denial, private API socket connect, trusted synthetic CA/exact SNI,
HTTPS login200, no-store/same-origin, unauthorized users401, admin route404.
Полный продуктовый набор повторно не запускался: продуктовый код/unit не менялись,
G6/G7 не принимаются. W6 3/4; W7 2/4, завершён только подшаг HTTPS sandbox W7/3.
Следующий шаг: real owner CLI/browser downloads/alpha13, deploy/rollback package;
production switching требует отдельного согласования, затем телефон G6/G7.
## New copy7201: CLI/browser substep passed

Baselineaf63ab0 with unchanged8fc03c7 product binaries. Real owner CLI,
canonical queue/worker, three private profiles and fresh TCP/UoT passed.
Desktop browser downloaded all3 supported variants; protected account/default/
warning/version reset verified. Local profile hashes matched real API issuance
metadata; no profile content printed or committed. The older unconfirmed
browser download entry is historical. Root7201 was cleaned up and confirmed
inactive/MainPID0; synthetic Downloads files and loopback helpers removed.

Offline package draft: W7_UPGRADE_WINDOW.md and ../pilot/prepare_panel_upgrade.py.
Trial assembly/hash/modes/unit syntax passed; final pinned full suite/package
validation still pending. Whole production switch/rollback and phone G6/G7
remain unexecuted. No production mutation/restart/deploy occurred.