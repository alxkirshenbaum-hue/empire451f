# BL-011.1 — Domain/path HTTPS panel

17.11.2026. Architect panel_domain_design; Lead integrates.

## Contract

One existing main Caddy process manages the VPN domain certificate and renewal.
Public :443 block stays without any panel proxy, even with a known prefix.
Private https://<domain>:18650 binds only127.0.0.1 inside namespace naive.
Only /<32 random hex>/ and descendants proxy to existing evpn-panel frontend
(now HTTP127.0.0.1:18651). Strip prefix exactly once at main Caddy; others404.
Private HTTP127.0.0.1:18652 redirects to https://<domain>{uri}.
No TLS key copying/shared storage across processes/new helper or service.
Frontend retains dedicated Unix API identity/sandbox. Main Caddy gets no extra
identity/group/capability/API socket permission.

Controller creates panel_path once before render, retaining config/manifest/session.
Root-owned API env: PROFILE_DOMAIN,PANEL_ORIGIN,PANEL_BASE_PATH,PANEL_ENTRY_IP.
Validate HTTPS origin/base path/entry IPv4 at startup; never derive trust from Host
or forwarded headers. Internal API routes stay rooted; HTML/JS/redirect/cookie use
external prefix. Strict Origin/CSRF/session guards unchanged. CLI parses configured
origin from env or root-owned api.env; defaults preserve legacy installations.
No schema/journal changes.

Exact sing-box TCP80/443 domain and entry IPv4 rules route VPN traffic to loopback
18652/18650 before deny rules; no generic private/loopback bypass. Profiles match
these exact destinations before direct rules, without fake transport-domain DNS.
Independent direct transport DNS resolver stays intact. Old credentials preserved.
No private CA generation/save/trust prompts; final ready URL in protected session
and output: connect VPN, open URL, log in with separate panel owner.

## Acceptance and rollout

Targeted Go auth/API/profile/CLI and Python render/controller/delivery checks plus
Caddy validate and exact sing-box check; reuse unchanged crypto/worker PASS.
Architect review before destructive rollout. Publish new immutable release, never
retag rc4. Software-clean only authorized hh-entry85.155.185.169 and
hh-exit85.155.184.194; preserve OS/SSH/default host routes. Existing source JSON
verified before cleanup, no extra backups requested, reserve193.233.22.78 untouched.
One published command: JSON import, installer exit0, fresh SSH both nodes. External
real VPN: system-trusted TLS, prefix UI/assets/login/create/download, new/master
TCP/UoT; public known prefix/forwarded spoof denied, Origin/CSRF negatives, worker
reload retains private block. Observe resources. No DR/reboot/E matrix inferred.
