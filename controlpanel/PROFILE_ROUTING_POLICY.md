# Profile routing policy — 2026-11-14

Decision from the owner clarification during W5–W7 development.

## Defaults and option

New panel-generated profiles default to **base routing**: no RU domain/IP
split, no remote RU rule sets and no Android Download Manager package rules.
Preserve Naive/UoT, protected DNS/bootstrap, the exact panel.home.arpa proxy
route, and separately reviewed local-network routing. This decision does not
edit any existing issued profile or installed template revision.

Offer one unchecked option: **Enable RU / Download Manager routing**.

English warning:
"Requires SFA 1.15.0-alpha.13. Routes selected Russian resources and other
Download Manager traffic directly; OpenAI downloads stay on the VPN.
Compatibility must be verified on your device."

The supported option target is the exact 1.15.0-alpha.13 build named in this
project (owner shorthand “15a3” is interpreted in that established context).
Do not silently treat alpha.3, other prereleases or arbitrary 1.15 builds as
certified. Target 1.14.4 supports only the base product variant; selecting the
option must fail with TEMPLATE_INCOMPATIBLE rather than dropping rules.
API/CLI/renderer enforce the same capability gate as the UI.

Approved immutable variants must share one renderer and issuance path.
Persist/audit the selected target, revision and nonsecret routing option.
The option changes profile generation only, never Caddy credentials and never
an already-issued profile. Switching the option requires an explicit download.

## Evidence and limits

The official [1.14.4 route documentation](https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.4/docs/configuration/route/rule.md)
already describes package_name, package_name_regex (added in 1.14.0), domain,
rule_set and routing actions. Thus “1.14.4 has no such syntax” is not a verified
fact. The existing project template includes combined package/domain rules,
RU suffixes and rule sets, and was adapted for 1.15 alpha13.

This is a product support restriction for the optional combined scenario;
it does not assert that RU routing is technically impossible in 1.14.4.
JSON/checker acceptance does not prove Android package attribution, real
Download Manager behavior or RU routing. The exact alpha release is
[1.15.0-alpha.13](https://github.com/SagerNet/sing-box/releases/tag/v1.15.0-alpha.13).

## Required acceptance

- Base: import, fresh VPN TCP/UoT, panel DNS/TLS/access, public/private access
  boundaries on both 1.14.4 and 1.15.0-alpha.13.
- Optional: on 1.15.0-alpha.13, actual OpenAI download through VPN, another
  Download Manager download direct, RU domain/IP direct and other traffic via
  VPN; Wi-Fi and mobile observations recorded separately.
- 1.14.4: option rejection and base absence of DM/RU rules, not an unsupported
  requirement that the optional scenario works on that target.
- Owner reports both builds available. Phone measurements remain open.

## Exact panel destination — policy revision 2

New immutable variants include a hosts DNS server for exact
panel.home.arpa → 192.0.2.119 (A; AAAA is an empty successful answer) and
an exact TCP/443 192.0.2.119/32 Naive route beside the exact domain route.
This matches the already deployed relay allowlist; it adds no generic private
route and does not change the relay or an issued profile.

Schema 7 retains all policy-1 variant IDs, bodies and mappings. A new policy-2
mapping selects new approved immutable revisions at issuance; the existing
user source/binding and credential remain intact. Real isolated DNS exchanges
and exact-version checker passed on f482bb6 for base 1.14.4, base alpha13 and
optional alpha13. Android acceptance is still pending.