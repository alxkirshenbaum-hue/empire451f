# Local lab qualification — 2026-11-14

Result: local runner3/3 qualified for subsequent development. G6/G7/G8 are NOT
accepted by this report. W6/W7 remain3/4, E1 unreleased. All mutations below are
synthetic within VPNControl-Lab. No production mutations or downtime occurred.

## Revisions and dependencies

- Full product tests and RootDirectory scenarios: pinned78515f4 (includes reviewed
  harness portability03f627a). Two hardcoded Python3.14 paths became/usr/bin/python3;
  UID/capability/network/mount/denial protections unchanged. SOL-B review PASS.
- Independently reviewed raw-tar guard: source82b74a1 -> integrated2ae9706;
  design588e6d9 ->6687c8c. Separate new source directory preserved78515f4 runs.
- Windows offlineproxy9files/3modules reused; Go1.27.3/GCC13.3.0, CGO SQLite
  built successfully. GOPROXY=file:///opt/vpn-control/proxy, GOSUMDBoff,
  GOTOOLCHAINlocal, GOFLAGS=-p=1 -mod=readonly. Initial/post-build mod verify PASS.
- Repository and both Linux source go.sum SHA256:
  d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825.
- Caddy2.11.9 rebuilt locally with existing pinnedxcaddy0.4.7/klzgradforwardproxy.
  Actual SHA7509cd6b38a5da3324a08f32f62a7000237e5e1f6ccfb58e818bf730de58d30c
  EXACTLY historical; SOL-B independently checked embedded Go/module mapping,
  actual hash and forward_proxy module. Build evidence /opt/naive-build.
- sing-box1.14.4 archive699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968;
  alpha13 archivebfc39f643a5ecc1b702c5723ff662e61dde813f12b3af0d0cfce4f629ff74047.
  Official checksum evidence and local transfer hashes match; actual version
  output1.14.4/c005f353 and1.15.0-alpha.13/824dbcfb confirmed. libcronet deps resolve.

## Executed evidence

| Check | Observation |
|---|---|
| Baseline Go e263338 | go test -count=1 ./... PASS; not final opt-in/network proof |
| Full Go78515f4 | ALL packages PASS under separate systemd PrivateNetwork unit vpn-lab-full-78515f4-20261114110229 |
| Exact flags | VPN_TEST_CADDY_ADAPTER=1, VPN_TEST_NAIVE_PROBE=1, VPN_TEST_SFA_CHECK and _1144=/opt/empire-vpn/bin/sing-box, _ALPHA13=/opt/vpn-control/artifacts/alpha13/sing-box-1.15.0-alpha.13-linux-amd64/sing-box, VPN_TEST_SFA_DNS=1 |
| Python78515f4 | Ran82 OK/skipped4, PrivateNetwork |
| Frontend8202 | RootDirectory/LoadCredential + private API bind; UID981/CapEff0/network isolation; vault/proc-root/admin denied, API allowed; HTTPS trustedCA/exactSNI/login/no-store/owner+admin denial PASS |
| Owner CLI8202 | Actual CLI/API/worker create/replay/rename/CAS/protected record;3 private mode0600 profile files, no-overwrite/no-output-secrets; fresh issued TCP/UoT PASS |
| Full worker8204 | disable/no-op/enable/rotate/delete/replay; injected SQLite finish failures + explicit rollback/complete; fresh new/old/control TCP/UoT; MIG05/real paths/unprivileged validate/TLS/socket denial/download/installer return PASS |
| Python2ae9706 | Full discovery Ran84 OK/skipped4, PrivateNetwork; includes10 artifact tests and raw extension-before-parser guards |
| Go evidence reuse | git diff78515f4..2ae9706 -- controlpanel/{cmd,internal,migrations,go.mod,go.sum} EMPTY; unchanged Go evidence applies, no new Go run claimed |

Python skips4 are platform-specific Windows/macOS checks; Linux xattr and actual
hardlink tests ran. Raw admission remains a read-only prototype: extension records
are refused before tarfile; PAX/ACL compatibility, DB binding, end-to-end streaming
envelope/usable backup restore and resource gates remain OPEN. No backup verified
status or new API backup workflow is asserted.

## Local setup incidents and lifecycle

1. First full Go transientunit stopped BEFOREtests because HOME/cache unspecified.
   Explicit HOME/GOMODCACHE/GOCACHE fixed it on first correction; network isolation
   preserved. No failed corrective iteration.
2. Copy8201 stopped before completion; not counted PASS. WSL lifetime was held
   explicitly by one owned foreground sleep while detached UI scenarios ran.
   Copy8202 then reached ready and actual checks PASS. No systemd sandbox workaround.
3. First frontend8202 got217/USER: host WSL NSS lacked numeric UID/GID981.
   Independently reviewed lab-only locked/nologin evpn-panel981:981 provisioned
   after names/IDs collision checks. No home/supplementary groups; passwd-S L.
   Same frontend/sandbox then PASS on first correction.
4. Lead prepared8203 too early after removing8202 ui-hold: ETXTBSY while old API
   exited. Partial8203 preserved; no test PASS claimed. Waited confirmed8202
   inactive/MainPID0 BEFORE new8204 preparation. All later scenario preparation
   must wait previous unit MainPID0, not only removal of marker. Shared source
   subtree must not be overwritten while a copy executes it.

Final8201/8202/8204: inactive, MainPID0, Resultsuccess.8201 remains interrupted,
not accepted despite Resultsuccess. No Caddy/sing-box/vpn-control/vpnctl processes
remain. No old run directories removed. Owned WSL keeper is released after checks.
Single234.7M UI unit peak is an observation only, NOT aggregate G8 RAM proof;
full backup/load/retention/disk500MB and RAM500MB gates still unmeasured.
WSL optional Ubuntu-Pro Windows bridge had failed-unit noise with interop disabled;
no general OS-health/G9 claim is made and no global service policy changed.

Lead read-only scp of PUBLIC Caddy binary attempted once, SSH publickey denied;
no retry/access-policy/key/production-file change. Local rebuild supplied exact
bytes, so no production artifact access was needed. No real owner material used.

## Agents and next step

- Lead: lab qualification3/3 done, integration + pinned tests + live copy checks.
- SOL-A: dependency inventory3/3, sing-box acquisition2/2, Caddy planning2/2 and
  build3/3, compatibility design2/2 and raw guard3/3 complete.
- SOL-B: portability review3/3, full-suite mapping2/2, Caddy review1/1,
  raw guard review/verification2/2, local identity proposal review1/1 complete.
- ASTRA routed0; failed corrective attempts0 (distinct setup failures fixed on
  first correction). No counters reset or production authority granted.

FIRST NEXT ACTION: W8 consistent snapshot/registry generation + credential-vault
binding and producer-compatible artifact/restore proof, reusing existing queue,
writer and owner envelope. Do not promote backup state before actual checks.
G6 phone-specific missing evidence/deferred ChatGPT Download Manager issue remains
explicitly open; no new phone/production session authorized by local tests.
