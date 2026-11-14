# W8 local dependencies — 3/3 inventory package

Read-only Windows inventory. No SSH, owner materials, execution or lab changes. PLAN latest local runner entry reviewed; runtime qualification remains Lead-owned.

## Existing reusable artifacts

Module cache root: C:/Users/a.filatov/AppData/Local/Temp/w2proxy-5333edf4305f4eab99555586c8d03449
Versions exactly match installer/controlpanel/go.mod: mattn/go-sqlite3 v1.14.53, x/crypto v0.45.0, x/sys v0.38.0. Historical origin and previous go mod verify: PLAN W3. SHA256 below identifies bytes only; new Linux go mod verify against tracked go.sum still required.

| Relative cache path | bytes | SHA256 |
|---|---:|---|
| github.com\mattn\go-sqlite3\@v\v1.14.53.info | 196 | 2982d5e08c768762ead4dd3fd2171cb5e975fec12b3af2aa72e93039bcbf96e3 |
| github.com\mattn\go-sqlite3\@v\v1.14.53.mod | 146 | 4c08597e14c92d9ed25f1bd14a2242198f0e3011964e798018abceb2ccbe82bf |
| github.com\mattn\go-sqlite3\@v\v1.14.53.zip | 2987031 | a1a2f76a2109acba21d65ecb44c1de0f98257fe506737a7acf6959304dd8782c |
| golang.org\x\crypto\@v\v0.45.0.info | 193 | d169a8a622c096c362a243da61b57cc19ad2bf0144c84404cdf7bde7369596ec |
| golang.org\x\crypto\@v\v0.45.0.mod | 192 | 6eee774fe69c286329ac0ae96c550a53f62dc1ad320b34d2b72e89e7f72c28a9 |
| golang.org\x\crypto\@v\v0.45.0.zip | 2223680 | 416335b9102df16747b29fe58d034d6d9fb70af314740136fb0a37ae8c568705 |
| golang.org\x\sys\@v\v0.38.0.info | 190 | bcdcfb9af95382ec461792e0188fe0df61e2ccf50af6041d0884cc49622f5c64 |
| golang.org\x\sys\@v\v0.38.0.mod | 35 | f411814d83a96e86781b1dee41c125b9504da5422dba37cc1d63b016ae39cfe2 |
| golang.org\x\sys\@v\v0.38.0.zip | 2002991 | dacd7c9aa2b298f966822da214c6d601da08f14d41b29032bcac4bc503887a49 |

Local alpha13: C:/AllFiles/SoftWare/VPN/Amnezia/CodexVPN/w6-alpha13.tar.gz
SHA256 bfc39f643a5ecc1b702c5723ff662e61dde813f12b3af0d0cfce4f629ff74047, matches previously upstream-verified PLAN W6/3. tar listing contains sing-box and libcronet.so under sing-box-1.15.0-alpha.13-linux-amd64. Not executed or extracted. Original upstream checksum not re-fetched in this inventory.

Caddy exact historical build: v2.11.9, Go1.27.3, xcaddy0.4.7, klzgrad/forwardproxy v0.0.0-20261022172731-e747854e7874. Expected binary SHA256 7509cd6b38a5da3324a08f32f62a7000237e5e1f6ccfb58e818bf730de58d30c (PROJECT_CONTEXT.md and pilot/caddy-apply.md). Local reusable binary not found in targeted project filename scan; production path deliberately not accessed.

Naive/base checker: official sing-box1.14.4 revision c005f35300ce76427dc285481ec5695f5b179cd2; historical release archive SHA256 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968 (PROJECT_CONTEXT.md). No matching local archive/binary found in targeted project scan. TEST_STATUS references production /opt/empire-vpn/bin/sing-box and /opt/empire-vpn/cache/w6-checker-alpha13/... only, not local evidence.

## Minimal next actions

1. Copy existing nine-file proxy to dedicated Linux lab path; GOPROXY=file:// absolute path, GOSUMDB=off, GOTOOLCHAIN=local, GOFLAGS=-p=1 -mod=readonly; run go mod verify against pinned repository go.sum before accepting reuse.
2. Copy existing alpha13 archive after checksum comparison; safely inspect members/extract only into new private lab cache, keep sing-box and libcronet together; qualify exact version and checker behavior in lab.
3. Obtain official SagerNet/sing-box v1.14.4 linux-amd64 release plus checksum manifest, compare expected archive hash above, stage binary/libcronet privately. No production copy needed.
4. For Caddy prefer locating an explicitly authorized local build cache first. If absent, Lead may rebuild from build-caddy.sh pinned versions on lab, validate version/module manifest; different binary hash is a new candidate requiring exact engine qualification, not identity with historical build.

prepare_rehearsal_root.py additionally needs newly built rehearsal-bin/vpnctl and existing templates/helpers; it does not provision Caddy or Naive itself. Harness systemd mounts, credentials, namespaces, identity proof and exact Caddy/Naive flags remain qualification work.

Steps: 1 cache/artifact inspection done; 2 identified path/hash inventory done; 3 missing acquisition/copy instructions done. Failed-fix count0; no tests needed for report-only inventory.
