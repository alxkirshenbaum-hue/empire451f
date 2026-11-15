# Fresh VPN + panel release candidate — 2026-11-15

Priority: PRIORITY_FRESH_INSTALL.md. Portable export/import and its fixtures remain STOPPED. W9.5U-Fresh local F1/F2/F4 prepared; F3 real new-pair acceptance OPEN. This is not general W9.5U/E or E1 acceptance.

## Ready artifact

Code/source 08be0c38781fc08c40522ede361ed9ea940b921a. Release v0.4.0-rc1. Checked panel runtime core0c05a6174e254192939227668f9d4947904984d4; unfinished portable runtime is excluded.

Outer dist/w95-fresh-08be0c3-candidate.zip:22,736,406bytes SHA256 a4625d457a03cc97dbe1d44b0d9c85263f6b3f9d5c66347f4cff92329f389551. Contains README.txt, installer.zip, installer.sha256, windows.ps1, macos.sh, build-provenance.json.
Inner installer.zip:22,760,632bytes SHA256 eb8810f5299cbc8592dc7e77bf52409e6dbeaa9f659a04c749b0626ad4bf3e5c. Main independently checked both hashes/archive inventory. Artifacts are local, NOT published/pushed. Prior intermediate25db9d1 folder retained, not final.

After extracting outer ZIP, from its folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows.ps1 -BundlePath .\installer.zip
```

Choose new/fresh with two NEW Ubuntu24.04/26.04 amd64 hosts, verifiedSSHkeys and readyDNS/domain. ExistingnativeSSH/SCP sends checked ZIP to bothnodes. ExistingVPNapply/freshSSH/commit precedes registry→ownerstdin→G3/MIG05→privateAPI/frontend/worker. Save VPNprofile and publicCA, compareCAfingerprint and explicitlytrustclientCA; ownerpassword independent ofVPNpassword, notargv/session/exitRPC. Realuse awaits targetedserverauthorization.

## Actual local evidence

- Pinned08be0c3 firstfreshcontroller4testsPASS0.015s; complete selectedregression63testsPASS3.230s, skipped4platform-specific. Earlier193/2e repeatsfailed oneNEWfixtureexpectation (controllerreturns1/stderr), corrected08; no productfailurehidden.
- Windows PS7 and WindowsPowerShell5.1.19041 ASTPASS. ActualPowerShell withSSH/SCPmocks: bundleuploadbothnodes/hashrejection/publicCAdownload,tamperrefusal,absentskip PASS. DoesnotprovephysicalWindows→twoVDS install.
- GeneratedmacOS bash-nPASS onLinux; actualmacOSnotrun.
- Freshrenderengines PrivateNetwork unitfresh-config-engine-f177001: singbox1.14.4 relayJSON+SFAprivateDNScheckPASS, Caddy2.11.9 adapt/validatePASS. Onlyfixturepath/socket/TLSmapping, no listeners/servicesstarted. Render/delivery unchanged946d0bf..f177001; finalchangesafterwardscontroller/launcher/docs/tests, reusevalid.
- Pinnedcore binaries actuallybuilt fromimmutable0c05a61 Go1.27.3/offlineproxy: vpncontrol SHA34ce33ecfaea722a300b01b0507e21ff8449a9eb033d4c62472e65369ed5c497; vpnctl SHA5ee106d875cd13852fde0d4182acf1ff575c08ec612577f58422c7d806b368f6. go.sum/modverifyPASS, provenance fileinsidecandidate. Existingowner/create/profile/TCP-UoT proof reused only forunchangedcore; notnewfreshinstallationproof.
- Independentsecurity source-review no remainingcodeblocker: freshonly/rootguard, earlyregistry/TLS/unitconflicts inclsymlinks, distinctUID/GID, privateUnixadmin, exactTCP443panelroute, sourcepin/hash, ownerstdin, committedVPNnotrolledbackonpanelfailure.

## Honest boundary / next action

F1 packaged and locallyverified. F2 standardfreshhook implemented andunitchecked. F4 localcandidate/Windowscommand/instructionsready. F3 NOTRUN: no two new authorizedVDS targets supplied. WSLunit/config/mocks do not prove actualnetworkinstall, serviceboot, namespace/socketdenials, SSH or newowner→create→download→freshTCP/UoT acrossfreshpair. Need explicitnewentrySSH, newexitSSH, domain/DNS and permission toinstall/test ONLY thatpair. Existingproduction/reserve untouched.

No new framework/journal. Freshpayload rejectsexistingpanelstate; upgrade/replace/migration deferred. PublicCA trust is manual/explicit; privateleaf365days, automaticrenewalnotimplemented. Optionalwebsitepublishing skipped forpanelcandidate to preserveworker.site baseline; legacyVPN-onlyworkflow unchanged. DNSmustreadybeforeapply; readonlypreviewallowedbeforeDNS.

Finalruntime source /opt/vpn-control/release-src-08be0c3-20261115181927, unitw95-final-08be0c3 completed, labreleased. Noownruntimejobsfromportable remain (STOP record W8U_STOP_FRESH_PRIORITY_2026-11-15.md). Nexttask is targetednewpairtest, NOT portable/Econtinuation.
