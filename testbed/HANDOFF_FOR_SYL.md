# Callandor dylib-hijack research — handoff

You're picking up an authorized macOS dylib-hijack research campaign. This is the full state
so you can continue without prior context.

## TL;DR

Callandor is a Swift macOS dylib-hijack scanner + PoC generator. We hardened it (Phases 1–4 +
a bundle weakest-link rollup), built a reproducible test corpus of ~60 enterprise apps on a VM
(`nbvm`), scanned it, and **dynamically proved exploitability**. Result: **43 of 57 apps
exploitable** — 39 via a no-library-validation dylib foothold, 9 via Electron `RunAsNode` RCE.
The dynamic/reversing-station pass is the open thread; it's **blocked because nbvm is out of
disk (~117 MB free)**.

## Repo

- GitHub: `https://github.com/UnsaltedHash42/Callandor`
- Branch: `feat/phase-1-parser-core` (pushed; latest ~`faa85f5`)
- `git clone` it, then read `testbed/FINDINGS.md` — that's the authoritative findings doc.
- Build: `swift build -c release` → `.build/release/Callandor`. Sanity: `testbed/build_fixtures.sh`
  builds one synthetic Mach-O per variant and asserts detection (all 5 pass).

### What Callandor does now
- Parses FAT/thin Mach-O; reads load commands, LC_ID_DYLIB, `__TEXT,__cstring`, `_dlopen` import.
- `VulnerabilityType`: weakDylibHijack, rpathHijack, relativePath, envVarInjection, dlopenRelative.
- Code-signing **load-viability gate** per binary: LOADABLE / SAME_TEAM_ONLY / BLOCKED.
- `BundleAnalyzer`: rolls per-binary data up to the bundle and reports the **weakest link**
  (one LOADABLE binary = foothold for the whole bundle) + names the foothold binary.
- Proxy PoC generator: `generate --type proxy --from <dylib>` (reexport proxy, version-matched).
- Electron is NOT yet in Callandor (see open threads); audited via `testbed/electron_audit.py`.

## Test environment: nbvm

- `ssh nbvm` (192.168.64.23), key auth, **NOPASSWD sudo**. macOS 26.5.1, arm64, 4 CPU / 4 GB.
- Homebrew installed. ~60 apps in /Applications.
- **DISK FULL: ~117 MB free.** Static scans work; dynamic work (running apps, dtrace scratch)
  will fail until reclaimed. Root cause: a disk expansion was done but the +77 GB sits
  unpartitioned *behind the Recovery partition*, so the APFS container (131.5 GB ceiling) never
  grew. Fix before dynamic work: reclaim console/Disk Utility, OR `diskutil` partition surgery
  (risky on boot disk — get sign-off), OR uninstall a few big apps (Android Studio/IntelliJ/
  PyCharm ≈ 6 GB) for scratch.
- State notes: batch-1 bundles are `root:wheel` (models a managed deployment); batch-2 bundles
  user-owned; quarantine was cleared on DBeaver + the Electron apps for PoCs.
- **Gotcha:** Homebrew 6 quarantines casks; the `com.apple.quarantine` xattr makes Gatekeeper
  SIGKILL binaries run headless (exit 137, no output). Clear with
  `sudo xattr -dr com.apple.quarantine <app>` before running/PoCing.
- Corpus install is reproducible: `testbed/apps.txt` + `testbed/install_apps.sh` (Homebrew 6
  removed `--cask --no-quarantine`; the script omits it). `apps_batch2.txt` is a second batch
  (Office/GlobalProtect/etc. — mostly failed/skipped on disk, not yet installed).

## Findings (authoritative copy in testbed/FINDINGS.md)

Two independent barriers, kept separate:
- **Library validation** — `LOADABLE` = no LV barrier (binary not hardened, or has
  `disable-library-validation`) → an unsigned planted dylib loads. `SAME_TEAM_ONLY` = needs a
  bypass.
- **Write access** — bundle-internal = admin on a managed Mac (but devs are often admins;
  user-installed apps + auto-update dirs are user-writable).

**43/57 apps exploitable** (corpus scan `scan_nbvm_final.json`, local-only/gitignored):
- 39 have a no-LV dylib foothold (incl. VS Code, Slack, Teams, Zoom, Webex, Box, Docker,
  Chrome, Edge, Notion, Citrix; heavy: LibreOffice 213/216, Android Studio 183/183, Audacity
  132/132).
- 9 Electron fuse-RCE (below). Clean on both axes (~13): 1Password, KeePassXC, iTerm, Sequel
  Ace, Sourcetree, TeamViewer, Tunnelblick, DB Browser, Zotero, Remote Desktop, Rectangle,
  AppCleaner, Google Drive.

### PROVEN dynamically on nbvm
1. **DBeaver bundled JRE `libjli.dylib`** — launchers (jcmd/jstack/jwebserver) ship
   `disable-library-validation` + `allow-dyld-environment-variables`. Two vectors executed our
   code: rpath-shadow proxy planted at `jre/.../bin/libjli.dylib` (loads before `../lib`,
   reexports real symbols) and `DYLD_INSERT_LIBRARIES`. Same OpenJDK signing in Android
   Studio / IntelliJ / PyCharm JREs.
2. **Electron `RunAsNode` RCE — 7 apps** ran arbitrary node under the *vendor's* signing
   identity (no file write, no plant): VS Code (`com.microsoft.VSCode`/UBF8T346G9), Cursor
   (VDXQ22DGB9), GitHub Desktop (VEKTX9H2N7), Insomnia (FX44YY62GV), Postman (H7H8Q7M5CK),
   balenaEtcher (66H43P8FRG), Azure Storage Explorer (UBF8T346G9). Test:
   `ELECTRON_RUN_AS_NODE=1 "<app>/Contents/MacOS/<exe>" -e '<js>'`. Inherits the app's TCC.
   1Password/Notion/Slack correctly lock their fuses.

### VERIFIED (not yet detonated)
3. **Citrix Workspace** — the main `Citrix Viewer` process has `disable-library-validation`
   (`+ allow-jit`) and loads `libavcodec`/`libswscale`/`Ctx*` frameworks from its writable
   `Frameworks/` via `@rpath`. Same mechanism as DBeaver. The `HdxRtcEngine` binary enforces LV
   (the `.`/`$ORIGIN` rpath there is a porting bug, not exploitable). Lesson baked in: judge the
   bundle, not one binary.

### Bypass taxonomy for SAME_TEAM_ONLY (wiki + web)
- **Weakest-link sibling** (LV is per-binary): apps that looked blocked but have a LOADABLE
  sibling — Citrix, Google Chrome, Microsoft Edge, The Unarchiver.
- `disable-library-validation` / `allow-dyld-environment-variables` entitlements.
- **TCC inheritance** — inject a process holding camera/mic/Screen/FDA → inherit those grants.
- Ad-hoc resign; Dev-ID theft (out of scope); notarization swap. Recent: CVE-2025-30462
  (App Sandbox bypass). SIP strips `DYLD_*` but rpath hijack still works when LV is off.
- Wiki refs: `~/wiki/pages/techniques/dylib-hijacking-macos.md`,
  `concepts/macos-code-signing-architecture.md`, `concepts/amfi-code-signature-validation.md`,
  `techniques/electron-app-injection-macos.md`.

## Tooling artifacts (testbed/)
- `build_fixtures.sh` — detection oracle (host, no VM).
- `apps.txt` / `install_apps.sh` / `apps_batch2.txt` — reproducible corpus install.
- `electron_audit.py` — parses the @electron/fuses wire + checks asar; flags RunAsNode/
  NODE_OPTIONS/asar-integrity. Run: `python3 electron_audit.py` on the target host.
- `FINDINGS.md` — full writeup.
- Scan JSONs are local-only (gitignored): `scan_nbvm.json` (user-owned), `scan_nbvm_rootowned.json`
  (managed model), `scan_nbvm_final.json` (expanded corpus). Re-generate with
  `Callandor /Applications --json`.
- `dtrace` works on nbvm with SIP on (syscall provider — traces hardened apps without attaching):
  `sudo dtrace -q -n 'syscall::open*:entry /strstr(copyinstr(arg0),".dylib")!=0/{...}'`.

## Open threads (suggested next steps)
1. **Unblock disk on nbvm** (see above) — prerequisite for anything dynamic.
2. **Reversing-station active pass** — per app, launch with a real workload and dtrace
   `open`/`dlopen` to confirm static dlopen-relative findings and catch runtime-only loads;
   upgrade confirmed findings to CONFIRMED. First attempt on LibreOffice (`soffice --headless
   --convert-to`) hung on first-run init and filled the disk — needs disk + per-app tuning
   (execname becomes `soffice.bin`; use a workload that actually loads the libs).
3. **Bake Electron into Callandor** — add `VulnerabilityType.electronFuse` + an `ElectronDetector`
   (port `electron_audit.py`: find Electron Framework, parse fuse wire, flag RunAsNode/
   NODE_OPTIONS/no-asar-integrity). Makes it a first-class finding.
4. **Dropbox RunAsNode** — fuse reads ON but the main-exe invocation didn't take (native
   wrapper); find the real Electron entry/helper.
5. **Citrix Viewer** — detonate to convert VERIFIED → PROVEN (replace a `Frameworks/` dylib
   with an ad-hoc proxy; LV is off).
6. **Finish batch-2** once disk allows (Office, GlobalProtect, Company Portal, PowerShell, etc.).

## Discipline
Authorized purple-team research on a disposable lab VM. Clean up plants (use traps), prefer
benign markers over live payloads, don't run destructive partition ops without sign-off.
