# Callandor test campaign — findings

Target VM: `nbvm` (NightBlood VM, 192.168.64.23) — macOS 26.5.1, arm64.
Date: 2026-06-23. Binary: Callandor release built from `feat/phase-1-parser-core` @ Phase 4.

## Method

1. **Detection validation** (`build_fixtures.sh`, host, no VM): one synthetic Mach-O per
   variant. All five flagged — `relativePath`, `weakDylibHijack`, `rpathHijack`,
   `dlopenRelative`, `envVarInjection`. Deterministic gate; passes.
2. **Corpus** (`apps.txt`, `install_apps.sh`): 49 enterprise-weighted casks, 47 installed
   (zoom, anydesk failed: EULA/pkg). 54 apps / 3284 Mach-O binaries in `/Applications`.
3. **Two scans** to bracket the threat model — bundles user-owned (as Homebrew installs
   them) vs. root-owned (managed / standard-user deployment).

## The permission artifact

Homebrew installs casks owned by the invoking user (`nightblood:staff`, owner-writable), so
every bundled dylib trips the writability gate. This inflates findings and is not
representative of a hardened deployment.

| Threat model | Findings | Dylib-hijack candidates |
|---|---|---|
| Bundles user-owned (single-user install) | 4721 | 3743 HIGH/MED |
| Bundles **root-owned** (`chown -R root:wheel`) | **113** | **2** (LOW) |

Root-owning collapses 4721 → 113 (the residual 111 are `envVarInjection`, which does not
depend on writability). The gating works: on a properly-permissioned system a non-privileged
process can hijack almost nothing. The realistic answer sits between the two — if the
enterprise user is a **local admin** (`/Applications` group `admin`, frequently g+w), the
user-owned findings are live.

## Exploitability verdict (dynamically confirmed on nbvm)

| Target | Callandor | Exploitable? | Why |
|---|---|---|---|
| DBeaver bundled JRE (`libjli.dylib`) | rpathHijack HIGH | **YES — proven** | `disable-library-validation` → planted unsigned dylib loads |
| Citrix `HdxRtcEngine` (`libwebrpc.dylib`) | rpathHijack LOW | No (this binary) | LV enforced on HdxRtcEngine; real codecs resolve via `@executable_path/../Resources` |
| **Citrix `Viewer` (main process)** | — | **YES** (corrected) | Viewer has `disable-library-validation` + `allow-jit`; loads `libavcodec/libswscale/Ctx*` from its writable `Frameworks/` via `@rpath`. Same proven mechanism as DBeaver. App-specific detonation pending; entitlement + load structure verified. |

**Correction:** an earlier pass called Citrix "not exploitable" off the one binary (HdxRtcEngine)
that enforces LV. Wrong — judge the *bundle*, not one binary. The primary `Citrix Viewer`
process disables LV. Lesson: per-binary, weakest-link wins.

Callandor's load-viability gate separated the two correctly: HIGH/loadable for the exploitable
JRE, LOW for the LV-protected Citrix binary. The gate is what makes the difference — a
load-command-only scanner would rate the Citrix `.`/`$ORIGIN` rpath Critical.

**Test-env caveat:** Homebrew 6 quarantines casks by default; the quarantine xattr makes
Gatekeeper SIGKILL binaries run headless (exit 137, no output). Cleared it
(`xattr -dr com.apple.quarantine`) to model an approved / MDM-deployed app before the PoC.

## Exploitable surface — corrected & expanded

Two *independent* barriers, which an earlier pass conflated:

- **Library validation (LV)** — code-signing gate. `LOADABLE` = no LV barrier (binary not
  hardened, or carries `disable-library-validation`) → a planted *unsigned* dylib loads.
  `SAME_TEAM_ONLY` = LV enforced → needs a bypass (below).
- **Write access** — can you write the dylib's resolved path. Inside `/Applications/*.app` =
  needs admin on a managed Mac (but: devs are often local admins; user-installed apps are
  user-writable; auto-update staging dirs are often user-writable).

Counts from the nbvm corpus (`scan_nbvm.json`): **4610 hijack findings — 3744 `LOADABLE`
(no LV barrier) across 26 apps**, 866 `SAME_TEAM_ONLY`.

26 apps with a no-LV-barrier hijack: Android Studio, Audacity, Cursor, Cyberduck, DBeaver,
Docker, Firefox, HandBrake, IINA, IntelliJ IDEA CE, LibreOffice, Notion, OBS, ONLYOFFICE,
Obsidian, PyCharm CE, Royal TSX, Slack, Stats, Sublime Text, Thunderbird, VLC, Visual Studio
Code, Webex, Wireshark, balenaEtcher.

### Bundle weakest-link rollup (added to Callandor)

LV is per-binary, so a bundle is only as strong as its weakest Mach-O. Callandor already
enumerated every binary per bundle (verified 391/391 vs the RE-platform gatherer on Citrix);
it now rolls that up (`BundleAnalyzer`). Corpus result: **34 of 51 top-level apps (67%) have a
LOADABLE foothold** — a binary with no LV barrier (mostly `disable-library-validation`, some
unsigned/non-hardened) — independent of write access. Includes VS Code, Slack, Teams, Zoom,
Webex, Box, Docker, Chrome, Edge, Notion, Citrix, plus the heavy-finding apps (LibreOffice
213/216, Android Studio 183/183, Audacity 132/132). The foothold binary is named in the output
so a bundle is never judged by one binary again.

### Bypassing `SAME_TEAM_ONLY` (LV enforced)

Per [[macos-code-signing-architecture]] / [[dylib-hijacking-macos]] / [[amfi-code-signature-validation]]:

1. **Weakest-link sibling** — LV is per-binary. If any binary in the bundle is `LOADABLE`
   (non-hardened, or `disable-LV`) and loads the same dylib, plant once and it executes in
   that binary. Bundles where every *finding* was `SAME_TEAM_ONLY` but a `LOADABLE` sibling
   exists: **Citrix Workspace** (Citrix Viewer), **Google Chrome**, **Microsoft Edge**,
   **The Unarchiver**.
2. **`disable-library-validation` / `allow-dyld-environment-variables` entitlements** — common
   on third-party apps (DBeaver JRE, Citrix Viewer). Trivial plant / `DYLD_INSERT`.
3. **Ad-hoc re-sign** for non-LV contexts; Developer-ID theft (out of scope); notarization
   swap (revocation race).
4. **TCC inheritance** — injecting a process that holds camera/mic/Screen/FDA inherits those
   grants (dylib injection → TCC bypass; cyberark/zznQ writeups). Citrix Viewer (`allow-jit`,
   HDX media perms) is a candidate.

Recent context (web): CVE-2025-30462 (App Sandbox bypass, SentinelOne); SIP strips `DYLD_*`
for protected/hardened binaries but rpath hijack still works when LV is off; HackTricks
"macOS Library Injection"; cyberark macOS pentest pt.3.

### Coverage gap: Electron apps

VS Code, Slack, Teams, Notion, Cursor, Obsidian are Electron — their classic dylib surface is
~1 finding each (the `SAME_TEAM_ONLY` Electron-Framework `libffmpeg`). Their *real* attack
surface is Electron-specific (RunAsNode/EmbeddedAsarIntegrity fuses, `app.asar` tampering,
`NODE_OPTIONS`, `--inspect`) — see [[electron-app-injection-macos]]. Callandor's dylib lens
**under-reports** these; they need a separate Electron audit.

## Electron coverage (separate vuln class; `electron_audit.py`)

Callandor's dylib lens under-reports Electron apps, so a fuse/asar audit was run. The
high-impact fuse is **RunAsNode**: with it ON, `ELECTRON_RUN_AS_NODE=1 <app>/Contents/MacOS/Electron`
turns the signed binary into a Node interpreter → arbitrary code execution **with no file write
and no dylib plant**, under the app's code-signing identity (trust laundering) and inheriting
its TCC grants.

| App | RunAsNode | Other | Verdict |
|---|---|---|---|
| Visual Studio Code | ON | NODE_OPTIONS, --inspect, no-asar-integrity | **EXPLOITABLE — proven** |
| Cursor, Dropbox, GitHub Desktop, Insomnia, balenaEtcher | ON | NODE_OPTIONS, --inspect, no-asar-integrity | EXPLOITABLE |
| Postman | ON | NODE_OPTIONS, no-asar-integrity | EXPLOITABLE |
| OpenVPN Connect | OFF | NODE_OPTIONS, no-asar-integrity | EXPLOITABLE |
| 1Password, Notion, Slack | OFF | fuses locked | hardened (good) |

**Proven on nbvm:** `ELECTRON_RUN_AS_NODE=1 "Visual Studio Code.app/Contents/MacOS/Electron"
-e '<js>'` executed arbitrary JS under `com.microsoft.VSCode` (TeamID UBF8T346G9), uid 501.
See [[electron-app-injection-macos]]. (Candidate to bake into Callandor: detect Electron
Framework, parse the fuse wire, flag RunAsNode/NODE_OPTIONS/asar-integrity.)

## Verified findings

### 1. Citrix Workspace — `libwebrpc.dylib` CWD rpath + `$ORIGIN` porting bug (LOW — NOT exploitable)

`/Applications/Citrix Workspace.app/Contents/CitrixWorkspaceApps/HdxRtcEngine.bundle/Contents/Resources/libwebrpc.dylib`

```
otool -l:
  LC_LOAD_DYLIB  @rpath/libwebrtc_codecs.dylib
  LC_LOAD_DYLIB  @rpath/libRtmControl.dylib
  LC_RPATH       path .            <- literal current working directory
  LC_RPATH       path $ORIGIN/     <- ELF-ism; macOS dyld does NOT expand it
```

`$ORIGIN/` is a Linux build artifact — macOS dyld doesn't expand it, so it resolves to a
literal directory named `$ORIGIN` (never present). That leaves `.` (the process CWD) as a
live rpath resolver. The real dylibs ship in the same `Resources/` dir, reachable via these
rpaths only when CWD is set there; a process launched with an attacker-influenced CWD would
search `./libwebrtc_codecs.dylib` first. Survives the root-owned scan because it does not
depend on bundle permissions.

**Why LOW, not HIGH:** `libwebrpc.dylib` is hardened-runtime + `TeamIdentifier=S272Y5R93J`
→ load-viability `SAME_TEAM_ONLY`. A planted dylib must carry Citrix's Team ID or library
validation rejects it. Callandor's Phase 2 viability gate correctly caps the rating — a
load-command-only scanner would mis-rate this Critical. This is the gate working on a real
binary.

Follow-up worth doing: confirm the HdxRtcEngine launch CWD; report the `$ORIGIN` porting bug
to Citrix regardless (broken on macOS).

### 2. DBeaver bundled JRE — `libjli.dylib` rpath shadow (HIGH, bundle-perm-dependent)

`/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/bin/*` (jwebserver, jstack, jcmd, …)

```
otool -l:
  LC_LOAD_DYLIB  @rpath/libjli.dylib
  LC_RPATH       path @loader_path/.        <- bin/ : libjli.dylib NOT here
  LC_RPATH       path @loader_path/../lib   <- lib/ : legit libjli.dylib lives here
```

First rpath (`bin/`) precedes the rpath that actually holds the dylib (`../lib`). Plant
`libjli.dylib` in `bin/` → loads before the legit one (shadow). Correct shadow detection.

**Exploitable — proven on nbvm.** The launchers (`jcmd`, `jstack`, `jwebserver`, …) are
hardened+Team-signed (OpenJDK, `JCDTMS22B4`) but ship `com.apple.security.cs.disable-library-validation`
**and** `com.apple.security.cs.allow-dyld-environment-variables`. Library validation is off,
so a planted unsigned dylib loads. Two confirmed vectors (each wrote a marker as the
non-privileged user, bundle chowned back to the user to model local-admin/user-install):

1. **rpath shadow** — a reexport proxy planted at `bin/libjli.dylib` loaded before
   `../lib/libjli.dylib`, ran its constructor, and reexported the real symbols so the
   launcher kept working. (This is exactly Callandor's Phase 4 proxy structure.)
2. **`DYLD_INSERT_LIBRARIES`** — second, simpler vector enabled by the `allow-dyld` entitlement.

Precondition: write access to the bundle (local admin on a managed Mac, or any user for a
user-installed copy) — no code-signing barrier. Same OpenJDK signing in Android Studio,
IntelliJ CE, PyCharm CE bundled JREs → same exposure.

### Other leads (user-owned model)

- `dlopenRelative` MEDIUM (imports `_dlopen`): LibreOffice (`@loader_path` → Frameworks —
  matches the wiki survey's libcairo dlopen case), Android Studio NDK/lldb dirs, Royal TSX.
- Royal TSX missing weak `libswift_Concurrency.dylib`.

## Tool-quality note (Phase 6 candidate)

When an entire bundle is writable, Callandor emits one finding **per dylib** (Audacity →
2698). It should collapse "entire bundle writable" into a single finding to cut noise; the
per-dylib detail belongs behind a verbose flag.

## Reproduce

```sh
./testbed/build_fixtures.sh                     # detection oracle (host)
scp testbed/{apps.txt,install_apps.sh} VM:~/cb/ # corpus
ssh VM 'cd ~/cb && bash install_apps.sh'        # install (needs NOPASSWD sudo)
scp .build/release/Callandor VM:~/cb/
ssh VM '~/cb/Callandor /Applications --json' > scan.json
# realistic model:
ssh VM 'sudo chown -R root:wheel /Applications/*.app'   # then re-scan
```
