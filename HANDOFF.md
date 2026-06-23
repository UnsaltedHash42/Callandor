# Callandor Handoff

## What this is
Callandor is a Swift macOS dylib-hijack vulnerability scanner + PoC generator for authorized purple-team work. Branch `feat/phase-1-parser-core` carries Phases 1–4.

Commits:
- `30bd18a` Phase 1+2 — parser correctness + code-signing load-viability gate
- `8be1ce2` Phase 3 — static dlopen() target detection
- `ad53103` Phase 4 — proxy (re-export) PoC generation

## Module map
- **MachOParser.swift** — FAT/universal (picks arm64, falls back x86_64), bounds-safe thin parse. Reads filetype, LC_LOAD/WEAK/REEXPORT dylib paths + versions, **LC_ID_DYLIB** (install name + version), LC_RPATH, LC_ENCRYPTION_INFO(_64), `__RESTRICT`, `__TEXT,__cstring` bounds, and scans LC_SYMTAB string table for `_dlopen`. Exposes `cstringOffset/cstringSize/importsDlopen` on `BinaryInfo`.
- **VulnerabilityDetector.swift** — every hijack finding gated through the load-viability matrix (LOADABLE / SAME_TEAM_ONLY / BLOCKED). Confidence tiers. TeamID + Apple-platform-binary detection. Distinguishes public `disable-library-validation` (real) from private `clear-library-validation` (not load-time hijackable). Rpath shadow detection. Skips `.rpath` and `.idDylib` load commands (a lib's own name is not a dependency). Path expansion (`expand`), writability, bundle-containment helpers reused by the dlopen detector.
- **DlopenDetector.swift** — Phase 3. Reads the `__TEXT,__cstring` bytes, extracts NUL-terminated literals, keeps dylib-shaped ones (`.dylib`/`.so`/`.framework/` or `@rpath`/`@loader_path`/`@executable_path` with a library-or-directory tail; data-file extensions like `.conf`/`.pem` excluded), dedupes against load commands, resolves + writability-gates them through the Phase 2 matrix. Confidence LOW by default, MEDIUM when the binary imports `_dlopen`.
- **ProxyGenerator.swift** — Phase 4. See below.
- **ExploitGenerator.swift** — standalone payload dylibs: `revshell` (constructor forks, connects, dup2, execve /bin/zsh) and `raw` (mmaps RWX, runs shellcode). Proxy reuses these C bodies verbatim.
- **Scanner.swift** — 4-byte magic check via FileHandle, symlink skip, stderr progress. Runs `VulnerabilityDetector.check` then `DlopenDetector.check`.
- **Models.swift** — `BinaryInfo` (+ teamID, loadViability, isApplePlatformBinary, cstring bounds, importsDlopen), `Vulnerability` (confidence + loadViability), `VulnerabilityType` (weakDylibHijack/rpathHijack/relativePath/envVarInjection/**dlopenRelative**), `DylibVersion` (current + compat strings), `LoadCommandType` (+ idDylib).
- **main.swift** — `scan` (default) with `--json`/`--markdown`; `generate --type <revshell|raw|proxy>`. Text output filters BLOCKED findings, shows `[Severity/CONFIDENCE]`.

## Phase 3 — dlopen detection (done)
Load commands only capture link-time deps; runtime `dlopen("lib/Foo.dylib")` is invisible to a load-command walker. The static pass closes that gap. Verified on /Applications: 23 findings — VLC libbluray plugin (relative `@loader_path`/`@executable_path` dirs), calibre OpenSSL engine/module dirs, Hopper Swift runtime (`@rpath/libswift*`, MEDIUM — imports `_dlopen`), VLC absolute writable libvlc paths.

Optional future active pass (`--validate`, lab-host only): run target under `DYLD_PRINT_LIBRARIES`/`DYLD_PRINT_APIS`, diff attempted loads against static findings to upgrade to CONFIRMED.

## Phase 4 — proxy (re-export) PoC generation (done)
A bare payload dropped over a legitimately-loaded dylib crashes the host (its linked symbols are gone). A **proxy** forwards every symbol to a renamed copy of the real library via `LC_REEXPORT_DYLIB`, stamped with the original's `compatibility_version`/`current_version` so dyld accepts the substitute, while the payload constructor still runs.

Usage:
```
Callandor generate --type proxy --from <original.dylib> --output <proxy.dylib> \
    (--host <ip> --port <port> | --payload <shellcode.bin>) \
    [--reexport-path <path where the real lib is staged on target>]
```

What it does:
1. Parses `--from` for its `LC_ID_DYLIB` install name + versions (errors cleanly if the target has no LC_ID_DYLIB, e.g. an executable).
2. Stages a copy of the real library as `<base>.real.dylib` next to the output (install name untouched — dyld loads it by the path recorded in the proxy's reexport command).
3. Emits the payload C (reused from `ExploitGenerator`) and links the proxy.
4. **Link sequencing** (the fiddly part): ld refuses to reexport a dylib whose install name equals the output's `-install_name`, and `install_name_tool` can't grow an id past the header padding. So the proxy is built under a placeholder install name with `-headerpad_max_install_names`, reexporting the original; then `install_name_tool -change` repoints the reexport to the staged real path and `-id` claims the original's install name. No surgery on the real copy.
5. Prints a static validation report (PASS/FAIL on LC_REEXPORT_DYLIB target, LC_ID_DYLIB match, compat_version stamp) and writes `validate_<base>.sh`. Validation is **static only by default** — a runtime `dlopen` of the proxy would detonate the payload, so runtime confirmation is left to the lab host (consistent with the Phase 3 active-pass posture).

Deployment (operator, on target): place the proxy at the original library's path; place the renamed real copy at the embedded reexport path (`--reexport-path` to point it where you'll stage it).

Verified: synthetic `libfoo.dylib` + client — client still returns 42 through the proxy (whole-library forwarding works), constructor compiled in, static validation PASSes; real-world VLC plugin (relative `.libs/...` install name) parses + builds; non-dylib `--from` errors; full /Applications rescan shows no regression and relative LC_ID_DYLIB names do not leak into `relativePath` findings.

Note: the proxy is single-arch (host arm64). Fat-target parity is a Phase 6 polish item.

## Remaining phases
- **Phase 5** — Purple-team reporting (ATT&CK T1574.004, SARIF output, detection guidance).
- **Phase 6** — Polish: test fixtures, chained-fixups parsing, fat/universal proxy output, perf, optional `--validate` active dlopen pass.

## Scan baseline (/Applications, current run)
1190 vulnerabilities — rpathHijack 726, envVarInjection 435, dlopenRelative 23, weakDylibHijack 5, relativePath 1. (Counts drift as installed apps update.)
