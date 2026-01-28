import Foundation

let asciiArt = """
\u{001B}[36m
   ______      _ _                 _            
  / ____/___ _| | | __ _ _ __   __| | ___  _ __ 
 | |   / _` | | | |/ _` | '_ \\ / _` |/ _ \\| '__|
 | |__| (_| | | | | (_| | | | | (_| | (_) | |   
  \\_____\\__,_|_|_|_|\\__,_|_| |_|\\__,_|\\___/|_|   
       \u{001B}[35mS W O R D   T H A T   I S   N O T\u{001B}[0m
"""

let helpMessage = """
\(asciiArt)

\u{001B}[1mUSAGE:\u{001B}[0m 
  Callandor <directory> [options]
  Callandor generate --type <revshell|raw> --output <path> [args]

\u{001B}[1mCOMMANDS:\u{001B}[0m
  scan <directory>        (Default) Scan directory for vulnerabilities.
  generate                Generate a POV dylib exploit.

\u{001B}[1mARGUMENTS:\u{001B}[0m
  <directory>             The directory path to scan recursively.

\u{001B}[1mOPTIONS:\u{001B}[0m
  --json                  Output results in JSON format.
  --markdown              Output results in Markdown format.
  --help, -h              Show this help information.

\u{001B}[1mGENERATE OPTIONS:\u{001B}[0m
  --type <type>           'revshell' or 'raw'
  --output <path>         Output .dylib path (default: exploit.dylib)
  --host <ip>             (revshell) Attacker IP
  --port <port>           (revshell) Attacker Port
  --payload <file>        (raw) Path to raw shellcode file (.bin)

\u{001B}[1mDESCRIPTION:\u{001B}[0m
  Scans macOS applications for Dylib Hijacking vulnerabilities, including:
  - Weak/Missing Dylibs
  - Writable RPATHs
  - Relative Path Loading
  - Environment Variable Injection Susceptibility (Hardened Runtime/Restricted segments)
"""

let args = CommandLine.arguments


if args.contains("-h") || args.contains("--help") {
    print(helpMessage)
    exit(0)
}

// Subcommand: generate
if args.count > 1 && args[1] == "generate" {
    // Parse generate args
    // generate --type <revshell|raw> --output <path> ...
    
    var type: String?
    var output: String = "exploit.dylib"
    var host: String?
    var port: Int?
    var payload: String?
    
    var i = 2
    while i < args.count {
        let arg = args[i]
        if arg == "--type" && i+1 < args.count {
            type = args[i+1]
            i += 1
        } else if arg == "--output" && i+1 < args.count {
            output = args[i+1]
            i += 1
        } else if arg == "--host" && i+1 < args.count {
            host = args[i+1]
            i += 1
        } else if arg == "--port" && i+1 < args.count {
            port = Int(args[i+1])
            i += 1
        } else if arg == "--payload" && i+1 < args.count {
            payload = args[i+1]
            i += 1
        }
        i += 1
    }
    
    guard let mode = type else {
        print("\u{001B}[31mError: Must specify --type <revshell|raw>\u{001B}[0m")
        exit(1)
    }
    
    let outputURL = URL(fileURLWithPath: output)
    
    if mode == "revshell" {
        guard let h = host, let p = port else {
            print("\u{001B}[31mError: revshell requires --host and --port\u{001B}[0m")
            exit(1)
        }
        print("Generating Reverse Shell dylib for \(h):\(p)...")
        _ = ExploitGenerator.generate(type: .reverseShell(host: h, port: p), outputURL: outputURL)
    } else if mode == "raw" {
        guard let p = payload else {
            print("\u{001B}[31mError: raw mode requires --payload <path>\u{001B}[0m")
            exit(1)
        }
        print("Generating Raw Shellcode dylib from \(p)...")
        _ = ExploitGenerator.generate(type: .rawShellcode(url: URL(fileURLWithPath: p)), outputURL: outputURL)
    } else {
        print("Unknown type: \(mode)")
        exit(1)
    }
    
    exit(0)
}


guard args.count > 1 else {
    print(helpMessage)
    exit(1)
}

let path = args[1]
// Basic check to ensure it looks like a path and not a flag
if path.hasPrefix("-") {
    print("\u{001B}[31mError: First argument must be a directory path or 'generate' command.\u{001B}[0m")
    print(helpMessage)
    exit(1)
}

var format = "text"
if args.contains("--json") { format = "json" }
if args.contains("--markdown") { format = "markdown" }

let scanner = Scanner(path: path)
let result = scanner.run() 

if format == "json" {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted
    if let data = try? encoder.encode(result), let json = String(data: data, encoding: .utf8) {
        print(json)
    }
} else if format == "markdown" {
    print("# Callandor Scan Report")
    print("Target: \(path)")
    print("Date: \(Date())\n")
    
    if result.vulnerabilities.isEmpty {
        print("No vulnerabilities found.")
    } else {
        print("## Vulnerabilities")
        for vuln in result.vulnerabilities {
            print("### \(vuln.type.rawValue)")
            print("- **Binary**: `\(vuln.targetBinary)`")
            print("- **Severity**: \(vuln.severity)")
            print("- **Details**: \(vuln.details)")
            print("")
        }
    }
    
    print("\nTotal binaries scanned: \(result.scannedBinaries.count)")

} else {
    // Text
    print("Found \(result.vulnerabilities.count) potential vulnerabilities.")
    for vuln in result.vulnerabilities {
        print("[\(vuln.severity)] \(vuln.type.rawValue): \(vuln.targetBinary) - \(vuln.details)")
    }
    print("\nScanned \(result.scannedBinaries.count) binaries.")
}
