# HERCULES Antivirus

A terminal-based antivirus application written in Rust.

## Features

- **Quick Scan** — Scans common locations (Downloads, Desktop, Temp)
- **Full Scan** — Scans your entire home directory
- **Custom Scan** — Scan any file or folder of your choice (native file picker or manual path entry)
- **Live Progress Bar** — Animated loading bar showing %, files scanned (x/y), and threats found during the scan
- **Scan Summary** — Threats detected, files checked, and time elapsed after every scan
- **Quarantine** — Isolate, restore, or delete detected threats
- **Real-time Protection** — Background file system monitoring with automatic threat handling by severity
- **Threat Database** — Built-in signature database (EICAR test file, trojans, ransomware, worms, rootkits, botnets, exploits, PUAs, adware, spyware, keyloggers)
- **Settings** — Configure real-time protection and monitored paths

## Requirements

- Rust (latest stable)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hercules.git
cd hercules

# Build
cargo build --release

# Run
cargo run --release
```

Or just:

```bash
cargo run
```

## Usage

Run the app and use the numbered menu:

```
═══════════════════════════════════════════
         HERCULES         
═══════════════════════════════════════════

  Status: System protected

MAIN MENU
1. Quick Scan
2. Full Scan
3. Custom Scan (choose file/folder)
4. Quarantine
5. Real-time Protection
6. Threat Database
7. Settings
0. Exit

Select option: 
```

### Testing Detection

The app detects the standard EICAR test file. To verify it works:

```bash
# Create an EICAR test file (harmless test string)
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Run Hercules and select Custom Scan (option 3), then enter the path /tmp/eicar.txt
```

## Project Structure

```
hercules/
├── Cargo.toml          # Rust project manifest
├── README.md           # This file
└── app/
    ├── Cargo.toml      # App dependencies
    └── src/
        ├── main.rs     # Terminal UI and menu
        ├── scanner.rs  # Hash-based scanning engine + quarantine
        ├── database.rs # Threat signature database
        └── realtime.rs # Real-time file system monitoring
```

## Detection Method

Hercules uses SHA-256 hash-based signature matching against a built-in threat database. When a file's hash matches a known threat signature, it is flagged and can be quarantined.

## License

MIT