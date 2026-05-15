# Tamper-Evident Logging System

A Python-based cryptographic logging system that detects unauthorized modifications to log files using SHA-256 hash chains.

## Overview

This system creates an immutable, tamper-proof audit trail by:
- **Linking each log entry** to the previous one using SHA-256 hashes
- **Detecting tampering** automatically—if any entry is modified, the hash chain breaks
- **Synchronized timestamping** using NTP (Network Time Protocol) for global clock independence
- **Automatic log rotation** to manage file sizes and maintain performance

## Why Use This?

Use this system when you need:
- **Compliance auditing** (HIPAA, SOC 2, PCI-DSS)
- **Security incident forensics** — prove logs haven't been doctored
- **Regulatory proof of integrity** — demonstrate to auditors that your audit trail is tamper-proof
- **Post-incident analysis** — distinguish between a real attack and a cover-up attempt

Traditional logs can be edited or deleted by privileged users or attackers. This system makes that tampering **mathematically detectable**.

## Features

✅ **Hash-Chain Integrity** — Each log references the hash of the previous log  
✅ **NTP Timestamping** — Uses synchronized internet time (fallback to local)  
✅ **Log Rotation** — Automatically rotates files at 100 MB to prevent unbounded growth  
✅ **CLI Interface** — Simple command-line tool for insert, view, and verify operations  
✅ **Multiple Log Types** — Support for `auth`, `sys`, and `app` categories  
✅ **Backward Compatible** — Parses both quoted and unquoted descriptions  

## Installation

### Prerequisites
- Python 3.7+
- Network access (for NTP sync; falls back to local time if unavailable)

### Setup

```bash
# Clone or download the project
cd "Tamper-Evident Logging System"

# Create a virtual environment (recommended)
python -m venv .venv

# Activate it
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command-Line Interface

All commands use the pattern: `.venv\Scripts\python.exe logops.py <command> [options]`

#### Insert a Log Entry
```bash
.venv\Scripts\python.exe logops.py insert --type auth --desc "unauthorized access attempt from 192.168.1.100"
.venv\Scripts\python.exe logops.py insert --type sys --desc "kernel module loaded"
.venv\Scripts\python.exe logops.py insert --type app --desc "database connection lost"
```

#### View All Logs of a Type
```bash
.venv\Scripts\python.exe logops.py view --type auth
.venv\Scripts\python.exe logops.py view --type sys
```

Output example:
```
Timestamp : 2026-05-15T09:20:46
Type : auth
Hash : dc249ec444585efba16c603b4f3bc06f175141e54dcdebb798e78d81470f699e
Description : Log file created
```

#### Verify Integrity (Detect Tampering)
```bash
.venv\Scripts\python.exe logops.py check --type auth
```

If all logs are intact:
```
All logs are intact.
```

If tampering is detected:
```
Log integrity compromised at log: 2026-05-15T09:20:57
```

### Programmatic Usage (Python)

```python
from logops import logops
from logs_storage import log
from NTP import NTP

# Insert a log entry
logops(type="auth").append("user login from IP 10.0.0.5")

# View all logs
logops(type="auth").view()

# Check integrity
is_intact = logops(type="auth").checkIntegrity()
if is_intact:
    print("All logs are valid!")
```

## How It Works

### The Hash Chain

Each log entry contains:
1. **Timestamp** — When the event occurred (ISO-8601 format)
2. **Type** — Category (`auth`, `sys`, `app`)
3. **Hash** — SHA-256 of `previous_hash + timestamp + type + description`
4. **Description** — What happened

Example log file (`logStorage/auth.log`):
```
2026-05-15T09:20:46 auth dc249ec444585efba16c603b4f3bc06f175141e54dcdebb798e78d81470f699e 'Log file created'
2026-05-15T09:20:45 auth 9650ad3da577fb52275e301187bbb593f42c0045490281141f8fa19ddb895cbc 'unauthorized access'
2026-05-15T09:20:57 auth bac7247e5a0e869c13f1077d20edd13ff8003e0d12018944f56a66c70b12bf2c 'unauthorized access'
```

### Detection

When `check` runs:
1. It reads the **first entry** — confirms it uses the genesis hash: `dc249ec444585efba16c603b4f3bc06f175141e54dcdebb798e78d81470f699e`
2. For each **subsequent entry** — it recomputes the hash using the previous entry's hash
3. If the computed hash **matches** the stored hash → that entry is valid
4. If they **differ** → someone modified a previous entry

**Why this works:** If you change ANY field in log #2, you must also recalculate the hash for log #3, #4, etc. Modifying log #2 without updating #3+ will break the chain and be detected immediately.

## Project Structure

```
Tamper-Evident Logging System/
├── logops.py              # Main logging operations (insert, view, check)
├── logs_storage.py        # Log storage, parsing, and file management
├── hashmodule.py          # Hash calculation and verification
├── NTP.py                 # Network Time Protocol timestamp fetching
├── logStorage/            # Directory where log files are stored
│   ├── auth.log
│   ├── sys.log
│   └── app.log
├── requirements.txt       # Python dependencies (ntplib)
└── Readme.md             # This file
```

## Known Limitations & Future Improvements

### Current Limitations
- **Single-machine design** — Logs are stored locally; no distributed consensus
- **No encryption** — If an attacker gains filesystem access, they can read log contents (but can't modify without detection)
- **NTP dependency** — Relies on internet-accessible NTP server; falls back to local time if unavailable
- **No log signing** — No external signature authority (e.g., PKI, timestamping service)

### Planned Enhancements
- [ ] **Distributed verification** — Send log hashes to a central server for signed receipts
- [ ] **Encrypted storage** — Add AES-256 encryption for confidentiality
- [ ] **Multiple log types support** — Query/filter logs across all types in one command
- [ ] **Log archival** — Export and seal old rotated logs
- [ ] **REST API** — HTTP interface for remote logging
- [ ] **Database backend** — Optional PostgreSQL/SQLite storage instead of files

## Bug Fixes & Improvements

### Version 1.1 (Current)

**Bugs Fixed:**
- ✅ **Hash verification mismatch** — Descriptions with quotes were not being stripped before hashing, causing verification to fail
- ✅ **NTP error handling** — System would return an Exception object instead of a timestamp if NTP failed
- ✅ **Path inconsistency** — Log storage path was based on `os.getcwd()`, causing issues when running from different directories
- ✅ **Import-time side effects** — Code was executing during import, making testing/reuse difficult
- ✅ **Uncaught parsing errors** — Invalid log format would return `False` instead of raising an exception

**Improvements:**
- ✅ Refactored `log` class to use `@dataclass` for cleaner code
- ✅ Added type hints throughout
- ✅ Implemented missing log rotation feature (was defined but unused)
- ✅ Added comprehensive CLI with subcommands
- ✅ Better error messages and exception handling
- ✅ Cross-platform compatibility (Windows chmod handling)

## Troubleshooting

### "Log file does not exist"
The log file is created automatically on first insert. If it's missing:
```bash
# Manually initialize by inserting a test entry
.venv\Scripts\python.exe logops.py insert --type auth --desc "initializing log"
```

### "All logs are intact" but some entries look wrong
Log descriptions are stored with surrounding quotes (e.g., `'description'`). The system automatically strips them during parsing—this is normal.

### NTP timeouts
If running offline, the system falls back to your system clock automatically. For production, consider:
- Using a local NTP server
- Pre-configuring a fallback NTP pool
- Storing logs on a time-synchronized network appliance

### Windows Permission Denied
The system tries to set read-only permissions on log files (Unix only). On Windows, use NTFS permissions instead. This is best-effort and won't break logging.

## Security Considerations

⚠️ **This is a detection system, not prevention.** It will tell you if logs were tampered with, but it cannot prevent a privileged attacker from modifying files.

**For defense-in-depth:**
1. **Store log backups elsewhere** — Copy logs to immutable storage (e.g., S3 with Object Lock)
2. **Use OS-level integrity monitoring** — File Integrity Monitoring (FIM) tools like `osquery` or `aide`
3. **Centralize logs** — Send logs to a remote server immediately (syslog, CloudWatch, etc.)
4. **Cryptographic signing** — Use this system with a timestamping authority (TSA) for external proof
5. **Audit log access** — Monitor who reads/modifies the `logStorage/` directory

## License

This project is provided as-is for educational and compliance purposes.

## Support

For issues, questions, or improvements, review:
- The code comments in each module
- The CLI help: `.venv\Scripts\python.exe logops.py --help`
- Log files in `logStorage/` to inspect format directly
