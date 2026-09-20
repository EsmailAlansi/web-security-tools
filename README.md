# 🛡️ Web Security & Forensics Tools

> **Author:** Esmail Alansi
> **Purpose:** Educational penetration testing, web security assessment, and Windows forensic incident response.
> **⚠️ For authorized use only. Do not use on systems without explicit written permission.**

---

## 📌 Overview

This repository contains security and forensics tools for both web application testing and Windows incident response:

| Tool | Type | Platform |
|------|------|----------|
| `Deep_Windows_IR_Audit_v5.ps1` | Forensic IR Audit | Windows (PowerShell) |
| `sqlmap_pro.sh` | SQL Injection Testing | Linux/Kali (Bash) |
| `Parametar.sh` | Parameter Discovery | Linux/Kali (Bash) |
| `brute-loginid.ps1` | Login ID Brute Force | Windows (PowerShell) |

---

## 🔬 Tool 1: Deep_Windows_IR_Audit_v5.ps1

### 🎯 Purpose
A comprehensive **Windows Incident Response (IR) and Forensic Audit** tool written in PowerShell 5.1. It performs deep system analysis to detect persistence mechanisms, malware indicators, and security misconfigurations — **without making any changes to the system** (read-only).

**Created by:** Esmail Alansi

### 🧩 What It Analyzes
| Category | Details |
|----------|---------|
| **Services** | Signer, hash, ACL, start mode, account, unquoted paths |
| **Processes** | Command lines, parent processes, signatures, hashes |
| **Drivers** | Kernel-mode drivers, signatures, hashes |
| **Scheduled Tasks** | Executables, signers, suspicious locations |
| **Autoruns** | Run/RunOnce keys, Startup folders |
| **Registry** | Winlogon, IFEO, AppInit, Session Manager |
| **WMI Persistence** | EventFilter, EventConsumer, FilterToConsumerBinding |
| **Network** | TCP/UDP connections, firewall rules, DNS, proxy, hosts file |
| **Local Accounts** | Users, Administrators group members |
| **Installed Software** | 32-bit & 64-bit uninstall hives, AppX packages |
| **Antivirus State** | Windows Defender status, threat detections, AV products |
| **Event Logs** | Security (4624,4672,4688,4697), System (7045), Defender (1116,1117,1119) |

### 📊 Severity Levels
| Level | Meaning |
|-------|---------|
| 🔴 `CRITICAL` | Writable service binary by broad principals — immediate action needed |
| 🟠 `HIGH` | Unsigned drivers, WMI consumers, suspicious autoruns/processes |
| 🟡 `MEDIUM` | Custom hosts entries, unsigned startup files |
| 🟢 `LOW` | Unquoted service paths (requires verification) |
| ℹ️ `INFO` | System baseline information |

### 📁 Output Files Generated
```
C:\Forensic_IR\DeepWindowsIR_v5_<timestamp>\
├── Audit.log                     # Full timestamped run log
├── Summary.txt                   # Executive summary
├── Findings.csv                  # All findings (CSV)
├── Findings.json                 # All findings (JSON)
├── Services.csv                  # Service inventory
├── Processes.csv                 # Process inventory
├── Drivers.csv                   # Driver inventory
├── ScheduledTasks.csv            # Task inventory
├── Autoruns.csv                  # Autorun/startup inventory
├── WMIPermanentSubscriptions.csv
├── TCPConnections.csv
├── UDPEndpoints.csv
├── FirewallProfiles.csv
├── FirewallRules.csv
├── DNSClientServers.csv
├── LocalUsers.csv
├── LocalAdministrators.csv
├── InstalledSoftware.csv
├── AppXPackages.csv
├── HostsActiveEntries.csv
├── hosts.snapshot                # Copy of hosts file at time of audit
├── WinDefendService.csv
├── AntiVirusProducts.csv
├── DefenderThreatDetections.csv
├── CollectionErrors.csv
└── Raw\                          # Raw text dumps (OS, registry, Defender, proxy, etc.)
```

### 🚀 Usage

> **Requires:** PowerShell 5.1+, Administrator privileges recommended.

**Basic audit (last 14 days of events):**
```powershell
.\Deep_Windows_IR_Audit_v5.ps1 -CollectEventLogs
```

**Full deep audit (30 days, hash all executables):**
```powershell
.\Deep_Windows_IR_Audit_v5.ps1 -CollectEventLogs -EventDays 30 -DeepHashAllExecutables
```

**Custom output directory:**
```powershell
.\Deep_Windows_IR_Audit_v5.ps1 -CollectEventLogs -OutputRoot "D:\IR_Evidence"
```

### ⚙️ Parameters
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputRoot` | String | `C:\Forensic_IR` | Root folder for all evidence output |
| `-CollectEventLogs` | Switch | Off | Export Security/System/Defender event logs |
| `-EventDays` | Int | `14` | Number of days of event history to collect |
| `-DeepHashAllExecutables` | Switch | Off | SHA256-hash every resolvable executable (slower) |

### 🔐 Key Design Principles
- **Read-only**: No service is stopped, no file modified, no registry key changed.
- **Low false-positives**: Separates *Observation* from *Finding* — "Auto + LocalSystem + unquoted" alone is NOT flagged as malicious.
- **Evidence integrity**: All outputs include timestamps, hashes, and metadata.
- **Compatible**: Works on PowerShell 5.1 (no external modules required).

---

## 📂 Tool 2: sqlmap_pro.sh

### 🎯 Purpose
Simplify the process of running SQLMap by providing:
- Interactive target & cookie configuration
- Predefined scanning levels (Level 1–5, Risk 1–3)
- One-click options for common SQLMap tasks (e.g., --dbs, --dump, --os-shell)
- Colored, user-friendly interface

### 🚀 Usage
```bash
chmod +x sqlmap_pro.sh
./sqlmap_pro.sh
```

### 📋 Main Menu Options
| Option | Description |
|--------|-------------|
| 1 | Set target URL (and optional cookies) |
| 2 | Adjust level & risk (1/1, 3/2, 5/3) |
| 3 | Basic detection (technique=BEUST) |
| 4 | List databases (--dbs) |
| 5 | List tables of a specific database |
| 6 | Dump a specific table (e.g., users) |
| 7 | Dump all data (--dump-all) |
| 8 | Show current database (--current-db) |
| 9 | Show current user (--current-user) |
| 10 | Attempt to get an OS shell (--os-shell) |
| 11 | Extract passwords (--passwords) |
| 12 | Advanced full scan (Level 5, Risk 3) |
| 13 | Delete previous results |
| 0 | Exit |

### 🔧 How It Works
- The script constructs SQLMap commands dynamically.
- All results are saved in `sqlmap_results/`.
- Cookies are added if provided.
- The `--batch` flag ensures non-interactive execution.

---

## 📂 Tool 3: Parametar.sh

### 🎯 Purpose
Discover hidden parameters, forms, and input fields in web pages, then optionally scan them for SQL injection vulnerabilities.

### 🚀 Usage
```bash
chmod +x Parametar.sh
./Parametar.sh
```

### 📋 Main Menu Options
| Option | Description |
|--------|-------------|
| 1 | Set target URL, cookies, crawl depth, and threads |
| 2 | Extract parameters/forms from the page using curl |
| 3 | Full crawl scan using sqlmap --crawl |
| 4 | Manually scan each discovered link containing parameters |
| 5 | Update depth & threads settings |
| 6 | Delete scan results (param_scan_results/) |
| 0 | Exit |

### 🔧 How It Works
- **Extraction** – Uses curl to fetch the HTML, then parses: GET links containing `?`, `<form>` tags with action and method, input fields with name attributes.
- **Crawl Scanning** – Uses SQLMap's built-in `--crawl` engine to spider the site.
- **Manual Scanning** – Saves all parameterised links to `links.txt` and optionally scans each one.

---

## 📂 Tool 4: brute-loginid.ps1

### 🎯 Purpose
A PowerShell script that iterates through a list of phone numbers / usernames from a text file, sends login requests to a target URL, and captures the `loginID` cookie value upon successful authentication.

**Created by:** Esmail Alansi

### 🚀 Usage
```powershell
# Place your number list in 158to.txt, then run:
.\brute-loginid.ps1
```

### ⚙️ Configuration (edit at top of script)
| Variable | Default | Description |
|----------|---------|-------------|
| `$NUMBERS_FILE` | `158to.txt` | File containing 11-digit numbers (one per line) |
| `$SLEEP_TIME` | `0` | Delay in seconds between requests |
| `$LOG_FILE` | `success_results.txt` | Output file for successful findings |

---

## 🗂️ Output Directories
| Tool | Output Location |
|------|----------------|
| `Deep_Windows_IR_Audit_v5.ps1` | `C:\Forensic_IR\DeepWindowsIR_v5_<timestamp>\` |
| `sqlmap_pro.sh` | `sqlmap_results/` |
| `Parametar.sh` | `param_scan_results/` (includes `links.txt`) |
| `brute-loginid.ps1` | `success_results.txt` |

---

## 🧰 Prerequisites

### For PowerShell tools (Windows)
- PowerShell 5.1 or later
- Administrator privileges (recommended for IR audit)

### For Bash tools (Linux/Kali)
| Tool | Installation |
|------|-------------|
| sqlmap | `sudo apt install sqlmap` |
| curl | `sudo apt install curl` |
| grep | Usually pre-installed |
| bash | Usually pre-installed |

---

## ⚠️ Important Warnings
- **Legal Use Only** – These scripts are for educational purposes and authorized security assessments.
- **Ethical Responsibility** – Do not use on any system without explicit written permission.
- **Data Sensitivity** – Dumping databases may expose sensitive information (PII, credentials, etc.). Handle with care.
- **No Warranty** – The author is not responsible for any misuse or damage caused by these tools.

---

## 📝 Example Workflow

### 🔎 Using Deep_Windows_IR_Audit_v5.ps1
```powershell
# Run as Administrator
.\Deep_Windows_IR_Audit_v5.ps1 -CollectEventLogs -EventDays 30 -DeepHashAllExecutables -OutputRoot "D:\"
# Review findings
Import-Csv "D:\DeepWindowsIR_v5_<timestamp>\Findings.csv" | Where-Object Severity -eq 'HIGH'
```

### 🔎 Using sqlmap_pro.sh
```bash
# 1. Launch the script
./sqlmap_pro.sh

# 2. Set target (option 1)
> http://example.com/page.php?id=1

# 3. Set level/risk (option 2, e.g., 3/2)

# 4. List databases (option 4)

# 5. Dump a table (option 6) – enter database name and table name
```

### 🔍 Using Parametar.sh
```bash
# 1. Launch the script
./Parametar.sh

# 2. Set target (option 1) – e.g., http://example.com

# 3. Extract parameters manually (option 2)

# 4. Run full crawl scan (option 3)

# 5. Optionally, scan each discovered link (option 4)
```

---

## 📄 License
This project is intended for educational and authorized security research purposes only.
