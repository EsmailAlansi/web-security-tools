# 🛡️ Web Security Tools

> **Author:** Esmail Alansi
> **Purpose:** Educational penetration testing and web application security assessment.
> **⚠️ For authorized use only. Do not use on systems without explicit written permission.**

---

## 📌 Overview

This repository contains Bash and PowerShell tools for web application security testing:

| Tool | Type | Platform |
|------|------|----------|
| `sqlmap_pro.sh` | SQL Injection Testing | Linux/Kali (Bash) |
| `Parametar.sh` | Parameter Discovery | Linux/Kali (Bash) |
| `brute-loginid.ps1` | Login ID Brute Force | Windows (PowerShell) |

---

## 📂 Tool 1: sqlmap_pro.sh

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

## 📂 Tool 2: Parametar.sh

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

## 📂 Tool 3: brute-loginid.ps1

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
| `sqlmap_pro.sh` | `sqlmap_results/` |
| `Parametar.sh` | `param_scan_results/` (includes `links.txt`) |
| `brute-loginid.ps1` | `success_results.txt` |

---

## 🧰 Prerequisites

### For PowerShell tools (Windows)
- PowerShell 5.1 or later

### For Bash tools (Linux/Kali)
| Tool | Installation |
|------|-------------|
| sqlmap | `sudo apt install sqlmap` |
| curl | `sudo apt install curl` |
| grep | Usually pre-installed |
| bash | Usually pre-installed |

---

## 📝 Example Workflow

### 🔎 Using sqlmap_pro.sh
```bash
./sqlmap_pro.sh
# Set target (option 1): http://example.com/page.php?id=1
# Set level/risk (option 2): 3/2
# List databases (option 4)
# Dump a table (option 6)
```

### 🔍 Using Parametar.sh
```bash
./Parametar.sh
# Set target (option 1): http://example.com
# Extract parameters (option 2)
# Run full crawl scan (option 3)
# Scan each discovered link (option 4)
```

---

## ⚠️ Important Warnings
- **Legal Use Only** – These scripts are for educational purposes and authorized security assessments.
- **Ethical Responsibility** – Do not use on any system without explicit written permission.
- **Data Sensitivity** – Dumping databases may expose sensitive information. Handle with care.
- **No Warranty** – The author is not responsible for any misuse or damage caused by these tools.

---

## 📄 License
This project is intended for educational and authorized security research purposes only.
