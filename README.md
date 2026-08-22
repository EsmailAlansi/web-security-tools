📌 Overview
This repository contains two Bash automation scripts designed for educational penetration testing and web application security assessment:

sqlmap_pro.sh – An interactive wrapper around SQLMap to automate SQL injection testing.

Parametar.sh – A parameter discovery tool that extracts GET/POST parameters, forms, and input fields from web pages, then optionally scans them with SQLMap.

⚠️ Important: These tools are for authorized testing only (e.g., your own systems, CTF challenges, or pentesting engagements with explicit permission). Unauthorized use is illegal.

🧰 Prerequisites
Make sure the following tools are installed on your system (Kali Linux recommended):

Tool	Installation Command
sqlmap	sudo apt install sqlmap
curl	sudo apt install curl
grep	Usually pre-installed
bash	Usually pre-installed
Optionally, Python3 with additional libraries may be used for advanced features (currently placeholders).

📂 Script 1: sqlmap_pro.sh
🎯 Purpose
Simplify the process of running SQLMap by providing:

Interactive target & cookie configuration

Predefined scanning levels (Level 1–5, Risk 1–3)

One‑click options for common SQLMap tasks (e.g., --dbs, --dump, --os-shell)

Colored, user‑friendly interface

🚀 Usage
bash
chmod +x sqlmap_pro.sh
./sqlmap_pro.sh
📋 Main Menu Options
Option	Description
1	Set target URL (and optional cookies)
2	Adjust level & risk (1/1, 3/2, 5/3)
3	Basic detection (technique=BEUST)
4	List databases (--dbs)
5	List tables of a specific database
6	Dump a specific table (e.g., users)
7	Dump all data (--dump-all)
8	Show current database (--current-db)
9	Show current user (--current-user)
10	Attempt to get an OS shell (--os-shell)
11	Extract passwords (--passwords)
12	Advanced full scan (Level 5, Risk 3)
13	Delete previous results
0	Exit
🔧 How It Works
The script constructs SQLMap commands dynamically.

All results are saved in sqlmap_results/.

Cookies are added if provided.

The --batch flag ensures non‑interactive execution.

📂 Script 2: Parametar.sh
🎯 Purpose
Discover hidden parameters, forms, and input fields in web pages, then optionally scan them for SQL injection vulnerabilities.

🚀 Usage
bash
chmod +x Parametar.sh
./Parametar.sh
📋 Main Menu Options
Option	Description
1	Set target URL, cookies, crawl depth, and threads
2	Extract parameters/forms from the page using curl
3	Full crawl scan using sqlmap --crawl
4	Manually scan each discovered link containing parameters
5	Update depth & threads settings
6	Delete scan results (param_scan_results/)
0	Exit
🔧 How It Works
Extraction – Uses curl to fetch the HTML, then parses:

GET links containing ?

<form> tags with action and method

input fields with name attributes

Crawl Scanning – Uses SQLMap’s built‑in --crawl engine to spider the site.

Manual Scanning – Saves all parameterised links to links.txt and optionally scans each one.

🗂️ Output Directories
sqlmap_results/ – All SQLMap output from sqlmap_pro.sh

param_scan_results/ – Output from Parametar.sh (including links.txt)

⚠️ Important Warnings
Legal Use Only – These scripts are for educational purposes and authorized security assessments.

Ethical Responsibility – Do not use on any system without explicit written permission.

Data Sensitivity – Dumping databases may expose sensitive information (PII, credentials, etc.). Handle with care.

No Warranty – The authors are not responsible for any misuse or damage caused by these tools.

📝 Example Workflow
🔎 Using sqlmap_pro.sh
bash
# 1. Launch the script
./sqlmap_pro.sh

# 2. Set target (option 1)
> http://example.com/page.php?id=1

# 3. Set level/risk (option 2, e.g., 3/2)

# 4. List databases (option 4)

# 5. Dump a table (option 6) – enter database name and table name
🔍 Using Parametar.sh
bash
# 1. Launch the script
./Parametar.sh

# 2. Set target (option 1) – e.g., http://example.com

# 3. Extract parameters manually (option 2)

# 4. Run full crawl scan (option 3) – this uses SQLMap to find all injection points

# 5. Optionally, scan each discovered link (option 4)
