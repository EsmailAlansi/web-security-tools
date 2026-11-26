# Bug Bounty & Reconnaissance Methodology

> **Disclaimer:**
> This guide is intended strictly for authorized security assessments, penetration testing, and educational purposes. Always ensure you have explicit permission before scanning or testing any target.

---

## Phase 0: Environment Setup

Setting up a clean, structured workspace and installing the core suite of open-source reconnaissance tools (Go and Rust based).

### 1. Directory Structure

```bash
mkdir -p ~/recon/{subs,http,urls,scans,js}
cd ~/recon
```

### 2. Core Tools Installation (Go)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/anew@latest
```

### 3. Installing Feroxbuster (Rust)

```bash
cargo install feroxbuster
# Or via the official installation script:
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
```

> **Pro Tip:**
> Configure API keys for `subfinder` inside `~/.config/subfinder/provider-config.yaml` (Shodan, Censys, SecurityTrails, VirusTotal, GitHub, etc.). This significantly differentiates shallow enumeration from deep, professional asset discovery.

---

## Phase 1: Layered Subdomain Enumeration

Never rely on a single tool or technique. Combine **Passive**, **Active**, and **Permutation** methods for maximum attack surface coverage.

### 1. Passive Enumeration (Public Sources)

```bash
DOMAIN="target.com"

subfinder -d $DOMAIN -all -recursive -o subs/subfinder.txt
assetfinder --subs-only $DOMAIN > subs/assetfinder.txt
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs/crtsh.txt
amass enum -passive -d $DOMAIN -o subs/amass.txt   # If installed
```

### 2. Active Enumeration (DNS Resolution & Brute-force)

```bash
# Combine and resolve live domains using dnsx
cat subs/*.txt | sort -u > subs/all_raw.txt
dnsx -l subs/all_raw.txt -a -resp -o subs/resolved.txt

# Active DNS brute-forcing using strong wordlists
puredns bruteforce /path/to/wordlist.txt $DOMAIN -r resolvers.txt -w subs/brute.txt
```

### 3. Permutation Scanning

```bash
# Using dnsgen or altdns to generate and resolve similar subdomain permutations
cat subs/resolved.txt | awk '{print $1}' | dnsgen - | dnsx -silent -a -o subs/permutated.txt
```

### 4. Final Deduplication & Cleaning

```bash
cat subs/*.txt | awk '{print $1}' | sed 's/\*\.//g' | tr 'A-Z' 'a-z' | sort -u > subs/final.txt
wc -l subs/final.txt
```

---

## Phase 2: HTTP Probing

Identify active web servers, underlying technologies, HTTP status codes, TLS details, and CDN protections.

```bash
# Comprehensive probing with httpx
httpx -l subs/final.txt \
  -ports 80,443,8080,8443,8000,8888,9000,3000,5000 \
  -threads 100 \
  -title -tech-detect -status-code -content-length -web-server \
  -follow-redirects -cdn -tls-grab \
  -o http/httpx_full.txt

# Extract live URLs with relevant status codes
grep -E "\[200\]|\[301\]|\[302\]|\[401\]|\[403\]" http/httpx_full.txt | awk '{print $1}' > http/live.txt
```

> **Pro Tip:**
> Isolate subdomains sitting behind CDNs (e.g., Cloudflare, Akamai) tagged by `httpx` as `[cloudflare]`, as they often mask the origin server and require specialized origin-discovery techniques.

---

## Phase 3: Port Scanning

Discover non-standard open ports and exposed services across the infrastructure.

```bash
# Fast top-1000 port scan across all discovered subdomains
naabu -l subs/final.txt -top-ports 1000 -rate 1000 -o scans/ports.txt

# Deep full-port scan on confirmed live hosts
naabu -list http/live.txt -p - -rate 500 -o scans/allports.txt
```

---

## Phase 4: URLs, Parameters & JS Analysis

Gather historical endpoints, crawl live web applications, and extract sensitive data or hidden routes from JavaScript files.

### 1. Archival & Active Crawling

```bash
# Historical URLs from web archives
cat http/live.txt | waybackurls > urls/wayback.txt
cat http/live.txt | gau --threads 10 > urls/gau.txt

# Active Crawling
katana -list http/live.txt -d 5 -jc -kf all -o urls/katana.txt

# Merge and normalize URLs
cat urls/*.txt | sed 's/:80//;s/:443//' | sort -u > urls/all.txt
```

### 2. Filtering Endpoints & Parameters

```bash
# Extract URLs with parameters (Critical for XSS, SQLi, SSRF, Open Redirect)
cat urls/all.txt | grep "=" | sort -u > urls/params.txt

# Extract API endpoints
cat urls/all.txt | grep -Ei "\.(json|xml|api)|/api/|/v[0-9]/" > urls/api.txt

# Extract JavaScript file URLs
cat urls/all.txt | grep -E "\.js($|\?)" | sort -u > js/js_urls.txt
```

### 3. Extracting Secrets from JS

```bash
# Quick regex scan across collected JS files (Alternatively use SecretFinder or Mantra)
cat js/js_urls.txt | while read u; do
  curl -s "$u" | grep -Eo "(api[_-]?key|token|secret|password|Bearer)[\"'=: ]+[A-Za-z0-9_\-]{16,}"
done
```

---

## Phase 5: Content Discovery (Fuzzing)

### 1. Wordlists Preparation

```bash
mkdir -p ~/wordlists && cd ~/wordlists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
```

### 2. Advanced `feroxbuster` Usage

```bash
# 1) Comprehensive scan with automatic extension detection and link extraction
feroxbuster -u https://target.com \
  -w ~/wordlists/raft-large-directories.txt \
  -t 50 -d 3 \
  -x php,html,js,json,bak,old,zip,txt,xml,env,git,conf,config,log \
  -C 404 -s 200,204,301,302,307,401,403,405,500 \
  -H "User-Agent: Mozilla/5.0" \
  --extract-links --smart \
  -o scans/ferox_target.txt

# 2) Safe scan with auto-tuning and wildcard bailout
feroxbuster -u https://target.com -w ~/wordlists/common.txt \
  --auto-tune --auto-bail -d 2 -o scans/ferox_safe.txt

# 3) Targeted API endpoint fuzzing
feroxbuster -u https://target.com/api/ -w ~/wordlists/api-endpoints.txt \
  -t 30 --json -o scans/ferox_api.json

# 4) Batch scanning from a file
feroxbuster --stdin -w ~/wordlists/common.txt \
  -x php,js,json -d 2 --auto-tune < http/live.txt
```

**Key `feroxbuster` Flags:**

* `--auto-tune`: Automatically adjusts scan rate upon encountering `429` or `503` responses (crucial for WAF evasion).
* `--smart`: Reduces redundant requests by analyzing directory structures.
* `-s 403,401`: Monitor forbidden/unauthorized responses closely; they often indicate valid restricted paths.
* `--dont-filter`: Use if you suspect wildcard filtering is hiding valid results.
* `--scan-limit`: Safely distribute load when scanning multiple targets concurrently.

---

## Phase 6: Vulnerability Scanning with Nuclei

```bash
# Daily template updates
nuclei -update -update-templates

# Fast general scan (Technologies, Misconfigurations, Exposures)
nuclei -l http/live.txt -severity critical,high,medium \
  -t http/technologies/ -t http/misconfiguration/ -t http/exposures/ \
  -o scans/nuclei_general.txt -stats

# Targeted CVE scan
nuclei -l http/live.txt -t http/cves/ -severity critical,high \
  -o scans/nuclei_cve.txt -rate-limit 150

# Comprehensive automatic scan
nuclei -l http/live.txt -as -severity critical,high,medium \
  -o scans/nuclei_all.txt -timeout 10 -retries 1

# Scanning newly discovered endpoints from feroxbuster
nuclei -l scans/ferox_target.txt -t http/default-logins/ -t http/exposures/ \
  -o scans/nuclei_ferox.txt
```

> **Custom Templates:**
> Writing custom Nuclei YAML templates for specific patterns or newly discovered edge cases is vastly faster than manual testing. Study `nuclei-templates/http/exposures/configs/` for reference.

---

## Phase 7: Essential Supplementary Tools

| Tool | Category | Description |
| :--- | :--- | :--- |
| **amass** | Subdomain Enum | Advanced passive & active attack surface mapping |
| **puredns** | DNS Resolution | Fast DNS brute-forcing with accurate wildcard handling |
| **shuffledns** | DNS Resolution | Wrapper around massdns for active brute-forcing |
| **dalfox** | XSS Scanner | Fast parameter-based & DOM XSS scanner |
| **sqlmap** | SQL Injection | Automated SQL injection detection and exploitation |
| **ffuf** | Web Fuzzer | Fast general-purpose fuzzer (vhosts, params, dirs) |
| **gobuster** | Content Discovery | Lightweight alternative to feroxbuster |
| **arjun** | Parameter Discovery | Discovers hidden HTTP parameters |
| **paramspider** | Parameter Mining | Extracts parameters from web archives |
| **gf + patterns** | Pattern Matching | Filters URLs by vulnerability class (`ssrf`, `xss`, `redirect`) |
| **trufflehog / gitleaks** | Secret Scanning | Scans repositories and JS files for leaked credentials |
| **LinkFinder / xnLinkFinder** | JS Analysis | Extracts endpoints and parameters from JavaScript |
| **mantra** | Secret Scanning | Hunts down API keys inside JS files |
| **subjack / subzy** | Takeover | Detects Subdomain Takeover vulnerabilities |
| **interactsh** | OOB Testing | Out-of-Band interaction server (SSRF, Blind XSS) |
| **waymore** | Archival Mining | Comprehensive archive URL & response downloader |

### Quick Usage Examples

```bash
# XSS scanning on extracted parameters
cat urls/params.txt | dalfox pipe --mining-dom --deep-domxss -o scans/xss.txt

# Hidden parameter discovery
arjun -u https://target.com/api/endpoint -m GET,POST -o scans/arjun.json

# Subdomain takeover verification
subzy run --targets subs/final.txt --hide_fails

# Filtering URLs by vulnerability pattern using gf
cat urls/all.txt | gf ssrf > urls/ssrf_candidates.txt
cat urls/all.txt | gf xss > urls/xss_candidates.txt
cat urls/all.txt | gf redirect > urls/redirect_candidates.txt

# Start Out-of-Band (OOB) listener
interactsh-client -v
```

---

## Phase 8: Automated Recon Skeleton Script

A baseline Bash script to automate the initial reconnaissance workflow. Save as `recon.sh` and run with `chmod +x recon.sh && ./recon.sh target.com`.

```bash
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

DOMAIN=$1
BASE_DIR=~/recon/$DOMAIN

mkdir -p $BASE_DIR/{subs,http,urls,scans,js}
cd $BASE_DIR

echo "[*] Phase 1: Subdomain Enumeration for $DOMAIN..."
subfinder -d $DOMAIN -all -silent | anew subs/subs.txt
assetfinder --subs-only $DOMAIN | anew subs/subs.txt
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew subs/subs.txt

echo "[*] Phase 2: Resolving Live Subdomains..."
dnsx -l subs/subs.txt -silent -a -resp | awk '{print $1}' | anew subs/live_subs.txt

echo "[*] Phase 3: HTTP Probing..."
httpx -l subs/live_subs.txt -silent -ports 80,443,8080,8443 \
  -title -tech-detect -status-code -follow-redirects | anew http/httpx.txt
awk '{print $1}' http/httpx.txt > http/live.txt

echo "[*] Phase 4: Gathering URLs & Crawling..."
cat http/live.txt | waybackurls | anew urls/all.txt
cat http/live.txt | gau --threads 10 | anew urls/all.txt
katana -list http/live.txt -d 3 -jc -silent | anew urls/all.txt

echo "[*] Phase 5: Running Nuclei Vulnerability Scans..."
nuclei -l http/live.txt -severity critical,high,medium -as -o scans/nuclei.txt

echo "[+] Reconnaissance Complete! Reports saved in $BASE_DIR/"
```