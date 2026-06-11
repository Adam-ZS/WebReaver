# 🕷️ WebReaver — Web App Auto-Pwn

> *Automated web application penetration testing & data extraction*

WebReaver is a single-script web application security scanner that automates the full web recon-to-exploit chain. Point it at a domain and it hunts sensitive files, tests SQL injection, discovers admin panels, brute-forces basic auth, and extracts credentials.

**Ideal for:** Bug bounty recon, penetration testing engagements, CTF web challenges.

---

## Features

| Module | What it does |
|--------|-------------|
| **Alive Check + Tech Detection** | Probes target, detects server stack (PHP, Python, ASP.NET) |
| **Sensitive File Hunter** | 40+ paths: `.env`, `.git/config`, `wp-config.php`, `composer.json`, `phpinfo.php`, backups, config dumps |
| **Admin Panel Discovery** | 14 common admin paths + basic auth brute force (20 credential pairs) |
| **SQLi Detection** | Error-based + time-based blind injection testing |
| **Secret Extraction** | Regex scanner for emails, passwords, API keys, DB creds, AWS keys, JWTs |
| **Report Generation** | JSON + HTML reports with all findings |

---

## Quick Start

```bash
# Clone or download the single file
git clone https://github.com/Adam-ZS/webreaver
cd webreaver

# Make executable
chmod +x webreaver.py

# Run against a target
python3 webreaver.py http://target.com

# Deep scan (more SQLi payloads)
python3 webreaver.py http://target.com --deep

# Through Tor
python3 webreaver.py http://target.com --proxy socks5://127.0.0.1:9050

# Custom thread count
python3 webreaver.py http://target.com --threads 20
```

---

## CLI Options

```
usage: webreaver.py [-h] [--threads THREADS] [--proxy PROXY]
                    [--output OUTPUT] [--deep]
                    target

positional arguments:
  target              Target URL (e.g. http://example.com)

optional arguments:
  --threads THREADS   Thread count (default: 10)
  --proxy PROXY       Proxy (e.g. socks5://127.0.0.1:9050)
  --output OUTPUT     Output directory
  --deep              Deep scan (more SQLi payloads)
```

---

## Example Output

```
  ╔═══════════════════════════════════════════════╗
  ║                                               ║
  ║    __        ___    ______                    ║
  ║    \ \      / / \  |  _ \    /\               ║
  ║     \ \    / / _ \ | |_) |  /  \     Web      ║
  ║      \ \  / / ___ \|  _ <  / /\ \    Reaver   ║
  ║       \ \/ /_/   \_\_| \_\/_/  \_\           ║
  ║                                               ║
  ║          Web App Auto-Exploit v1.0.0          ║
  ║               by Adam-ZS                      ║
  ║                                               ║
  ╚═══════════════════════════════════════════════╝

  ═══════════════════════════════════════════════════
  WebReaver Scan — http://target.com
  ═══════════════════════════════════════════════════

  [1/5] Checking target...
  ✔ Target is alive (200)
    Server: Apache/2.4.41

  [2/5] Hunting sensitive files...
  200 .env
      → email: admin@target.com
      → password: DB_PASSWORD=SuperSecret123
  200 .git/config
  200 robots.txt
  ✔ Found 3 files

  [3/5] Finding admin panels...
  200 admin/
  200 admin/ → CRACKED: Basic: admin/admin123

  [4/5] Testing SQL injection...
  ✔ SQLi on id (error-based)

  [5/5] Extracting data...
  ✔ Saved 12 secrets
      email: 4
      password: 3
      db_host: 2
      api_key: 1
```

---

## Use Cases

- **Bug bounty**: Quick recon on targets before manual testing
- **CTFs**: Auto-detect common web vulns
- **Pentest reports**: Generate HTML reports for client deliverables
- **Initial access**: Find exposed creds and admin panels fast

---

## Requirements

- Python 3.6+
- No external dependencies (stdlib only)

---

## License

MIT

---

## Author

**Adam-ZS** — Wraithe & WebReaver developer
