# Cybersecurity & Networking Master Platform 🛡️

A comprehensive, interactive, production-ready **Cybersecurity & Networking Master Platform & Security Tool Suite** designed for security analysts, penetration testers, network defenders, and SOC engineers.

Built with pure vanilla HTML5, modern CSS3 (responsive 320px to 1920px), and modular ES6 JavaScript. Zero external dependencies required. 100% offline-ready.

---

## 🌟 Key Architecture & Modules

### 1. 📡 Protocols & Networking Models
- **OSI 7-Layer Architecture**: Deep security breakdown of each layer (Physical, Data Link, Network, Transport, Session, Presentation, Application), Protocol Data Units (PDUs), active attack vectors, and defensive controls.
- **TCP/IP 4-Layer Mapping**: Direct comparison and encapsulation mapping.
- **Comprehensive Protocols Directory**: 20+ protocols (HTTP, HTTPS, DNS, SSH, ARP, TCP, UDP, DHCP, ICMP, FTP, SFTP, IPSec, SMTP, SNMP, RDP, SMB, etc.) with default ports, transport types, vulnerabilities, hardening configurations, and Wireshark filter syntax.

### 2. 🛡️ Defensive Engineering & Architecture
- **Firewall Comparison**: Packet Filtering vs. Stateful Inspection vs. WAF vs. NGFW with syntax examples.
- **Intrusion Detection & Prevention (IDS / IPS)**: Passive vs. inline modes, Snort/Suricata rules, and signature vs. anomaly detection.
- **Network Segmentation**: DMZ, Corporate Internal, Secure Database, and Out-of-Band Management (OOBM) zones.
- **Zero Trust Architecture (ZTA)**: NIST SP 800-207 core pillars (Verify Explicitly, Least Privilege, Assume Breach).
- **Defense in Depth**: 5-layer layered security model.

### 3. ⚡ Attacks & Exploits Hub
- **Network Attacks**: DDoS (SYN floods, UDP amplification, HTTP Slowloris), Man-in-the-Middle (MitM), ARP Cache Poisoning, DNS Cache Poisoning (Kaminsky attack), Packet Sniffing, and Port Scanning reconnaissance.
- **Web Application Exploits**: Cross-Site Scripting (XSS), SQL Injection (SQLi), Cross-Site Request Forgery (CSRF), Server-Side Request Forgery (SSRF), and OWASP Top 10 vulnerabilities with attack mechanisms and defensive coding rules.

### 4. 🛠️ Interactive Cybersecurity Tool Suite (Tested per Section D)
Each tool handles valid, invalid, empty, and boundary inputs, and includes 1-click Copy, Reset, and Download:
1. **Subnet & CIDR Calculator**: Computes network, broadcast, netmask, wildcard mask, usable IP range, host count, and binary representations.
2. **Cryptographic Hash Generator & Analyzer**: Computes MD5, SHA-1, SHA-256, and Shannon entropy in pure JS.
3. **Port & Threat Surface Scanner**: Inspects ports 1-65535 or service names (SSH, FTP, SMB, etc.) for threat severity and hardening steps.
4. **Password Entropy & Crack Estimator**: Calculates character pool diversity, bits of entropy, and crack time across online vs. offline GPU attack scenarios.
5. **Security Payload Encoder / Decoder**: Base64, Hexadecimal, URL encoding, and ROT13 cipher.
6. **Firewall & ACL Rule Builder**: Generates syntax for Cisco IOS Extended ACLs, Linux `iptables`, and Ubuntu `ufw`.
7. **IPv4 & TCP Packet Header Inspector**: Interactive bit-field layout with live TCP flags (SYN, ACK, FIN, RST).
8. **Wireshark Display Filter Builder**: Quick filter builder for packet analysis.

### 5. 🔬 7 Hands-on Interactive SOC Labs
1. **Lab 1: Packet Capture & Wireshark Filter Simulator**: Filter simulated packet streams and inspect raw payloads.
2. **Lab 2: Network Reconnaissance & Nmap Terminal Sandbox**: Interactive bash terminal running realistic `nmap` commands.
3. **Lab 3: Port Risk Analysis & Attack Surface Explorer**: Evaluate server vulnerability scores and apply hardening patches.
4. **Lab 4: Firewall Testing & Rule Simulator**: Transmit test packets through firewall rules to verify allow/deny logic.
5. **Lab 5: DNS Query & Poisoning Analysis**: Compare normal recursive queries against spoofed cache poisoning.
6. **Lab 6: Traffic Pattern & DoS Detection**: Monitor bandwidth telemetry and trigger alerts for volumetric anomalies.
7. **Lab 7: SOC Incident Log Investigation**: Multi-source log correlation (Apache, auth.log, iptables) with incident reporting.

### 6. 🗺️ Career Roadmaps & Progress Tracking
- 4 progressive phases: Foundations, Security Controls, Traffic Monitoring, Threat Detection.
- Interactive checkboxes with persistent progress saving in `localStorage`.
- Career profiles for SOC Analyst, Penetration Tester, Network Security Engineer, and Threat Intelligence Analyst.

### 7. 📖 Glossary & Abbreviation Engine
- Viewport-clamped tooltips for all essential acronyms: **IP, MAC, ARP, DNS, DHCP, TCP, UDP, HTTP, HTTPS, SSH, VPN, XSS, CSRF, SSRF, OSINT, SOC, SIEM, IDS, IPS, API, JWT**.
- Instant search and category filter.

---

## 🚀 How to Run the Website

### Option 1: Direct File Launch
Double click `index.html` or open in any web browser:
```powershell
Start-Process "C:\Users\Dhankhar\.gemini\antigravity\scratch\cybersecurity-portal\index.html"
```

### Option 2: Local HTTP Server (Recommended)
Run a local development server on port 8080:
```powershell
cd "C:\Users\Dhankhar\.gemini\antigravity\scratch\cybersecurity-portal"
node -e "const http=require('http'),fs=require('fs'),path=require('path');http.createServer((q,s)=>{let p=q.url.split('?')[0];if(p==='/')p='/index.html';let f=path.join('.',p);if(fs.existsSync(f)&&fs.statSync(f).isFile()){s.writeHead(200,{'Content-Type':f.endsWith('.html')?'text/html':(f.endsWith('.css')?'text/css':'application/javascript')});s.end(fs.readFileSync(f));}else{s.writeHead(404);s.end('Not Found');}}).listen(8080,()=>console.log('Server running at http://localhost:8080'));"
```
Or with Python:
```powershell
cd "C:\Users\Dhankhar\.gemini\antigravity\scratch\cybersecurity-portal"
python -m http.server 8080
```
Open in browser: [http://localhost:8080](http://localhost:8080)

---

## 🧪 Automated Testing & Verification

Run the comprehensive test suite (the test server automatically selects a free local port):
```powershell
cd "C:\Users\Dhankhar\.gemini\antigravity\scratch\cybersecurity-portal"
node test/run_all_tests.js
```

### Test Coverage Highlights:
- Automated assertions cover file integrity, interactive tools, search, glossary, responsive CSS, HTTP serving, and browser rendering. The exact count is reported by the test runner after each run.
- **All 8 Tools** tested across Valid, Invalid, Empty, Boundary inputs, Copy, Reset, and Download.
- **Global Search** tested for all mandatory terms: `ARP`, `DNS`, `TCP`, `UDP`, `XSS`, `SQL Injection`, `Nmap`, `Wireshark`, `Linux`, `OWASP`, `HTTP`, `VPN`, `SSH`.
- **Abbreviation Tooltips** tested across all 21 mandatory acronyms with mobile/desktop viewport clamping.
- **Static Security Review** verified: Zero `eval()`, zero `Function()`, zero hardcoded credentials.
- **Headless Browser Execution**: Microsoft Edge headless rendered 126,620 characters of DOM without runtime errors.


## Final QA Notes
- Static GitHub Pages compatible: no backend, database, build step, or package install required.
- Interactive features are browser-local wherever possible.
- External resources are limited to trusted primary/official documentation links and use `noopener noreferrer`.
- Reduced-motion support and keyboard skip navigation are included.
- Automated test suite should be run with `node test/run_all_tests.js`.
- Do not interpret a successful local test run as a guarantee of complete browser compatibility; verify the final deployment in current desktop and mobile browsers.
