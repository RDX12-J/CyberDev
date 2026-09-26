// ========================================================
// Practical Interactive Labs Data & Scenarios
// Labs 1 through 7 with interactive states and datasets
// ========================================================

const LABS_DATA = [
  {
    id: "lab-1",
    number: 1,
    title: "Packet Capture & Wireshark Filter Simulator",
    badge: "Traffic Analysis",
    objective: "Analyze a simulated packet stream, apply display filters, and isolate unencrypted credentials and DNS anomalies.",
    instructions: "Filter the packet stream using Wireshark syntax (e.g., `http`, `dns`, `tcp`, `arp`). Click on any packet row to inspect its detailed headers and payload.",
    packets: [
      { id: 1, time: "0.000", src: "192.168.1.50", dst: "192.168.1.1", proto: "ARP", len: 42, info: "Who has 192.168.1.1? Tell 192.168.1.50", payload: "Hardware type: Ethernet, Protocol type: IPv4, Sender MAC: 00:0c:29:1f:2a:3b" },
      { id: 2, time: "0.002", src: "192.168.1.1", dst: "192.168.1.50", proto: "ARP", len: 42, info: "192.168.1.1 is at 00:50:56:c0:00:08", payload: "ARP Reply: 192.168.1.1 is at 00:50:56:c0:00:08" },
      { id: 3, time: "0.015", src: "192.168.1.50", dst: "8.8.8.8", proto: "DNS", len: 74, info: "Standard query 0x12a4 A api.internal-portal.corp", payload: "DNS Query: api.internal-portal.corp, Type: A, Class: IN" },
      { id: 4, time: "0.028", src: "8.8.8.8", dst: "192.168.1.50", proto: "DNS", len: 90, info: "Standard query response 0x12a4 A 192.168.1.200", payload: "DNS Answer: api.internal-portal.corp A 192.168.1.200 (TTL 300)" },
      { id: 5, time: "0.035", src: "192.168.1.50", dst: "192.168.1.200", proto: "TCP", len: 66, info: "54231 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460", payload: "TCP SYN Flags: [SYN] Window: 64240, MSS: 1460" },
      { id: 6, time: "0.038", src: "192.168.1.200", dst: "192.168.1.50", proto: "TCP", len: 66, info: "80 → 54231 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0", payload: "TCP SYN-ACK Flags: [SYN, ACK] Window: 65535" },
      { id: 7, time: "0.040", src: "192.168.1.50", dst: "192.168.1.200", proto: "TCP", len: 54, info: "54231 → 80 [ACK] Seq=1 Ack=1 Win=64240", payload: "TCP ACK Handshake Complete" },
      { id: 8, time: "0.052", src: "192.168.1.50", dst: "192.168.1.200", proto: "HTTP", len: 320, info: "POST /login.php HTTP/1.1 (application/x-www-form-urlencoded)", payload: "POST /login.php HTTP/1.1\\r\\nHost: api.internal-portal.corp\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\n\\r\\nusername=admin&password=P@ssw0rd2026!&token=xyz987" },
      { id: 9, time: "0.065", src: "192.168.1.200", dst: "192.168.1.50", proto: "HTTP", len: 210, info: "HTTP/1.1 200 OK (text/html)", payload: "HTTP/1.1 200 OK\\r\\nSet-Cookie: session_id=dGhpcy1pcy1hLXNlY3JldA==; path=/\\r\\n\\r\\n<html><body>Welcome Admin!</body></html>" },
      { id: 10, time: "0.100", src: "10.0.0.99", dst: "192.168.1.1", proto: "TCP", len: 60, info: "49123 → 22 [SYN] Seq=0 Win=1024 Len=0", payload: "Suspicious SYN Scan probe on port 22 from external IP" }
    ]
  },
  {
    id: "lab-2",
    number: 2,
    title: "Network Reconnaissance & Nmap Terminal Sandbox",
    badge: "Recon & Scanning",
    objective: "Execute realistic Nmap scans in a simulated terminal environment to enumerate open ports, services, and OS fingerprints.",
    instructions: "Type an nmap command in the interactive terminal prompt. Examples: `nmap -sS 192.168.1.10`, `nmap -sV -p 80,443 192.168.1.25`, `nmap -O 192.168.1.1`, or `help`.",
    presetTargets: {
      "192.168.1.1": {
        os: "Cisco IOS 15.2 (Router)",
        ports: [
          { port: 22, proto: "tcp", state: "open", service: "ssh", version: "Cisco SSH 1.25" },
          { port: 80, proto: "tcp", state: "open", service: "http", version: "Cisco HTTP server 1.0" },
          { port: 443, proto: "tcp", state: "open", service: "https", version: "Cisco HTTPS server" }
        ]
      },
      "192.168.1.10": {
        os: "Ubuntu Linux 22.04 LTS (Kernel 5.15)",
        ports: [
          { port: 22, proto: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9p1 Ubuntu" },
          { port: 80, proto: "tcp", state: "open", service: "http", version: "Apache httpd 2.4.52" },
          { port: 3306, proto: "tcp", state: "open", service: "mysql", version: "MySQL 8.0.35" }
        ]
      },
      "192.168.1.25": {
        os: "Microsoft Windows Server 2019",
        ports: [
          { port: 135, proto: "tcp", state: "open", service: "msrpc", version: "Microsoft Windows RPC" },
          { port: 445, proto: "tcp", state: "open", service: "microsoft-ds", version: "Windows Server 2019 SMB" },
          { port: 3389, proto: "tcp", state: "open", service: "ms-wbt-server", version: "Microsoft Terminal Services" }
        ]
      }
    }
  },
  {
    id: "lab-3",
    number: 3,
    title: "Port Risk Analysis & Attack Surface Explorer",
    badge: "Risk Assessment",
    objective: "Assess port vulnerabilities across 3 enterprise server profiles, evaluate cumulative risk scores, and apply hardening patches.",
    nodes: [
      {
        id: "node-web",
        name: "Public DMZ Web Host",
        ip: "203.0.113.15",
        role: "Production E-Commerce Web Server",
        baselineRisk: "High (Score: 82/100)",
        ports: [
          { port: 80, service: "HTTP", status: "Vulnerable", risk: "Plaintext credentials transmitted", patch: "Enforce HTTPS 443 & 301 Redirect" },
          { port: 21, service: "FTP", status: "Critical", risk: "Plaintext legacy file upload", patch: "Disable FTP; migrate to SFTP" },
          { port: 22, service: "SSH", status: "Medium", risk: "Password auth enabled on root", patch: "Enforce SSH Keys & PermitRootLogin=no" }
        ]
      },
      {
        id: "node-db",
        name: "Internal Database Server",
        ip: "10.0.50.4",
        role: "Customer Records Database",
        baselineRisk: "Critical (Score: 94/100)",
        ports: [
          { port: 3306, service: "MySQL", status: "Critical", risk: "Publicly accessible on 0.0.0.0", patch: "Bind to 127.0.0.1 and restrict to app server" },
          { port: 3389, service: "RDP", status: "High", risk: "RDP exposed without MFA", patch: "Isolate behind VPN with MFA" }
        ]
      }
    ]
  },
  {
    id: "lab-4",
    number: 4,
    title: "Firewall Testing & Rule Simulator",
    badge: "Defensive Controls",
    objective: "Configure stateful packet filtering rules and simulate live traffic packets to verify allow/deny filtering outcomes.",
    defaultRules: [
      { id: 1, action: "DENY", protocol: "TCP", src: "0.0.0.0/0", dstPort: 23, description: "Block legacy Telnet" },
      { id: 2, action: "ALLOW", protocol: "TCP", src: "192.168.1.0/24", dstPort: 22, description: "Allow internal subnet SSH" },
      { id: 3, action: "ALLOW", protocol: "TCP", src: "0.0.0.0/0", dstPort: 443, description: "Allow public HTTPS" },
      { id: 4, action: "DENY", protocol: "TCP", src: "0.0.0.0/0", dstPort: 445, description: "Block SMB from Internet" },
      { id: 5, action: "DENY", protocol: "ALL", src: "0.0.0.0/0", dstPort: 0, description: "Default Deny All" }
    ]
  },
  {
    id: "lab-5",
    number: 5,
    title: "DNS Query & Poisoning Analysis",
    badge: "Protocol Security",
    objective: "Compare normal recursive DNS resolution flow against Kaminsky cache poisoning and observe traffic redirection.",
    steps: {
      legitimate: [
        { step: 1, actor: "Client", target: "Local Resolver (192.168.1.1)", msg: "Query: bank.com A record" },
        { step: 2, actor: "Local Resolver", target: "Root Server (.)", msg: "Query: bank.com -> Refers to .com TLD" },
        { step: 3, actor: "Local Resolver", target: "TLD Server (.com)", msg: "Query: bank.com -> Refers to ns1.bank.com" },
        { step: 4, actor: "Local Resolver", target: "Authoritative (ns1.bank.com)", msg: "Query: bank.com -> Answer: 198.51.100.25 (Legitimate IP)" },
        { step: 5, actor: "Local Resolver", target: "Client", msg: "Resolved: bank.com -> 198.51.100.25" }
      ],
      poisoned: [
        { step: 1, actor: "Attacker", target: "Local Resolver", msg: "Generates flood of spoofed queries: sub01.bank.com, sub02.bank.com..." },
        { step: 2, actor: "Attacker", target: "Local Resolver", msg: "Injects guessed Transaction ID + Authority Section: bank.com NS ns.attacker.com (Attacker IP: 203.0.113.66)" },
        { step: 3, actor: "Local Resolver", target: "Cache", msg: "Cache Poisoned! Resolver accepts fake NS record without DNSSEC" },
        { step: 4, actor: "Victim Client", target: "Local Resolver", msg: "Query: bank.com -> Returned Rogue IP 203.0.113.66 (Phishing Server!)" }
      ]
    }
  },
  {
    id: "lab-6",
    number: 6,
    title: "Traffic Pattern & DoS Detection Simulator",
    badge: "SOC Monitoring",
    objective: "Monitor real-time network traffic telemetry, detect abnormal bandwidth and packet rate anomalies, and deploy mitigation.",
    baselineBps: "45 Mbps",
    baselinePps: "3,200 pps",
    attackProfiles: [
      { name: "Normal Enterprise Traffic", bps: 45, pps: 3200, status: "Normal", alert: "Traffic within normal baseline thresholds." },
      { name: "SYN Flood Attack", bps: 380, pps: 98000, status: "CRITICAL ALERT", alert: "High-rate SYN packet spike detected without ACK responses. Backlog buffer saturation!" },
      { name: "DNS Amplification Flood", bps: 1200, pps: 145000, status: "CRITICAL ALERT", alert: "Volumetric UDP flood on port 53 originating from spoofed reflector IPs. Pipe saturation!" }
    ]
  },
  {
    id: "lab-7",
    number: 7,
    title: "SOC Incident Log Investigation & Triage",
    badge: "Incident Response",
    objective: "Review multi-source server and firewall logs, correlate threat indicators (IOCs), identify the compromised account and attack vector, and compile an incident triage report.",
    logs: [
      { id: 101, timestamp: "2026-09-26 20:14:02", source: "auth.log", ip: "198.51.100.77", event: "Failed password for root from 198.51.100.77 port 41234 ssh2", severity: "Warning" },
      { id: 102, timestamp: "2026-09-26 20:14:05", source: "auth.log", ip: "198.51.100.77", event: "Failed password for admin from 198.51.100.77 port 41235 ssh2", severity: "Warning" },
      { id: 103, timestamp: "2026-09-26 20:14:09", source: "auth.log", ip: "198.51.100.77", event: "Failed password for test from 198.51.100.77 port 41236 ssh2", severity: "Warning" },
      { id: 104, timestamp: "2026-09-26 20:14:14", source: "auth.log", ip: "198.51.100.77", event: "Accepted password for deploy_user from 198.51.100.77 port 41238 ssh2", severity: "Critical" },
      { id: 105, timestamp: "2026-09-26 20:15:30", source: "apache_access.log", ip: "198.51.100.77", event: "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1 200", severity: "Critical" },
      { id: 106, timestamp: "2026-09-26 20:16:01", source: "iptables.log", ip: "192.168.1.15", event: "OUTBOUND_CONN: 192.168.1.15:45210 -> 203.0.113.99:4444 [SYN] - Potential Reverse Shell", severity: "Emergency" }
    ],
    triageQuestions: [
      {
        question: "Which external IP address performed the SSH brute-force attack?",
        correctAnswer: "198.51.100.77"
      },
      {
        question: "Which user account was successfully compromised via SSH?",
        correctAnswer: "deploy_user"
      },
      {
        question: "What web vulnerability was exploited in Apache access logs?",
        correctAnswer: "SQL Injection"
      }
    ]
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { LABS_DATA };
}
