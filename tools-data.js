// ========================================================
// Tools Database & Reference Engine
// Common Ports, Hashes, Subnet Specs, Wireshark Filters
// ========================================================

const COMMON_PORTS_DATABASE = [
  {
    port: 21,
    service: "FTP",
    transport: "TCP",
    severity: "High",
    description: "File Transfer Protocol. Sends authentication credentials in plaintext.",
    risks: "Anonymous login, plaintext credential sniffing, brute force.",
    remediation: "Disable plain FTP. Migrate to SFTP (port 22) or FTPS."
  },
  {
    port: 22,
    service: "SSH",
    transport: "TCP",
    severity: "Medium",
    description: "Secure Shell. Encrypted remote administration interface.",
    risks: "Brute-force credential guessing, compromised private keys, vulnerable OpenSSH versions.",
    remediation: "Disable password auth, use SSH keys, change port, implement Fail2ban."
  },
  {
    port: 23,
    service: "Telnet",
    transport: "TCP",
    severity: "Critical",
    description: "Legacy unencrypted remote terminal communication.",
    risks: "All commands, usernames, and passwords sent in plaintext over the wire.",
    remediation: "Immediately deprecate and replace with SSH. Block port 23 on all firewalls."
  },
  {
    port: 25,
    service: "SMTP",
    transport: "TCP",
    severity: "Medium",
    description: "Simple Mail Transfer Protocol used for mail routing.",
    risks: "Open mail relay, email spoofing, spam distribution, STARTTLS stripping.",
    remediation: "Disable open relaying, implement SPF, DKIM, DMARC, and require authentication on submission ports (587)."
  },
  {
    port: 53,
    service: "DNS",
    transport: "UDP/TCP",
    severity: "Medium",
    description: "Domain Name System resolution.",
    risks: "DNS cache poisoning, DNS amplification DDoS reflection, DNS tunneling exfiltration.",
    remediation: "Deploy DNSSEC, restrict open recursive resolution, enable response rate limiting (RRL)."
  },
  {
    port: 80,
    service: "HTTP",
    transport: "TCP",
    severity: "High",
    description: "Hypertext Transfer Protocol. Insecure web communications.",
    risks: "Session hijacking, plaintext eavesdropping, MitM content injection.",
    remediation: "Redirect all traffic to HTTPS (port 443) and enforce HSTS."
  },
  {
    port: 110,
    service: "POP3",
    transport: "TCP",
    severity: "High",
    description: "Post Office Protocol for retrieving email.",
    risks: "Cleartext credentials, unauthorized email download.",
    remediation: "Migrate to POP3S (port 995 with TLS) or IMAPS (port 993)."
  },
  {
    port: 135,
    service: "MS RPC",
    transport: "TCP",
    severity: "Critical",
    description: "Microsoft Remote Procedure Call endpoint mapper.",
    risks: "Remote code execution, network reconnaissance, lateral movement.",
    remediation: "Never expose port 135 to the internet. Restrict to domain controller VLAN."
  },
  {
    port: 139,
    service: "NetBIOS",
    transport: "TCP",
    severity: "High",
    description: "NetBIOS Session Service used for legacy Windows file and printer sharing.",
    risks: "SMB relay attacks, anonymous user enumeration, password hash harvesting.",
    remediation: "Disable NetBIOS over TCP/IP in network adapter settings."
  },
  {
    port: 143,
    service: "IMAP",
    transport: "TCP",
    severity: "High",
    description: "Internet Message Access Protocol for email sync.",
    risks: "Plaintext credentials and mailbox inspection.",
    remediation: "Enforce IMAPS over TLS on port 993."
  },
  {
    port: 161,
    service: "SNMP",
    transport: "UDP",
    severity: "High",
    description: "Simple Network Management Protocol.",
    risks: "Cleartext community strings ('public'/'private'), network topology disclosure.",
    remediation: "Upgrade to SNMPv3 with authPriv (AES encryption). Block from untrusted networks."
  },
  {
    port: 389,
    service: "LDAP",
    transport: "TCP/UDP",
    severity: "High",
    description: "Lightweight Directory Access Protocol for enterprise directory queries.",
    risks: "Plaintext credential transmission, user enumeration, LDAP injection.",
    remediation: "Mandate LDAPS (port 636) with TLS or StartTLS."
  },
  {
    port: 443,
    service: "HTTPS",
    transport: "TCP",
    severity: "Low",
    description: "HTTP Secure over TLS/SSL.",
    risks: "Weak TLS ciphers, expired certificates, hidden malicious web payloads.",
    remediation: "Enforce TLS 1.3, configure WAF, use A+ SSL Labs configuration."
  },
  {
    port: 445,
    service: "SMB",
    transport: "TCP",
    severity: "Critical",
    description: "Server Message Block for file sharing and IPC.",
    risks: "EternalBlue (MS17-010), ransomware propagation, NTLM relay attacks.",
    remediation: "Disable SMBv1. Block port 445 inbound on all edge firewalls. Require SMB signing."
  },
  {
    port: 1433,
    service: "MSSQL",
    transport: "TCP",
    severity: "Critical",
    description: "Microsoft SQL Server database engine.",
    risks: "Brute force against 'sa' account, SQL injection, OS command execution (`xp_cmdshell`).",
    remediation: "Isolate behind firewall. Never bind to public IP. Disable 'sa' account."
  },
  {
    port: 1521,
    service: "Oracle DB",
    transport: "TCP",
    severity: "Critical",
    description: "Oracle Database TNS Listener.",
    risks: "TNS poisoning, default DBA passwords, unauthorized schema access.",
    remediation: "Bind to localhost/private IP only. Enforce Oracle Network Encryption."
  },
  {
    port: 3306,
    service: "MySQL",
    transport: "TCP",
    severity: "Critical",
    description: "MySQL database server.",
    risks: "Root brute force, unauthorized database dumps, remote privilege escalation.",
    remediation: "Set `bind-address = 127.0.0.1`. Disable remote root login. Enforce TLS."
  },
  {
    port: 3389,
    service: "RDP",
    transport: "TCP/UDP",
    severity: "Critical",
    description: "Microsoft Remote Desktop Protocol.",
    risks: "BlueKeep (CVE-2019-0708), brute force attacks, ransomware entry vector.",
    remediation: "Never expose directly to Internet. Require VPN, MFA, and Network Level Authentication (NLA)."
  },
  {
    port: 5432,
    service: "PostgreSQL",
    transport: "TCP",
    severity: "Critical",
    description: "PostgreSQL relational database.",
    risks: "Credential brute force, unauthorized data exfiltration.",
    remediation: "Configure `pg_hba.conf` to allow specific internal IPs only. Require SCRAM-SHA-256."
  },
  {
    port: 5900,
    service: "VNC",
    transport: "TCP",
    severity: "Critical",
    description: "Virtual Network Computing remote desktop.",
    risks: "Weak 8-character DES password limits, no built-in encryption in standard VNC.",
    remediation: "Tunnel VNC sessions exclusively over SSH or VPN. Enable TLS encryption."
  },
  {
    port: 6379,
    service: "Redis",
    transport: "TCP",
    severity: "Critical",
    description: "Redis in-memory key-value database.",
    risks: "No authentication by default in legacy setups; allows arbitrary file write leading to root SSH key injection.",
    remediation: "Require strong password (`requirepass`), disable dangerous commands (`CONFIG`, `FLUSHALL`), bind to localhost."
  },
  {
    port: 8080,
    service: "HTTP-Proxy / Alt",
    transport: "TCP",
    severity: "Medium",
    description: "Alternate HTTP web server or proxy port (e.g. Tomcat, Jenkins, Spring Boot).",
    risks: "Unauthenticated developer admin dashboards, default vendor passwords.",
    remediation: "Apply authentication, restrict access via IP allowlists, run behind reverse proxy with TLS."
  }
];

const WIRESHARK_FILTERS_CATALOG = [
  {
    category: "HTTP Traffic",
    name: "HTTP Requests Only",
    syntax: "http.request",
    description: "Displays only packets containing client HTTP request methods (GET, POST, PUT, DELETE)."
  },
  {
    category: "HTTP Traffic",
    name: "Filter by HTTP Status Code (4xx / 5xx)",
    syntax: "http.response.code >= 400",
    description: "Identifies client-side errors (403, 404) and internal server errors (500, 502)."
  },
  {
    category: "DNS Analysis",
    name: "DNS Queries for Suspicious Domains",
    syntax: "dns.flags.response == 0",
    description: "Isolates outgoing DNS queries before receiving response answers."
  },
  {
    category: "DNS Analysis",
    name: "DNS Non-Existent Domain (NXDomain) Errors",
    syntax: "dns.flags.rcode == 3",
    description: "Detects DGA (Domain Generation Algorithm) malware botnet beaconing."
  },
  {
    category: "TCP & Connection Health",
    name: "TCP SYN Packets (Scanning & DoS)",
    syntax: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    description: "Finds initial connection handshakes; excessive rates indicate SYN flooding or port scanning."
  },
  {
    category: "TCP & Connection Health",
    name: "TCP Reset (RST) Packets",
    syntax: "tcp.flags.reset == 1",
    description: "Highlights dropped or rejected connections, closed ports, or TCP RST injection attacks."
  },
  {
    category: "ARP & Local Network",
    name: "Duplicate IP Detection / Gratuitous ARP",
    syntax: "arp.duplicate-address-detected || arp.opcode == 2",
    description: "Flags ARP spoofing and IP conflict anomalies on local LAN broadcast domains."
  },
  {
    category: "Security & TLS",
    name: "TLS Client Hello (SNI Inspection)",
    syntax: "tls.handshake.type == 1",
    description: "Inspects initial TLS negotiation and SNI (Server Name Indication) domain names."
  },
  {
    category: "Security & TLS",
    name: "Plaintext Credential Searches",
    syntax: "frame contains \"password\" || frame contains \"USER\"",
    description: "Searches raw unencrypted payloads for plain authentication strings."
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    COMMON_PORTS_DATABASE,
    WIRESHARK_FILTERS_CATALOG
  };
}
