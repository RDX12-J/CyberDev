// ========================================================
// Protocols & Networking Architecture Data
// OSI Model, TCP/IP Model, Protocols Deep Catalog
// ========================================================

const OSI_LAYERS_DATA = [
  {
    number: 7,
    name: "Application",
    pdu: "Data",
    summary: "Closest to the end-user. Provides network services directly to software applications.",
    protocols: ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", "DHCP", "SNMP"],
    securityRisks: [
      "Cross-Site Scripting (XSS)",
      "SQL Injection (SQLi)",
      "Server-Side Request Forgery (SSRF)",
      "Malicious payload injection",
      "API parameter tampering"
    ],
    defenseControls: [
      "Web Application Firewall (WAF)",
      "Strict Input Validation & Sanitization",
      "Application authentication & Role-Based Access Control (RBAC)",
      "API rate limiting and OAuth2/JWT verification"
    ],
    packetInspection: "Full payload inspection, HTTP headers, URI decoding, JSON/XML body validation."
  },
  {
    number: 6,
    name: "Presentation",
    pdu: "Data",
    summary: "Handles data formatting, character encoding, compression, and encryption/decryption.",
    protocols: ["TLS/SSL", "MIME", "JPEG", "ASCII", "JSON", "XML"],
    securityRisks: [
      "Weak cipher suites (DES, RC4, 3DES)",
      "SSL Strip / TLS Downgrade attacks",
      "Format string and serialization exploits",
      "Certificate forgery and expired certificates"
    ],
    defenseControls: [
      "Enforce TLS 1.3 / TLS 1.2 with PFS (Perfect Forward Secrecy)",
      "HTTP Strict Transport Security (HSTS)",
      "Certificate pinning and automated revocation checks (OCSP)",
      "Safe serialization libraries"
    ],
    packetInspection: "TLS handshake inspection, SNI (Server Name Indication), cipher suite negotiation."
  },
  {
    number: 5,
    name: "Session",
    pdu: "Data",
    summary: "Establishes, manages, and terminates connections between local and remote applications.",
    protocols: ["NetBIOS", "RPC", "PPTP", "SOCKS", "PAP"],
    securityRisks: [
      "Session Hijacking & Token fixation",
      "RPC unauthorized remote execution",
      "Session replay attacks",
      "Man-in-the-Middle (MitM) session splicing"
    ],
    defenseControls: [
      "Secure, cryptographically random session IDs",
      "Short session timeouts with re-authentication",
      "Binding tokens to IP and user agents",
      "Disabling legacy NetBIOS / SMBv1"
    ],
    packetInspection: "Connection state tracking, session cookie validation, keep-alive monitoring."
  },
  {
    number: 4,
    name: "Transport",
    pdu: "Segment (TCP) / Datagram (UDP)",
    summary: "Provides host-to-host communication, port multiplexing, reliability, flow and error control.",
    protocols: ["TCP", "UDP", "QUIC", "SCTP"],
    securityRisks: [
      "SYN Flood DDoS attacks",
      "TCP connection reset (RST injection)",
      "Port scanning (SYN scan, FIN scan, NULL scan)",
      "UDP amplification reflection floods"
    ],
    defenseControls: [
      "SYN Cookies & TCP rate limiting",
      "Stateful inspection firewalls",
      "Port knocking and stealth port management",
      "Blocking unused UDP reflection ports (e.g., NTP 123, Memcached 11211)"
    ],
    packetInspection: "TCP flags (SYN, ACK, FIN, RST), Sequence numbers, source/destination ports, MSS."
  },
  {
    number: 3,
    name: "Network",
    pdu: "Packet",
    summary: "Controls routing across intermediate routers, logical addressing (IP), and packet fragmentation.",
    protocols: ["IPv4", "IPv6", "ICMP", "IPSec", "BGP", "OSPF"],
    securityRisks: [
      "IP address spoofing",
      "ICMP Smurf and Ping of Death attacks",
      "BGP route hijacking and routing table poisoning",
      "IP fragmentation attacks (Teardrop)"
    ],
    defenseControls: [
      "Ingress/Egress packet filtering (BCP 38)",
      "IPSec tunnels for host-to-host encryption",
      "RPKI (Resource Public Key Infrastructure) for BGP verification",
      "ICMP rate limiting and rate thresholds"
    ],
    packetInspection: "Source IP, Destination IP, TTL (Time To Live), Protocol byte, Fragmentation offsets."
  },
  {
    number: 2,
    name: "Data Link",
    pdu: "Frame",
    summary: "Provides node-to-node data transfer across physical local network segments and handles physical MAC addresses.",
    protocols: ["Ethernet (802.3)", "Wi-Fi (802.11)", "ARP", "PPP", "VLAN (802.1Q)"],
    securityRisks: [
      "ARP Poisoning / ARP Spoofing (MitM)",
      "MAC Flooding (forcing switch into fail-open hub mode)",
      "VLAN Hopping (double tagging attacks)",
      "DHCP Starvation and Rogue DHCP servers"
    ],
    defenseControls: [
      "Dynamic ARP Inspection (DAI)",
      "Port Security (sticky MAC limit on switchports)",
      "DHCP Snooping",
      "Private VLANs (PVLAN) and proper 802.1Q native VLAN tagging"
    ],
    packetInspection: "Source MAC, Destination MAC, EtherType (0x0800 IPv4, 0x0806 ARP), VLAN tags."
  },
  {
    number: 1,
    name: "Physical",
    pdu: "Bit / Signal",
    summary: "Transmits raw unformatted bit streams over physical media (cables, optical fiber, radio frequencies).",
    protocols: ["1000BASE-T", "Fiber Optic", "Wi-Fi RF", "Bluetooth RF", "USB"],
    securityRisks: [
      "Physical wiretapping & fiber tapping",
      "RF jamming and eavesdropping",
      "Rogue hardware implants (Keyloggers, Rubber Ducky)",
      "Unauthorized physical console access"
    ],
    defenseControls: [
      "Physical access control (datacenter badge locks, biometric security)",
      "Tamper-evident seals on rack units",
      "Disabling unused physical RJ45 ports",
      "Faraday cages and RF shielding for high-security facilities"
    ],
    packetInspection: "Signal levels, bit error rate, cable attenuation testing."
  }
];

const TCPIP_MODEL_DATA = [
  {
    layer: "Application Layer",
    osiEquivalent: "Layers 5, 6, 7 (Session, Presentation, Application)",
    protocols: ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", "DHCP", "TLS"],
    description: "Handles high-level protocols, data representation, encryption, and direct user services."
  },
  {
    layer: "Transport Layer",
    osiEquivalent: "Layer 4 (Transport)",
    protocols: ["TCP", "UDP", "QUIC"],
    description: "Provides end-to-end communication, flow control, and port demultiplexing."
  },
  {
    layer: "Internet Layer",
    osiEquivalent: "Layer 3 (Network)",
    protocols: ["IPv4", "IPv6", "ICMP", "IPSec", "ARP"],
    description: "Packages data into IP datagrams and routes packets across independent networks."
  },
  {
    layer: "Network Access Layer",
    osiEquivalent: "Layers 1 & 2 (Physical & Data Link)",
    protocols: ["Ethernet", "Wi-Fi (802.11)", "PPP", "Fiber"],
    description: "Interfaces hardware devices, physical network media, frame framing, and MAC hardware addressing."
  }
];

const PROTOCOLS_CATALOG = [
  {
    id: "http",
    name: "HTTP",
    fullName: "HyperText Transfer Protocol",
    port: 80,
    transport: "TCP",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 7230 / RFC 9110",
    description: "Unencrypted protocol used to transmit web pages, media, and API payloads over the internet.",
    securityStatus: "Insecure (Plaintext)",
    risks: [
      "Data sent in plaintext (passwords, tokens, sessions visible to sniffers)",
      "Susceptible to Man-in-the-Middle (MitM) packet inspection and injection",
      "Vulnerable to credential harvesting over open Wi-Fi"
    ],
    defense: [
      "Enforce mandatory redirect to HTTPS (301 Permanent Redirect)",
      "Enable HSTS (HTTP Strict Transport Security) header",
      "Block plaintext port 80 traffic for sensitive administrative interfaces"
    ],
    wiresharkFilter: "http",
    samplePayload: "GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n"
  },
  {
    id: "https",
    name: "HTTPS",
    fullName: "HyperText Transfer Protocol Secure",
    port: 443,
    transport: "TCP",
    osiLayer: "Application / Presentation (Layers 6 & 7)",
    rfc: "RFC 2818 / RFC 9110",
    description: "HTTP encapsulated within a TLS (Transport Layer Security) encrypted tunnel.",
    securityStatus: "Secure (Encrypted)",
    risks: [
      "Malicious traffic and malware payloads can hide inside encrypted TLS streams",
      "SSL Stripping attacks if HSTS is omitted",
      "Compromised or rogue Certificate Authorities (CAs)"
    ],
    defense: [
      "Deploy TLS 1.3 with forward secrecy (ECDHE)",
      "Implement TLS decryption / inspection proxies in corporate SOC environments",
      "Set HSTS with max-age >= 31536000 and includeSubDomains; preload"
    ],
    wiresharkFilter: "tls.handshake.type == 1 || tcp.port == 443",
    samplePayload: "Client Hello [TLSv1.3] -> Cipher Suites: TLS_AES_256_GCM_SHA384, Server Name: secure.example.com"
  },
  {
    id: "dns",
    name: "DNS",
    fullName: "Domain Name System",
    port: 53,
    transport: "UDP (queries) / TCP (zone transfers & large responses)",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 1035",
    description: "Translates human-friendly domain names (e.g. google.com) into machine-routable IP addresses.",
    securityStatus: "Vulnerable by Default (Plaintext)",
    risks: [
      "DNS Cache Poisoning / Kaminsky attacks redirecting users to phishing IPs",
      "DNS Amplification DDoS (exploiting open recursive resolvers)",
      "DNS Tunneling for data exfiltration and C2 (Command & Control) beacons"
    ],
    defense: [
      "Deploy DNSSEC (DNS Security Extensions) for cryptographic record signing",
      "Adopt encrypted transport: DoH (DNS over HTTPS) and DoT (DNS over TLS)",
      "Configure DNS Response Rate Limiting (RRL) and firewall recursive queries"
    ],
    wiresharkFilter: "dns",
    samplePayload: "Standard query 0x1a2b A c2-server.evilcorp.com -> Answer: 198.51.100.42"
  },
  {
    id: "ssh",
    name: "SSH",
    fullName: "Secure Shell",
    port: 22,
    transport: "TCP",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 4253",
    description: "Cryptographic network protocol for secure command-line login, remote execution, and tunneling.",
    securityStatus: "Secure (Encrypted)",
    risks: [
      "Automated brute-force password dictionary attacks",
      "Compromised private keys without passphrase protection",
      "Unauthorized SSH port-forwarding and pivoting into internal networks"
    ],
    defense: [
      "Disable password authentication (`PasswordAuthentication no`); require Ed25519 keys",
      "Disable direct root login (`PermitRootLogin no`)",
      "Implement Fail2ban or CrowdSec; change default port or restrict via IP allowlist / VPN"
    ],
    wiresharkFilter: "ssh || tcp.port == 22",
    samplePayload: "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2 [Key exchange initiation]"
  },
  {
    id: "arp",
    name: "ARP",
    fullName: "Address Resolution Protocol",
    port: 0,
    transport: "Data Link (Layer 2)",
    osiLayer: "Data Link (Layer 2)",
    rfc: "RFC 826",
    description: "Resolves IPv4 network addresses into hardware MAC addresses on a local Ethernet or Wi-Fi segment.",
    securityStatus: "Insecure (Stateless, No Authentication)",
    risks: [
      "ARP Cache Poisoning / ARP Spoofing (redirects traffic through attacker host)",
      "Enables local Man-in-the-Middle (MitM) eavesdropping and credential theft",
      "Denial of Service by sending bogus ARP replies for the default gateway"
    ],
    defense: [
      "Enable Dynamic ARP Inspection (DAI) on managed switches",
      "Use static ARP bindings on critical servers and gateways",
      "Deploy network monitoring tools (Arpwatch, XArp) to flag gratuitous ARP spikes"
    ],
    wiresharkFilter: "arp",
    samplePayload: "Who has 192.168.1.1? Tell 192.168.1.50 -> Reply: 192.168.1.1 is at aa:bb:cc:dd:ee:ff"
  },
  {
    id: "tcp",
    name: "TCP",
    fullName: "Transmission Control Protocol",
    port: 0,
    transport: "Transport (Layer 4)",
    osiLayer: "Transport (Layer 4)",
    rfc: "RFC 793 / RFC 9293",
    description: "Reliable, connection-oriented transport protocol featuring a 3-way handshake (SYN, SYN-ACK, ACK).",
    securityStatus: "Protocol Layer",
    risks: [
      "TCP SYN Flood attacks filling the server connection backlog queue",
      "TCP Session Hijacking via predictable Initial Sequence Numbers (ISNs)",
      "TCP RST (Reset) packet injection tearing down active sessions"
    ],
    defense: [
      "Enable SYN Cookies (`net.ipv4.tcp_syncookies = 1`) on Linux kernels",
      "Cryptographically random Initial Sequence Number generation",
      "Stateful inspection firewalls verifying valid handshake transitions"
    ],
    wiresharkFilter: "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    samplePayload: "[SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=256 SACK_PERM=1"
  },
  {
    id: "udp",
    name: "UDP",
    fullName: "User Datagram Protocol",
    port: 0,
    transport: "Transport (Layer 4)",
    osiLayer: "Transport (Layer 4)",
    rfc: "RFC 768",
    description: "Connectionless, lightweight, unreliable transport protocol prioritizing speed over delivery guarantee.",
    securityStatus: "Protocol Layer",
    risks: [
      "UDP Flooding DDoS attacks overwhelming host network interfaces",
      "Susceptible to IP source spoofing due to lack of handshake verification",
      "Amplification reflection vectors (DNS, NTP, SNMP, Memcached)"
    ],
    defense: [
      "Upstream ISP BCP 38 anti-spoofing ingress filtering",
      "Rate-limit incoming UDP traffic at perimeter border firewalls",
      "Disable public reflection on open UDP services"
    ],
    wiresharkFilter: "udp",
    samplePayload: "Source Port: 53, Destination Port: 54321, Length: 512, Checksum: 0x4f2a"
  },
  {
    id: "dhcp",
    name: "DHCP",
    fullName: "Dynamic Host Configuration Protocol",
    port: 67,
    transport: "UDP (Server: 67, Client: 68)",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 2131",
    description: "Automatically provisions IP addresses, subnet masks, gateways, and DNS servers to local clients.",
    securityStatus: "Insecure (No Built-in Auth)",
    risks: [
      "DHCP Starvation: Attacker broadcasts thousands of fake MAC requests, exhausting IP pool",
      "Rogue DHCP Server: Attacker responds first, offering malicious DNS and default gateway",
      "Traffic interception through attacker-controlled default gateway routing"
    ],
    defense: [
      "Enable DHCP Snooping on managed network switches",
      "Configure switchport Port Security to limit MAC addresses per interface",
      "Designate trusted uplink switch ports for authorized DHCP servers only"
    ],
    wiresharkFilter: "bootp || dhcp",
    samplePayload: "DHCP Discover -> DHCP Offer [Your IP: 192.168.1.105, Gateway: 192.168.1.1]"
  },
  {
    id: "icmp",
    name: "ICMP",
    fullName: "Internet Control Message Protocol",
    port: 0,
    transport: "Network (Layer 3)",
    osiLayer: "Network (Layer 3)",
    rfc: "RFC 792",
    description: "Error-reporting and diagnostic protocol used by routers and hosts (Ping, Traceroute).",
    securityStatus: "Diagnostic (Abuse Risk)",
    risks: [
      "ICMP Smurf attacks (broadcast ping amplification)",
      "Ping of Death (oversized IP packet crashing unpatched TCP/IP stacks)",
      "ICMP Tunneling for covert communication and data exfiltration",
      "Network reconnaissance through ICMP sweep scans"
    ],
    defense: [
      "Filter ICMP echo-requests at edge perimeters or rate-limit responses",
      "Block ICMP redirect messages (Type 5) which can manipulate routing tables",
      "Inspect payload bytes for covert non-standard ASCII/base64 data"
    ],
    wiresharkFilter: "icmp",
    samplePayload: "Echo (ping) request id=0x0001, seq=1/256, ttl=64 (reply in 2ms)"
  },
  {
    id: "ftp",
    name: "FTP",
    fullName: "File Transfer Protocol",
    port: 21,
    transport: "TCP (Control: 21, Data: 20)",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 959",
    description: "Legacy protocol for transferring files between a client and server.",
    securityStatus: "Legacy / Insecure",
    risks: [
      "Transmits usernames and passwords in cleartext plaintext over the wire",
      "Anonymous login misconfigurations allowing unauthorized file upload/download",
      "FTP bounce attacks (scanning internal ports via the PORT command)"
    ],
    defense: [
      "Deprecate plain FTP immediately in favor of SFTP (SSH) or FTPS (TLS)",
      "Disable anonymous authentication (`anonymous_enable=NO`)",
      "Isolate FTP users in restricted chroot jails if legacy support is mandatory"
    ],
    wiresharkFilter: "ftp || ftp-data",
    samplePayload: "USER admin\\r\\nPASS SuperSecret123\\r\\n230 User logged in, proceed.\\r\\n"
  },
  {
    id: "sftp",
    name: "SFTP",
    fullName: "SSH File Transfer Protocol",
    port: 22,
    transport: "TCP",
    osiLayer: "Application (Layer 7)",
    rfc: "IETF Draft secsh-filexfer",
    description: "Secure alternative to FTP operating entirely over an encrypted SSH connection.",
    securityStatus: "Secure (Encrypted)",
    risks: [
      "Weak server host key algorithms (DSA, RSA < 2048)",
      "Brute-force credential guessing on public port 22",
      "Excessive user write permissions on system directories"
    ],
    defense: [
      "Use SSH public key authentication with passphrases",
      "Configure chroot directories for SFTP users (`ChrootDirectory /data/sftp/%u`)",
      "Restrict commands using `ForceCommand internal-sftp`"
    ],
    wiresharkFilter: "ssh && tcp.port == 22",
    samplePayload: "[Encrypted SSH Payload - SFTP Packet Type SSH_FXP_OPEN]"
  },
  {
    id: "ipsec",
    name: "IPSec",
    fullName: "Internet Protocol Security",
    port: 500,
    transport: "UDP 500 (IKE), UDP 4500 (NAT-T), Protocols 50 (ESP), 51 (AH)",
    osiLayer: "Network (Layer 3)",
    rfc: "RFC 4301",
    description: "Suite of protocols that provides mutual authentication, data confidentiality, and integrity at the IP layer.",
    securityStatus: "Secure (Standard Enterprise VPN)",
    risks: [
      "Weak Pre-Shared Keys (PSKs) susceptible to offline dictionary cracking",
      "Aggressive mode negotiation leaking client hash in IKEv1",
      "Misconfiguration of AH (Authentication Header) failing across NAT routers"
    ],
    defense: [
      "Migrate from IKEv1 to IKEv2",
      "Use strong certificate-based authentication (X.509 PKI) instead of weak PSKs",
      "Enforce AES-256-GCM encryption with SHA-384 and Diffie-Hellman Group 19 or higher"
    ],
    wiresharkFilter: "isakmp || esp",
    samplePayload: "IKEv2 Initiator Request: Security Association, Key Exchange, Nonce"
  },
  {
    id: "smtp",
    name: "SMTP",
    fullName: "Simple Mail Transfer Protocol",
    port: 25,
    transport: "TCP (Plain: 25, Submission: 587, SMTPS: 465)",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 5321",
    description: "Protocol used for transmitting email messages between mail servers across the internet.",
    securityStatus: "Plaintext by Default (Upgraded via STARTTLS)",
    risks: [
      "Email spoofing (forging sender address for phishing & BEC scams)",
      "Open relay misconfiguration enabling spammers to distribute spam",
      "STARTTLS stripping attacks downgrading to plaintext transmission"
    ],
    defense: [
      "Implement SPF (Sender Policy Framework) TXT records",
      "Deploy DKIM (DomainKeys Identified Mail) cryptographic signature verification",
      "Enforce DMARC (p=reject) and MTA-STS for mandatory TLS enforcement"
    ],
    wiresharkFilter: "smtp",
    samplePayload: "HELO mail.victim.com -> MAIL FROM:<ceo@victim.com> -> RCPT TO:<finance@victim.com>"
  },
  {
    id: "snmp",
    name: "SNMP",
    fullName: "Simple Network Management Protocol",
    port: 161,
    transport: "UDP (Agent: 161, Trap: 162)",
    osiLayer: "Application (Layer 7)",
    rfc: "RFC 3411",
    description: "Used by network administrators to monitor and configure switches, routers, and servers.",
    securityStatus: "Insecure (v1/v2c), Secure (v3)",
    risks: [
      "SNMPv1 & v2c transmit community strings (`public`, `private`) in cleartext",
      "Reconnaissance: Attackers query MIB trees to enumerate interfaces, OS versions, routing tables",
      "Write access (`private`) allowing remote reconfiguration of devices"
    ],
    defense: [
      "Disable SNMPv1 and SNMPv2c across the entire fleet",
      "Mandate SNMPv3 with authPriv (SHA authentication + AES encryption)",
      "Restrict SNMP UDP port 161 access strictly to dedicated management VLANs"
    ],
    wiresharkFilter: "snmp",
    samplePayload: "SNMPv2-MAPI: GetRequest-PDU sysDescr.0 community=public"
  },
  {
    id: "rdp",
    name: "RDP",
    fullName: "Remote Desktop Protocol",
    port: 3389,
    transport: "TCP & UDP",
    osiLayer: "Application (Layer 7)",
    rfc: "Proprietary (Microsoft)",
    description: "Proprietary protocol developed by Microsoft to provide a graphical interface to remote computers.",
    securityStatus: "High Risk when exposed directly to the Internet",
    risks: [
      "Brute force attacks and credential stuffing against open port 3389",
      "Critical RCE vulnerabilities (BlueKeep CVE-2019-0708, DejaBlue)",
      "Primary entry vector for enterprise ransomware deployment"
    ],
    defense: [
      "Never expose port 3389 directly to the public Internet",
      "Require VPN or RDP Gateway with MFA (Multi-Factor Authentication)",
      "Enforce Network Level Authentication (NLA) and account lockout policies"
    ],
    wiresharkFilter: "rdp || tcp.port == 3389",
    samplePayload: "T.125 Connection Request [Client-to-Server, NLA Negotiate]"
  },
  {
    id: "smb",
    name: "SMB",
    fullName: "Server Message Block",
    port: 445,
    transport: "TCP",
    osiLayer: "Application (Layer 7)",
    rfc: "MS-SMB2 specification",
    description: "Network file sharing and printer sharing protocol primarily used in Windows enterprise environments.",
    securityStatus: "High Risk (SMBv1 critical hazard)",
    risks: [
      "EternalBlue exploit (WannaCry / NotPetya wormable remote code execution)",
      "NTLM relay attacks and pass-the-hash credential lateral movement",
      "Eavesdropping and tampering on unsigned SMB sessions"
    ],
    defense: [
      "Disable legacy SMBv1 permanently across all domain machines",
      "Block inbound ports 445 and 139 at boundary perimeters",
      "Require SMB signing and SMB encryption (SMBv3) for all internal file shares"
    ],
    wiresharkFilter: "smb2 || tcp.port == 445",
    samplePayload: "SMB2 Negotiate Protocol Request [Dialects: 2.0.2, 2.1, 3.0, 3.1.1]"
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { OSI_LAYERS_DATA, TCPIP_MODEL_DATA, PROTOCOLS_CATALOG };
}
