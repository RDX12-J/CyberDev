// ========================================================
// Glossary & Abbreviation Engine Data
// Full definitions for mandatory and extended cybersecurity terms
// ========================================================

const GLOSSARY_TERMS = [
  {
    term: "IP",
    fullForm: "Internet Protocol",
    category: "Networking",
    description: "The principal communications protocol in the Internet protocol suite for relaying datagrams across network boundaries (IPv4 and IPv6)."
  },
  {
    term: "MAC",
    fullForm: "Media Access Control",
    category: "Networking",
    description: "A unique 48-bit physical identifier assigned to a network interface controller (NIC) for communications at the data link layer of a network segment."
  },
  {
    term: "ARP",
    fullForm: "Address Resolution Protocol",
    category: "Networking",
    description: "Protocol used to dynamically discover the hardware MAC address associated with a given IPv4 address on a local area network."
  },
  {
    term: "DNS",
    fullForm: "Domain Name System",
    category: "Networking",
    description: "Hierarchical and decentralized naming system that translates human-readable domain names into numerical IP addresses."
  },
  {
    term: "DHCP",
    fullForm: "Dynamic Host Configuration Protocol",
    category: "Networking",
    description: "Network management protocol used to automatically assign IP addresses, default gateways, and DNS server parameters to devices on an IP network."
  },
  {
    term: "TCP",
    fullForm: "Transmission Control Protocol",
    category: "Networking",
    description: "Connection-oriented transport layer protocol that provides reliable, ordered, and error-checked delivery of a stream of octets between applications."
  },
  {
    term: "UDP",
    fullForm: "User Datagram Protocol",
    category: "Networking",
    description: "Lightweight, connectionless transport layer protocol suitable for applications prioritizing low latency over error-correction or guaranteed delivery."
  },
  {
    term: "HTTP",
    fullForm: "HyperText Transfer Protocol",
    category: "Networking",
    description: "Application-layer protocol for transmitting hypermedia documents. Transmits data in unencrypted plaintext over TCP port 80."
  },
  {
    term: "HTTPS",
    fullForm: "HyperText Transfer Protocol Secure",
    category: "Networking",
    description: "Encrypted version of HTTP utilizing Transport Layer Security (TLS) over TCP port 443 to secure data integrity and confidentiality."
  },
  {
    term: "SSH",
    fullForm: "Secure Shell",
    category: "Defensive Security",
    description: "Cryptographic network protocol for operating network services securely over an unsecured network, typical for remote command-line login (port 22)."
  },
  {
    term: "VPN",
    fullForm: "Virtual Private Network",
    category: "Defensive Security",
    description: "Encrypted connection over the Internet from a device to a network, creating a secure tunnel that protects sensitive corporate traffic."
  },
  {
    term: "XSS",
    fullForm: "Cross-Site Scripting",
    category: "Offensive Security",
    description: "Client-side code injection attack where an adversary executes malicious scripts in a legitimate web browser by injecting code into trusted web pages."
  },
  {
    term: "CSRF",
    fullForm: "Cross-Site Request Forgery",
    category: "Offensive Security",
    description: "Attack that tricks an authenticated user into executing unwanted state-changing actions on a trusted web application without their awareness."
  },
  {
    term: "SSRF",
    fullForm: "Server-Side Request Forgery",
    category: "Offensive Security",
    description: "Web vulnerability where an attacker coerces the backend application server into making HTTP requests to internal or external unauthorized resources."
  },
  {
    term: "OSINT",
    fullForm: "Open Source Intelligence",
    category: "Operations",
    description: "The practice of collecting, analyzing, and synthesizing publicly available information to identify threat vectors or intelligence targets."
  },
  {
    term: "SOC",
    fullForm: "Security Operations Center",
    category: "Operations",
    description: "A centralized command facility within an enterprise where information security teams continuously monitor, detect, analyze, and respond to cybersecurity incidents."
  },
  {
    term: "SIEM",
    fullForm: "Security Information and Event Management",
    category: "Operations",
    description: "Software solution that aggregates log data and telemetry from across an organization's IT infrastructure to provide real-time correlation and threat detection."
  },
  {
    term: "IDS",
    fullForm: "Intrusion Detection System",
    category: "Defensive Security",
    description: "A hardware device or software application that monitors network or system activities for malicious activities or policy violations and produces alerts."
  },
  {
    term: "IPS",
    fullForm: "Intrusion Prevention System",
    category: "Defensive Security",
    description: "A network security appliance positioned inline that inspects network traffic flows to detect and automatically drop or block malicious exploit attempts."
  },
  {
    term: "API",
    fullForm: "Application Programming Interface",
    category: "Networking",
    description: "A set of protocols, routines, and tools for building software and applications, facilitating structured data interchange between distinct systems."
  },
  {
    term: "JWT",
    fullForm: "JSON Web Token",
    category: "Identity & Cryptography",
    description: "An open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting claims between parties as a JSON object, digitally signed using HMAC or RSA/ECDSA."
  },
  {
    term: "WAF",
    fullForm: "Web Application Firewall",
    category: "Defensive Security",
    description: "A reverse proxy security solution that filters, monitors, and blocks HTTP traffic to and from a web application, stopping OWASP Top 10 exploits."
  },
  {
    term: "CVE",
    fullForm: "Common Vulnerabilities and Exposures",
    category: "Operations",
    description: "A dictionary of publicly disclosed cybersecurity vulnerabilities and exposures maintained by MITRE."
  },
  {
    term: "CVSS",
    fullForm: "Common Vulnerability Scoring System",
    category: "Operations",
    description: "An open industry standard for assessing the severity of computer system security vulnerabilities on a scale from 0.0 to 10.0."
  },
  {
    term: "EDR",
    fullForm: "Endpoint Detection and Response",
    category: "Defensive Security",
    description: "An integrated endpoint security solution that combines real-time continuous monitoring and collection of endpoint data with rules-based automated response."
  },
  {
    term: "DLP",
    fullForm: "Data Loss Prevention",
    category: "Defensive Security",
    description: "Tools and practices designed to ensure that sensitive corporate data is not lost, misused, or accessed by unauthorized users."
  },
  {
    term: "DDoS",
    fullForm: "Distributed Denial of Service",
    category: "Offensive Security",
    description: "A cyber attack in which multiple compromised computer systems flood a target's resources or bandwidth, causing complete denial of service."
  },
  {
    term: "TLS",
    fullForm: "Transport Layer Security",
    category: "Identity & Cryptography",
    description: "The successor to SSL; a cryptographic protocol designed to provide end-to-end communication security and privacy over a computer network."
  },
  {
    term: "SSL",
    fullForm: "Secure Sockets Layer",
    category: "Identity & Cryptography",
    description: "A deprecated cryptographic protocol that pioneered encrypted network communications before being superseded by modern TLS standards."
  },
  {
    term: "MITM",
    fullForm: "Man-in-the-Middle",
    category: "Offensive Security",
    description: "An attack where the adversary secretly relays and possibly alters the communications between two parties who believe they are directly talking to each other."
  },
  {
    term: "NAC",
    fullForm: "Network Access Control",
    category: "Defensive Security",
    description: "Computer networking security technology that enforces policy compliance and identity verification (e.g. 802.1X) before granting device connectivity."
  },
  {
    term: "DMZ",
    fullForm: "Demilitarized Zone",
    category: "Defensive Security",
    description: "A physical or logical subnetwork that contains and exposes an organization's external-facing services to an untrusted network, typically the Internet."
  },
  {
    term: "PAM",
    fullForm: "Privileged Access Management",
    category: "Identity & Cryptography",
    description: "Cybersecurity strategies and technologies for exerting control and audit over elevated ('privileged') enterprise accounts and access credentials."
  },
  {
    term: "IAM",
    fullForm: "Identity and Access Management",
    category: "Identity & Cryptography",
    description: "Framework of business processes, policies, and technologies that facilitates the management of electronic or digital identities."
  },
  {
    term: "IOC",
    fullForm: "Indicator of Compromise",
    category: "Operations",
    description: "Pieces of forensic data (hashes, malicious IPs, domain names) that suggest a network or host has been compromised by a security threat."
  },
  {
    term: "RCE",
    fullForm: "Remote Code Execution",
    category: "Offensive Security",
    description: "A critical security flaw that allows an attacker to execute arbitrary malicious code or commands on a remote server across a network."
  },
  {
    term: "SOAR",
    fullForm: "Security Orchestration, Automation, and Response",
    category: "Operations",
    description: "Technologies that enable organizations to collect inputs monitored by security operations teams and automatically execute incident response playbooks."
  },
  {
    term: "ZTA",
    fullForm: "Zero Trust Architecture",
    category: "Defensive Security",
    description: "A cybersecurity paradigm centered on the belief that organizations should not automatically trust anything inside or outside its perimeters."
  },
  {
    term: "Nmap",
    fullForm: "Network Mapper",
    category: "Operations",
    description: "Industry-standard open-source network scanner for network discovery, port scanning, OS detection, and vulnerability reconnaissance."
  },
  {
    term: "Linux",
    fullForm: "Linux Operating System & Security Kernel",
    category: "Operations",
    description: "Open-source Unix-like operating system kernel forming the foundation for security distributions (Kali Linux), firewalls (iptables, nftables), and enterprise servers."
  },
  {
    term: "Wireshark",
    fullForm: "Wireshark Network Packet Analyzer",
    category: "Operations",
    description: "Leading open-source packet analysis and network protocol inspection tool used for troubleshooting and deep traffic forensics."
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { GLOSSARY_TERMS };
}
