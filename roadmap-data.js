// ========================================================
// Roadmaps & Career Track Checklist Data
// Progressive Phases and Specialization Paths
// ========================================================

const ROADMAP_PHASES = [
  {
    phaseId: "phase-1",
    phaseTitle: "Phase 1: Networking Foundations",
    badge: "Level 1 - Core",
    description: "Master essential networking models, logical addressing, and core transport mechanisms.",
    skills: [
      { id: "p1-1", title: "OSI 7-Layer Model Architecture & PDU Encapsulation", hours: 10 },
      { id: "p1-2", title: "TCP/IP 4-Layer Suite & Protocol Mapping", hours: 8 },
      { id: "p1-3", title: "IPv4 Addressing, Binary Math, & CIDR Subnetting", hours: 15 },
      { id: "p1-4", title: "MAC Addressing, Switching, and ARP Protocol", hours: 6 },
      { id: "p1-5", title: "TCP 3-Way Handshake & Connection Teardown", hours: 8 },
      { id: "p1-6", title: "UDP vs TCP Protocols and Port Multiplexing", hours: 6 },
      { id: "p1-7", title: "DNS Hierarchy, Record Types (A, AAAA, MX, TXT), and DHCP", hours: 10 }
    ]
  },
  {
    phaseId: "phase-2",
    phaseTitle: "Phase 2: Security Controls & Architecture",
    badge: "Level 2 - Defensive Controls",
    description: "Implement defense boundaries, traffic filtering, and encrypted tunneling.",
    skills: [
      { id: "p2-1", title: "Stateful Packet Inspection Firewalls & iptables/UFW", hours: 12 },
      { id: "p2-2", title: "Network Segmentation: DMZ, VLANs (802.1Q), and Private VLANs", hours: 10 },
      { id: "p2-3", title: "VPN Technologies: IPSec (IKEv2) and OpenVPN / WireGuard", hours: 12 },
      { id: "p2-4", title: "Intrusion Detection & Prevention (Snort & Suricata)", hours: 14 },
      { id: "p2-5", title: "TLS/SSL Cryptography, Public Key Infrastructure (PKI), & Certificates", hours: 12 },
      { id: "p2-6", title: "Zero Trust Architecture (NIST SP 800-207) Implementation", hours: 10 }
    ]
  },
  {
    phaseId: "phase-3",
    phaseTitle: "Phase 3: Traffic Analysis & Monitoring",
    badge: "Level 3 - SOC & Telemetry",
    description: "Capture live traffic, analyze raw packets, and configure SIEM log telemetry.",
    skills: [
      { id: "p3-1", title: "Packet Sniffing with Wireshark & Advanced Display Filters", hours: 15 },
      { id: "p3-2", title: "Command-Line Traffic Capture with tcpdump and Tshark", hours: 10 },
      { id: "p3-3", title: "Network Reconnaissance & Vulnerability Scanning with Nmap", hours: 12 },
      { id: "p3-4", title: "Log Aggregation & Centralization (Syslog, ELK, Splunk)", hours: 15 },
      { id: "p3-5", title: "Analyzing Firewall, Proxy, and DNS Resolver Logs", hours: 12 },
      { id: "p3-6", title: "NetFlow & IPFIX Traffic Behavioral Profiling", hours: 10 }
    ]
  },
  {
    phaseId: "phase-4",
    phaseTitle: "Phase 4: Threat Detection & Incident Response",
    badge: "Level 4 - Advanced Blue Team",
    description: "Identify live network attacks, hunt malicious actors, and triage security incidents.",
    skills: [
      { id: "p4-1", title: "Detecting DDoS Floods, MitM Attacks, & ARP Spoofing", hours: 12 },
      { id: "p4-2", title: "Malware Command & Control (C2) Traffic Analysis & Beaconing", hours: 15 },
      { id: "p4-3", title: "DNS Exfiltration & Covert ICMP Tunneling Identification", hours: 12 },
      { id: "p4-4", title: "Writing Custom Snort & Suricata Signatures", hours: 15 },
      { id: "p4-5", title: "SIEM Correlation Rule Creation & Alert Triage", hours: 18 },
      { id: "p4-6", title: "Network Forensics & PCAP Artifact Extraction", hours: 16 }
    ]
  }
];

const CAREER_TRACKS = [
  {
    role: "SOC Analyst (Security Operations Center)",
    summary: "Monitors enterprise telemetry, analyzes intrusion alerts, investigates suspicious network traffic, and initiates tier-1/tier-2 incident response.",
    keyTools: ["Wireshark", "Splunk / Elastic SIEM", "Suricata", "Zeek", "VirusTotal", "CyberChef"],
    certifications: ["CompTIA Security+", "Cisco CyberOps Associate", "BTL1 (Blue Team Level 1)"],
    avgSalary: "$75,000 - $115,000 / year"
  },
  {
    role: "Penetration Tester (Ethical Hacker)",
    summary: "Simulates adversary tactics to identify exploitable vulnerabilities across network infrastructure, wireless systems, and web applications.",
    keyTools: ["Nmap", "Metasploit", "Burp Suite Pro", "Wireshark", "Responder", "Hydra"],
    certifications: ["eJPT", "OSCP (Offensive Security Certified Professional)", "PNPT"],
    avgSalary: "$95,000 - $150,000 / year"
  },
  {
    role: "Network Security Engineer",
    summary: "Architects and maintains secure network topologies, deploys NGFWs, configures VPN tunnels, manages 802.1X NAC, and enforces zero-trust segmentation.",
    keyTools: ["Palo Alto / Fortinet NGFW", "Cisco ASA", "WireGuard", "Snort", "SolarWinds"],
    certifications: ["CCNA / CCNP Security", "Palo Alto PCNSE", "Fortinet NSE 4-7"],
    avgSalary: "$100,000 - $160,000 / year"
  },
  {
    role: "Threat Intelligence Analyst",
    summary: "Tracks cyber adversary groups (APTs), correlates indicators of compromise (IOCs), maps tactics to MITRE ATT&CK, and produces strategic intelligence reports.",
    keyTools: ["MISP", "OpenCTI", "Shodan", "Maltego", "YARA", "ThreatConnect"],
    certifications: ["CTIA (Certified Threat Intelligence Analyst)", "SANS GCTI"],
    avgSalary: "$90,000 - $145,000 / year"
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { ROADMAP_PHASES, CAREER_TRACKS };
}
