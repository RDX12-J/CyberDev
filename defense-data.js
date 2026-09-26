// ========================================================
// Network Defense & Architecture Data
// Firewalls, IDS/IPS, Zero Trust, Segmentation, Defense-in-Depth
// ========================================================

const FIREWALL_TYPES_DATA = [
  {
    type: "Packet Filtering Firewall",
    layer: "Layer 3 (Network) & Layer 4 (Transport)",
    operation: "Inspects individual packets in isolation based solely on source/destination IP, port, and protocol flags.",
    pros: ["Extremely fast and minimal latency", "Low resource consumption", "Cost-effective on routers"],
    cons: ["Stateless: cannot correlate packets belonging to an active session", "Vulnerable to IP spoofing and ACK scanning", "Cannot inspect application payload"],
    ruleExample: "iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT"
  },
  {
    type: "Stateful Inspection Firewall",
    layer: "Layers 3, 4 & 5 (Network, Transport, Session)",
    operation: "Tracks active connection states in a dynamic state table. Automatically allows inbound replies matching established outbound connections.",
    pros: ["Prevents unsolicited inbound packets", "Defends against SYN floods and out-of-order scans", "Rich logging of connection lifecycles"],
    cons: ["State table memory exhaustion attacks", "Higher latency than pure packet filtering", "No deep application payload inspection"],
    ruleExample: "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
  },
  {
    type: "Web Application Firewall (WAF)",
    layer: "Layer 7 (Application)",
    operation: "Analyzes HTTP/HTTPS requests and responses specifically looking for web attacks such as SQLi, XSS, CSRF, and path traversal.",
    pros: ["Protects against OWASP Top 10 vulnerabilities", "Virtual patching of zero-days before code fixes", "Custom regex rules for APIs and parameters"],
    cons: ["Requires TLS termination / decryption", "Can cause false positives for complex inputs", "Higher processing overhead"],
    ruleExample: "SecRule ARGS \"@rx select.+from\" \"id:1001,phase:2,deny,status:403,msg:'SQL Injection Attempt'\""
  },
  {
    type: "Next-Generation Firewall (NGFW)",
    layer: "Layers 3 through 7 (All Network & Application Layers)",
    operation: "Combines stateful inspection with deep packet inspection (DPI), integrated IDS/IPS, TLS decryption, and identity-aware user policies.",
    pros: ["Application-level identification (e.g. block BitTorrent even over port 80/443)", "Cloud-delivered threat intelligence and sandboxing", "Centralized enterprise visibility"],
    cons: ["High acquisition and licensing cost", "Performance bottleneck under full DPI load", "Complex policy management"],
    ruleExample: "permit application=salesforce user=marketing_group action=allow inspection=antivirus,ips"
  }
];

const IDS_IPS_DATA = [
  {
    category: "Intrusion Detection System (IDS)",
    mode: "Passive / Out-of-band (SPAN / Tap)",
    action: "Monitors traffic, compares against signatures or baselines, and generates alerts for SOC analysts without modifying packets.",
    tools: ["Snort (Passive Mode)", "Zeek (Bro)", "Suricata (IDS Mode)"],
    bestFor: "Forensic visibility, network telemetry, and non-disruptive monitoring without introducing single points of failure."
  },
  {
    category: "Intrusion Prevention System (IPS)",
    mode: "Inline (In-band)",
    action: "Sits directly in the traffic flow; inspects packets in real time and automatically drops or rejects malicious traffic before it reaches targets.",
    tools: ["Suricata (Inline IPS)", "Snort (Inline DAQ)", "Cisco Firepower"],
    bestFor: "Automated active perimeter protection and blocking known exploit payloads, scans, and brute-force spikes."
  }
];

const SEGMENTATION_ZONES = [
  {
    zone: "DMZ (Demilitarized Zone)",
    trustLevel: "Low / Semi-Trusted",
    purpose: "Houses public-facing services (Web servers, reverse proxies, mail relays, DNS).",
    rules: [
      "Inbound traffic permitted strictly on designated ports (80, 443, 25)",
      "Strictly prohibited from initiating new connections into the Internal Corporate Zone",
      "All administrative access must route through a dedicated Bastion/Jump host with MFA"
    ]
  },
  {
    zone: "Internal Corporate Network",
    trustLevel: "Medium / Internal",
    purpose: "Houses employee workstations, local file shares, and business endpoints.",
    rules: [
      "Outbound internet allowed via egress proxy and content filtering",
      "Lateral movement restricted using host-based firewalls and 802.1X",
      "Isolated from Server and Data zones"
    ]
  },
  {
    zone: "Secure Server & Database Zone",
    trustLevel: "High / Critical",
    purpose: "Houses backend application servers, databases, domain controllers, and ERP engines.",
    rules: [
      "Zero direct Internet ingress or egress allowed",
      "Only whitelisted application servers in the DMZ or App tier can connect via specific database ports (e.g., 5432, 3306)",
      "Continuous database activity monitoring and audit logging"
    ]
  },
  {
    zone: "Management & SOC Zone (OOBM)",
    trustLevel: "Highest / Restricted",
    purpose: "Out-of-Band Management (OOBM) for switches, routers, firewalls, and hypervisor consoles.",
    rules: [
      "Physically or cryptographically isolated VLAN",
      "Strict hardware token MFA required",
      "No routing to public Internet under any circumstances"
    ]
  }
];

const ZERO_TRUST_PRINCIPLES = [
  {
    pillar: "Verify Explicitly",
    description: "Always authenticate and authorize based on all available data points (user identity, device health, location, workload, data classification)."
  },
  {
    pillar: "Use Least Privilege Access",
    description: "Limit user access with Just-In-Time (JIT) and Just-Enough-Access (JEA), risk-based adaptive policies, and data protection."
  },
  {
    pillar: "Assume Breach",
    description: "Minimize blast radius by segmenting access by network, user, devices, and application awareness. Encrypt all sessions end-to-end and utilize analytics to gain visibility."
  }
];

const DEFENSE_IN_DEPTH_LAYERS = [
  {
    level: 1,
    layerName: "Perimeter Security",
    controls: ["Edge Firewalls", "DDoS Mitigation (Cloudflare, Akamai)", "BGP Flowspec", "Border Routers"]
  },
  {
    level: 2,
    layerName: "Network Security",
    controls: ["VLAN Segmentation", "802.1X NAC", "Internal IDS/IPS (Suricata)", "DNS Sinkholing"]
  },
  {
    level: 3,
    layerName: "Endpoint Security",
    controls: ["EDR (CrowdStrike, Defender)", "Host-based Firewalls", "AppLocker / Application Whitelisting", "Disk Encryption (BitLocker)"]
  },
  {
    level: 4,
    layerName: "Application Security",
    controls: ["Web Application Firewall (WAF)", "Secure Coding Standards (OWASP)", "Input Sanitization", "API Gateways & Rate Limiting"]
  },
  {
    level: 5,
    layerName: "Data Security",
    controls: ["AES-256 Encryption at Rest", "TLS 1.3 Encryption in Transit", "DLP (Data Loss Prevention)", "Access Token Rotation"]
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    FIREWALL_TYPES_DATA,
    IDS_IPS_DATA,
    SEGMENTATION_ZONES,
    ZERO_TRUST_PRINCIPLES,
    DEFENSE_IN_DEPTH_LAYERS
  };
}
