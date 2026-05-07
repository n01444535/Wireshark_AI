import ipaddress

_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]
_MULTICAST_NETWORK = ipaddress.ip_network("224.0.0.0/4")
_BROADCAST_IPS = {"255.255.255.255", "0.0.0.0"}
_BROADCAST_SUFFIXES = (".255",)

_SEVERITY_BASE = {"HIGH": 55, "MEDIUM": 40, "LOW": 25}

_BENIGN_CAUSES = {
    "Port Scan": [
        "Authorized vulnerability scanner (Nessus, Tenable, Nmap)",
        "Network inventory or asset discovery tool",
        "Software update manager checking multiple endpoints",
        "Printer or network device discovery (mDNS/SSDP broadcast)",
    ],
    "SYN Flood": [
        "Load balancer health check probing multiple backends simultaneously",
        "Automated deployment or smoke test touching many services",
        "Browser pre-connecting to multiple CDN endpoints",
        "Firewall synthetic-monitoring generating SYN traffic",
    ],
    "Lateral Movement": [
        "Backup software scanning file shares across the local subnet",
        "Domain controller replication or Kerberos ticket broadcast",
        "Software deployment agent pushing updates to multiple endpoints",
        "IT asset inventory scan by an authorized admin tool",
    ],
    "Lateral Sweep": [
        "Backup software scanning file shares across the local subnet",
        "Domain controller replication touching multiple hosts",
        "Network monitoring agent polling multiple endpoints",
        "IT asset inventory scan by an authorized admin tool",
    ],
    "ARP Cache Poisoning": [
        "DHCP server issuing a new lease that reuses a MAC address",
        "VM or container restarting with a new IP on the same MAC",
        "Failover cluster moving a virtual IP to a standby node",
        "Duplicate-IP conflict during device migration or reconfiguration",
    ],
    "SSH Brute Force": [
        "CI/CD pipeline retrying SSH key deployment after a failure",
        "Monitoring agent re-establishing a lost SSH tunnel",
        "Developer laptop with stale SSH config retrying the wrong key",
    ],
    "SSH Tunneling": [
        "Authorized remote-access tool using a non-standard port (corporate VPN policy)",
        "Jump-server or bastion forwarding SSH traffic through an alternate port",
        "Developer using port forwarding for local testing",
    ],
    "Cleartext Protocol": [
        "Legacy device that does not support SSH (printer, PLC, OT sensor)",
        "Internal management interface on a non-internet-facing segment",
        "Test or lab environment with a relaxed security policy",
    ],
    "ICS/HMI Web Reconnaissance": [
        "Authorized HMI operator accessing the control panel via web browser",
        "SCADA health-check script polling status endpoints",
        "OT security scanner performing an authorized assessment",
    ],
    "SMB Activity": [
        "Authorized file-share access (user accessing a network drive)",
        "Domain-joined laptop syncing group policy from the DC",
        "Backup agent accessing shared storage for scheduled backup",
        "Antivirus engine scanning shared folders",
    ],
    "RDP Exposure": [
        "IT support session remotely managing a workstation",
        "Developer connecting to a remote build server",
        "Jump-server or bastion host forwarding an RDP session",
    ],
    "ARP Host Discovery": [
        "Network monitoring tool performing routine host-reachability checks",
        "Switch or router refreshing its ARP table after a topology change",
        "Authorized nmap host-discovery scan (-sn flag)",
    ],
    "Possible DDoS": [
        "Load testing tool (JMeter, Locust) running against internal services",
        "Misconfigured application generating a connection storm",
        "Legitimate high-traffic event (software update distribution, backup)",
    ],
}

_DEFAULT_BENIGN_CAUSES = [
    "Scheduled task or automation script generating unusual traffic",
    "Software update or patch distribution in progress",
    "Monitoring or backup agent with atypical connection behaviour",
    "Misconfigured application retrying failed connections",
]


# Return True if the IP string is a private/loopback/link-local address. / Trả True nếu IP là địa chỉ nội bộ/loopback/link-local.
def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        return False


# Return True if the IP is a multicast, broadcast, or well-known noise address. / Trả True nếu IP là địa chỉ multicast, broadcast, hoặc noise đã biết.
def _is_noise_ip(ip_str: str) -> bool:
    if ip_str in _BROADCAST_IPS or any(ip_str.endswith(s) for s in _BROADCAST_SUFFIXES):
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr in _MULTICAST_NETWORK or addr.is_multicast
    except ValueError:
        return False


# Classify a pair of IP lists as a directional traffic category. / Phân loại cặp IP thành nhóm hướng traffic.
def classify_flow_direction(src_ips: list, dst_ips: list) -> str:
    real_srcs = [ip for ip in src_ips if not _is_noise_ip(ip)]
    real_dsts = [ip for ip in dst_ips if not _is_noise_ip(ip)]
    if not real_srcs:
        return "noise"
    src_internal = all(_is_internal(ip) for ip in real_srcs)
    dst_internal = all(_is_internal(ip) for ip in real_dsts) if real_dsts else True
    if src_internal and dst_internal:
        return "internal_to_internal"
    if src_internal and not dst_internal:
        return "internal_to_external"
    if not src_internal and dst_internal:
        return "external_to_internal"
    return "external_to_external"


# Return the list of known benign explanations for the given threat text. / Trả danh sách nguyên nhân lành tính đã biết cho loại threat.
def get_benign_causes(threat_text: str) -> list:
    for prefix, causes in _BENIGN_CAUSES.items():
        if threat_text.startswith(prefix):
            return causes
    return _DEFAULT_BENIGN_CAUSES


# Build a triage checklist pre-filled with what is already known from runtime context. / Tạo checklist triage được điền sẵn ngữ cảnh đã biết.
def build_triage_checklist(
    src_ips: list,
    dst_ips: list,
    features: dict,
    is_allowlisted: bool,
    correlation_count: int,
    flow_direction: str,
) -> list:
    direction_labels = {
        "internal_to_internal": "Internal → Internal",
        "internal_to_external": "Internal → External (outbound)",
        "external_to_internal": "External → Internal (inbound)",
        "noise": "Noise (multicast/broadcast only)",
    }
    direction_hint = direction_labels.get(flow_direction, "Unknown")
    tick = lambda cond: "✓" if cond else " "

    lines = [
        f"  [{tick(flow_direction != 'noise')}] Traffic direction: {direction_hint}",
    ]
    if is_allowlisted:
        lines.append("  [✓] Source is on the authorized-scanner allowlist — severity downgraded")
    else:
        lines.append("  [ ] Verify source is an authorized scanner or known asset")

    unique_dst_ports = int(features.get("unique_dst_ports", 0))
    if unique_dst_ports > 10:
        lines.append(f"  [ ] Determine if destination ports ({unique_dst_ports}) are business-expected")
    else:
        lines.append("  [ ] Confirm destination port is business-expected")

    if correlation_count >= 3:
        lines.append(f"  [✓] Repeated across windows: Yes ({correlation_count} suspicious windows from this source)")
    else:
        lines.append("  [ ] Check if this pattern repeats in adjacent capture windows")

    lines.append("  [ ] Did any destination respond? (check SYN-ACK in pcap)")
    lines.append("  [ ] Cross-reference source IP against SIEM / threat-intel feed")
    return lines


# Compute alert confidence percentage (0–100) and false-positive risk string. / Tính phần trăm độ tin cậy (0–100) và mức rủi ro false positive.
def compute_confidence(
    threat_text: str,
    features: dict,
    baseline_multiples: dict,
    correlation_count: int,
    is_allowlisted: bool,
    touches_critical: bool,
    severity: str,
    flow_direction: str,
) -> tuple:
    score = _SEVERITY_BASE.get(severity, 30)

    syn_ratio = features.get("syn_ratio", 0)
    if syn_ratio > 0.5:
        score += 15
    elif syn_ratio > 0.3:
        score += 8

    unique_dst_ports = int(features.get("unique_dst_ports", 0))
    if unique_dst_ports > 20:
        score += 15
    elif unique_dst_ports > 10:
        score += 8

    mean_pkts = features.get("mean_packets_per_flow", 99)
    if 0 < mean_pkts < 2:
        score += 12
    elif 2 <= mean_pkts < 4:
        score += 5

    arp_max = int(features.get("arp_max_ips_per_mac", 0))
    if arp_max > 2:
        score += 15

    max_multiple = max(baseline_multiples.values(), default=0)
    if max_multiple >= 10:
        score += 15
    elif max_multiple >= 5:
        score += 10
    elif max_multiple >= 2:
        score += 5

    if correlation_count >= 5:
        score += 15
    elif correlation_count >= 3:
        score += 10

    if touches_critical:
        score += 10

    # Threat-type specific signal strength
    if "ARP Cache Poisoning" in threat_text:
        score += 10
    elif "ICS/HMI" in threat_text:
        score += 15
    elif "Cleartext Protocol" in threat_text:
        score += 8

    # FP reducers
    if is_allowlisted:
        score -= 30
    if flow_direction == "noise":
        score -= 25
    elif flow_direction == "internal_to_external" and ("Port Scan" in threat_text or "Lateral" in threat_text):
        # Outbound scanning is slightly less alarming than internal east-west movement
        score -= 5

    confidence = max(10, min(95, score))
    if confidence >= 70:
        fp_risk = "LOW"
    elif confidence >= 45:
        fp_risk = "MEDIUM"
    else:
        fp_risk = "HIGH"

    return confidence, fp_risk
