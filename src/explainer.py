import threading

from src.triage import get_mitre_id

_NEXT_STEPS = {
    "SYN Flood": [
        "Apply filter: tcp.flags.syn==1 && tcp.flags.ack==0  to isolate all SYN packets",
        "Identify the source IP — verify it is a known, authorized device",
        "Check whether targeted services (web, SSH, DNS) are still responding",
        "Block or rate-limit the source IP at the firewall if SYN rate exceeds policy",
        "Look for follow-up exploit attempts in the same window — SYN flood often precedes intrusion",
    ],
    "Port Scan": [
        "Apply filter: ip.src==<src>  to review all ports probed by this host",
        "Verify the source IP is an authorized scanner (Nessus, Nmap, Tenable, etc.)",
        "Check if any probed ports sent a response — a real response means a live service is exposed",
        "Look for follow-up connections to open ports within the next 60 seconds",
        "Cross-reference the source IP against your authorized asset inventory",
    ],
    "ARP Cache Poisoning": [
        "Apply filter: arp  to identify the MAC claiming multiple IP addresses",
        "Check if a legitimate device recently changed its IP (DHCP renewal can look similar)",
        "Inspect ARP tables on affected hosts: run  arp -a  on each endpoint",
        "Isolate the suspect MAC from the network switch immediately if confirmed",
        "Look for unexpected TLS certificate warnings or HTTPS errors — sign of active MiTM",
    ],
    "Lateral Movement": [
        "Apply filter: ip.src==<src>  to map all destination IPs reached by this host",
        "Cross-reference destination IPs against your asset list — flag domain controllers, databases, file servers",
        "Check for SMB, RDP, or SSH sessions to sensitive hosts immediately after the sweep",
        "Correlate with Windows Event Log (Event IDs 4624, 4625, 4648) on contacted hosts",
        "Determine if the source host was itself compromised — investigate inbound connections to it first",
    ],
    "SSH Brute Force": [
        "Apply filter: tcp.dstport==22 && tcp.flags.syn==1  to count connection attempts per source",
        "Check SSH auth logs on the target host: /var/log/auth.log or /var/log/secure",
        "Verify no successful login occurred after the brute force window (Event ID 4624 or SSH log)",
        "Block or throttle the source IP — consider fail2ban or similar auto-block tool",
        "Rotate SSH credentials and consider moving SSH to a non-standard port or key-only auth",
    ],
    "RDP Exposure": [
        "Apply filter: tcp.port==3389  to identify all RDP clients and servers in this window",
        "Verify RDP access to this host is authorized — RDP should not be exposed to the internet",
        "Review Windows Event Log: Event ID 4624 (success) and 4625 (failure) for login attempts",
        "Consider restricting RDP access through VPN gateway only",
        "Look for follow-up lateral movement if credentials may have been obtained",
    ],
    "SMB Activity": [
        "Apply filter: tcp.port==445  to review all SMB endpoints",
        "Identify source and destination — confirm this is a known file server interaction",
        "Review Event ID 5140 (share access) and 5145 (file access) on the target",
        "Check whether multiple SMB shares were accessed — ransomware staging often scans all shares",
        "Look for NTLM or Kerberos ticket requests around the same timestamp",
    ],
    "Cleartext Protocol": [
        "Apply filter: telnet  to capture the full session content",
        "Review session for credential exposure — any username/password in cleartext",
        "Identify both endpoints and disable Telnet service immediately on the source device",
        "Replace Telnet with SSH on all affected devices — no exceptions in a security-conscious environment",
        "Alert on any future Telnet detection as a policy violation",
    ],
    "ICS/HMI Web Reconnaissance": [
        "Apply filter: http && http.request.uri  to review all accessed HMI endpoints",
        "Verify source IP is an authorized engineering workstation — all others are suspect",
        "Review accessed URIs against your ICS endpoint whitelist",
        "Check HMI access logs for unusual commands, configuration reads, or setpoint changes",
        "Escalate to the OT/ICS security team immediately — HMI recon often precedes sabotage",
    ],
    "Possible DDoS": [
        "Apply filter: tcp.flags.syn==1 && tcp.flags.ack==0  and group by ip.src",
        "Determine if attack is distributed (many sources) or single-source (use Statistics > Endpoints)",
        "Verify the targeted service is still responding to legitimate traffic",
        "Engage upstream ISP or cloud DDoS mitigation provider if attack is sustained",
        "Review ingress ACLs — apply SYN rate-limiting per source at the firewall",
    ],
    "Statistical Anomaly": [
        "Apply the Wireshark filter from the alert to isolate the time window",
        "Compare traffic visually against a known-good baseline capture from the same time of day",
        "Check whether the anomaly aligns with a scheduled task, backup job, or patch push",
        "Review the top flows — look for unusually large transfers or communication with new endpoints",
        "If no benign explanation is found, treat as unconfirmed threat and escalate for manual review",
    ],
}

# Fallback when no known threat prefix matches — treat the window as a generic ML anomaly. / Dùng khi không khớp prefix nào — xử lý như anomaly ML chung.
_DEFAULT_NEXT_STEPS = _NEXT_STEPS["Statistical Anomaly"]


# Select the analyst action list whose threat prefix matches the given threat text. / Chọn danh sách hành động phân tích theo prefix threat khớp với text.
def _get_next_steps(threat_text: str) -> list:
    for prefix, steps in _NEXT_STEPS.items():
        if threat_text.startswith(prefix):
            return steps
    return _DEFAULT_NEXT_STEPS


# Extract human-readable reasons from feature values to explain why this window was flagged. / Trích xuất lý do dễ đọc từ feature để giải thích tại sao window bị gắn cờ.
def _build_why_reasons(threat_text: str, features: dict, severity: str) -> list:
    reasons = []
    syn_ratio = features.get("syn_ratio", 0)
    unique_dst_ips = int(features.get("unique_dst_ips", 0))
    unique_dst_ports = int(features.get("unique_dst_ports", 0))
    packets = int(features.get("packets", 0))
    mean_pkts = features.get("mean_packets_per_flow", 0)
    arp_grat = features.get("arp_gratuitous_ratio", 0)
    arp_max = int(features.get("arp_max_ips_per_mac", 0))

    if syn_ratio > 0.3:
        reasons.append(f"SYN ratio {syn_ratio:.2f} — unusually high TCP connection initiation rate")
    if unique_dst_ips > 5:
        reasons.append(f"{unique_dst_ips} unique destination IPs — traffic fanning out to many hosts")
    if unique_dst_ports > 10:
        reasons.append(f"{unique_dst_ports} destination ports probed — automated service discovery sweep")
    if 0 < mean_pkts < 3:
        reasons.append(f"Average {mean_pkts:.1f} packets/flow — short-lived connections typical of scanning")
    if arp_grat > 0.05:
        reasons.append(f"Gratuitous ARP ratio {arp_grat:.2f} — possible ARP cache poisoning in progress")
    if arp_max > 1:
        reasons.append(f"One MAC claiming {arp_max} different IPs — classic MiTM indicator")
    if packets > 500:
        reasons.append(f"High packet volume: {packets} packets in one window")

    if not reasons:
        reasons.append(f"ML anomaly score outside learned baseline — severity classified as {severity}")

    return reasons


# Thread-safe indexed store of suspicious alert dicts, enabling explain alert N lookups. / Lưu trữ alert theo chỉ số thread-safe, hỗ trợ lệnh explain alert N.
class AlertStore:

    def __init__(self):
        self._lock = threading.Lock()
        self._alerts: list = []

    # Append an alert dict and return its 1-based index. / Thêm alert dict và trả về chỉ số 1-based.
    def add(self, alert: dict) -> int:
        with self._lock:
            self._alerts.append(alert)
            return len(self._alerts)

    # Return the alert at the given 1-based index, or None if out of range. / Trả về alert tại chỉ số 1-based, hoặc None nếu ngoài phạm vi.
    def get(self, one_based_index: int):
        with self._lock:
            if 1 <= one_based_index <= len(self._alerts):
                return self._alerts[one_based_index - 1]
            return None

    # Return the total number of stored alerts. / Trả về tổng số alert đã lưu.
    def count(self) -> int:
        with self._lock:
            return len(self._alerts)

    # Return a shallow copy of all stored alert dicts. / Trả về bản sao nông của tất cả alert đã lưu.
    def all(self) -> list:
        with self._lock:
            return list(self._alerts)


# Format a full human-readable explanation for a stored alert, including confidence, benign causes, triage checklist, and analyst next steps. / Định dạng giải thích đầy đủ cho alert, bao gồm confidence, nguyên nhân lành tính, checklist triage, và hành động khuyến nghị.
def explain_alert(alert: dict, sanitizer=None) -> str:
    from src.intelligence import ranked_flow_to_filter
    from src.confidence import get_benign_causes, build_triage_checklist

    threat = alert.get("threat", "Unknown")
    severity = alert.get("severity", "LOW")
    mitre_id = alert.get("mitre_id", "") or get_mitre_id(threat)
    window_time = alert.get("window_time", "")
    features = alert.get("features", {})
    flows = alert.get("flows", [])
    baseline_multiples = alert.get("baseline_multiples", {})
    correlation_count = alert.get("correlation_count", 0)
    confidence = alert.get("confidence")
    fp_risk = alert.get("fp_risk")
    stored_checklist = alert.get("triage_checklist")
    flow_direction = alert.get("flow_direction", "unknown")
    is_allowlisted = alert.get("is_allowlisted", False)
    src_ips = alert.get("src_ips", [])
    dst_ips = [f.destination_ip for f in flows if f.destination_ip not in {"", "unknown"}] if flows else []
    chain_timeline = alert.get("chain_timeline")

    lines = ["=== Alert Explanation ==="]
    lines.append(f"Threat   : {threat}")
    lines.append(f"Severity : {severity}")
    if confidence is not None:
        lines.append(f"Confidence: {confidence}%  |  FP Risk: {fp_risk or 'N/A'}")
    if window_time:
        lines.append(f"Window   : {window_time}")
    if correlation_count >= 3:
        lines.append(f"Correlation: this source triggered {correlation_count} suspicious windows — persistent threat")

    lines.append("")
    lines.append("Why this was flagged:")
    for reason in _build_why_reasons(threat, features, severity):
        lines.append(f"  - {reason}")
    if mitre_id:
        mitre_url = f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}"
        lines.append(f"  - MITRE ATT&CK: {mitre_id}  ({mitre_url})")

    if baseline_multiples:
        lines.append("")
        lines.append("Deviation from baseline:")
        for label, multiple in baseline_multiples.items():
            lines.append(f"  - {label}: {multiple:.1f}x above baseline")

    if flows:
        top_flow = flows[0]
        src = sanitizer.sanitize_ip(top_flow.source_ip) if sanitizer else top_flow.source_ip
        dst = sanitizer.sanitize_ip(top_flow.destination_ip) if sanitizer else top_flow.destination_ip
        raw_filter = ranked_flow_to_filter(top_flow)
        display_filter = sanitizer.sanitize_text(raw_filter) if sanitizer else raw_filter
        lines.append("")
        lines.append(f"Top flow : {src} -> {dst}  [{top_flow.protocol_name}, {top_flow.packet_count} pkts]")
        lines.append(f"Filter   : {display_filter}")

    # Benign causes reduce panic for analysts reviewing the alert
    benign = get_benign_causes(threat)
    lines.append("")
    lines.append("Possible benign causes:")
    for cause in benign:
        lines.append(f"  - {cause}")

    lines.append("")
    lines.append("Triage checklist:")
    if stored_checklist:
        lines.extend(stored_checklist)
    else:
        checklist = build_triage_checklist(src_ips, dst_ips, features, is_allowlisted, correlation_count, flow_direction)
        lines.extend(checklist)

    if chain_timeline:
        lines.append("")
        lines.append("Kill chain timeline:")
        for chain_line in chain_timeline:
            lines.append(f"  {chain_line}")

    lines.append("")
    lines.append("Recommended analyst actions:")
    steps = _get_next_steps(threat)
    for i, step in enumerate(steps, 1):
        step_text = step
        if flows and "<src>" in step_text:
            src_ip = flows[0].source_ip
            if sanitizer:
                src_ip = sanitizer.sanitize_ip(src_ip)
            step_text = step_text.replace("<src>", src_ip)
        lines.append(f"  {i}. {step_text}")

    return "\n".join(lines)
