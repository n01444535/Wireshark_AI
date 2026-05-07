import collections

_THREAT_TO_STAGE = {
    "ARP Host Discovery": "Reconnaissance",
    "Port Scan": "Scanning",
    "SYN Flood": "Scanning",
    "ARP Cache Poisoning": "Exploitation",
    "SSH Brute Force": "Exploitation",
    "SSH Tunneling": "Exploitation",
    "SSH Anomaly": "Exploitation",
    "Cleartext Protocol": "Exploitation",
    "RDP Exposure": "Exploitation",
    "Sensitive Port Access": "Exploitation",
    "Lateral Movement": "Lateral Movement",
    "Lateral Sweep": "Lateral Movement",
    "SMB Activity": "Lateral Movement",
    "ICS/HMI Web Reconnaissance": "Impact / Exfiltration",
    "Bulk Transfer Anomaly": "Impact / Exfiltration",
    "Possible DDoS": "Impact / Exfiltration",
}

# Multi-stage combinations that constitute a recognized intrusion pattern. / Tổ hợp nhiều giai đoạn cấu thành pattern xâm nhập đã biết.
_INTRUSION_PATTERNS = [
    (
        {"Port Scan", "SSH Brute Force"},
        "Port scan → SSH brute force — possible credential compromise in progress",
    ),
    (
        {"ARP Cache Poisoning", "Cleartext Protocol"},
        "ARP poisoning + cleartext session — active MiTM interception detected",
    ),
    (
        {"Port Scan", "Lateral Movement"},
        "Port scan → lateral movement — possible post-compromise host pivot",
    ),
    (
        {"Port Scan", "Lateral Sweep"},
        "Port scan → lateral sweep — multi-stage reconnaissance and pivot detected",
    ),
    (
        {"ARP Host Discovery", "Lateral Movement"},
        "Host discovery → lateral sweep — automated compromise propagation suspected",
    ),
    (
        {"ARP Host Discovery", "ARP Cache Poisoning"},
        "ARP host scan → ARP poisoning — systematic MiTM network preparation",
    ),
    (
        {"SSH Brute Force", "Lateral Movement"},
        "SSH brute force → lateral movement — post-authentication pivot detected",
    ),
    (
        {"Lateral Movement", "Bulk Transfer Anomaly"},
        "Lateral movement → bulk data transfer — possible staging and exfiltration",
    ),
    (
        {"Lateral Sweep", "ICS/HMI Web Reconnaissance"},
        "Lateral sweep → ICS/HMI access — post-pivot targeting of industrial controls",
    ),
]


# Map a threat string to its kill-chain stage label. / Ánh xạ chuỗi threat thành nhãn giai đoạn kill-chain.
def _get_stage(threat_text: str) -> str:
    for prefix, stage in _THREAT_TO_STAGE.items():
        if threat_text.startswith(prefix):
            return stage
    return "Anomaly"


# Tracks per-source alert sequences to detect multi-stage intrusion patterns. / Theo dõi chuỗi alert theo từng nguồn để phát hiện pattern xâm nhập nhiều bước.
class KillChainTracker:

    def __init__(self):
        self._chains: dict = collections.defaultdict(list)

    # Record a suspicious event for each source IP in the alert. / Ghi lại sự kiện suspicious cho mỗi IP nguồn.
    def record(self, src_ips: list, threat_text: str, window_time: str, severity: str) -> None:
        for ip in src_ips:
            if ip and ip not in {"", "unknown"}:
                self._chains[ip].append({
                    "threat": threat_text,
                    "stage": _get_stage(threat_text),
                    "time": window_time,
                    "severity": severity,
                })

    # Return an intrusion pattern warning string if a known multi-stage pattern is detected for any source IP. / Trả chuỗi cảnh báo nếu phát hiện pattern xâm nhập nhiều bước cho bất kỳ IP nguồn nào.
    def get_pattern_warning(self, src_ips: list) -> str | None:
        for ip in src_ips:
            events = self._chains.get(ip, [])
            if len(events) < 2:
                continue
            observed_prefixes: set = set()
            for e in events:
                for prefix in _THREAT_TO_STAGE:
                    if e["threat"].startswith(prefix):
                        observed_prefixes.add(prefix)
            for pattern_set, warning in _INTRUSION_PATTERNS:
                if pattern_set.issubset(observed_prefixes):
                    return warning
        return None

    # Format the activity timeline for a single source IP. / Định dạng timeline hoạt động cho một IP nguồn.
    def format_chain(self, ip: str, sanitizer=None) -> str:
        events = self._chains.get(ip, [])
        if not events:
            return ""
        display_ip = sanitizer.sanitize_ip(ip) if sanitizer else ip
        lines = [f"{display_ip} activity timeline ({len(events)} event(s)):"]
        for i, event in enumerate(events, 1):
            lines.append(f"  {i}. [{event['time']}] {event['stage']}: {event['threat'][:70]}")
        return "\n".join(lines)

    # Return formatted timelines for sources with at least min_events suspicious alerts. / Trả danh sách timeline cho các nguồn có ít nhất min_events alert suspicious.
    def get_notable_chains(self, min_events: int = 2, sanitizer=None) -> list:
        chains = []
        for ip, events in self._chains.items():
            if len(events) >= min_events:
                chains.append(self.format_chain(ip, sanitizer))
        return chains

    # Return a list of (ip, events) tuples sorted by event count descending, for priority display. / Trả danh sách (ip, events) sắp xếp theo số sự kiện giảm dần.
    def get_sorted_chains(self) -> list:
        return sorted(self._chains.items(), key=lambda kv: len(kv[1]), reverse=True)

    # Return a copy of all recorded events for the given IP. / Trả bản sao tất cả sự kiện đã ghi cho IP đã cho.
    def get_events_for_ip(self, ip: str) -> list:
        return list(self._chains.get(ip, []))
