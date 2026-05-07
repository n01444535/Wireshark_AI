import collections
import threading
import time

_DEFAULT_WINDOW_SECONDS = 600  # 10 minutes

_THREAT_PREFIXES = [
    "Port Scan", "SYN Flood", "ARP Cache Poisoning", "Lateral Movement",
    "Lateral Sweep", "SSH Brute Force", "SSH Tunneling", "RDP Exposure",
    "SMB Activity", "Cleartext Protocol", "ICS/HMI Web Reconnaissance",
    "Possible DDoS", "ARP Host Discovery", "Bulk Transfer Anomaly",
    "Sensitive Port Access", "SSH Anomaly", "Statistical Anomaly",
]


# Extract the known threat-type prefix from a threat string for use as a suppression key. / Trích xuất prefix loại threat đã biết để làm key cho suppression.
def _threat_prefix(threat_text: str) -> str:
    for prefix in _THREAT_PREFIXES:
        if threat_text.startswith(prefix):
            return prefix
    return threat_text[:40]


# Suppress duplicate terminal alerts when the same (threat type, source IP) recurs within a rolling window. / Ngăn duplicate alert terminal khi cùng (loại threat, IP nguồn) tái xuất hiện trong cửa sổ thời gian.
class AlertSuppressor:

    def __init__(self, window_seconds: int = _DEFAULT_WINDOW_SECONDS):
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._last_seen: dict = {}
        self._suppressed_count: collections.Counter = collections.Counter()

    def _make_key(self, threat_text: str, src_ips: list) -> str:
        prefix = _threat_prefix(threat_text)
        top_src = src_ips[0] if src_ips else "unknown"
        return f"{prefix}:{top_src}"

    # Check if this alert should be printed; also returns any pending suppression flush notice. / Kiểm tra có nên in alert này không; cũng trả về thông báo suppression nếu có.
    def check_and_record(self, threat_text: str, src_ips: list) -> tuple:
        key = self._make_key(threat_text, src_ips)
        now = time.time()
        with self._lock:
            last = self._last_seen.get(key)
            if last is not None and (now - last) < self._window_seconds:
                self._suppressed_count[key] += 1
                return False, None
            # Time to print — flush pending suppression count if any
            notice = None
            count = self._suppressed_count.pop(key, 0)
            if count > 0:
                mins = self._window_seconds // 60
                notice = f"Suppressed {count} duplicate alert(s) from the same source in the last {mins} minutes"
            self._last_seen[key] = now
            return True, notice
