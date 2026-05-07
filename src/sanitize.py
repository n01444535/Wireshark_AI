import re
import threading

_IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_MAC_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')
_LABEL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# Converts 0→A, 25→Z, 26→AA — bijective base-26 with no zero digit, same as Excel column labels. / Chuyển index thành nhãn base-26 không có chữ số không, giống cột Excel.
def _index_to_label(index):
    n = len(_LABEL_CHARS)
    label = ""
    i = index
    while True:
        label = _LABEL_CHARS[i % n] + label
        i = i // n - 1  # subtract 1 so the encoding is bijective — 26→AA not 26→BA
        if i < 0:
            break
    return label


# Thread-safe mapper from real IPs and MACs to HOST_A, HOST_B, ... aliases for privacy-safe output. / Ánh xạ thread-safe IP/MAC thực sang alias ẩn danh cho output.
class IpSanitizer:

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_map: dict = {}
        self._mac_map: dict = {}

    # Look up or assign a HOST_* alias for an IP address. / Tra cứu hoặc gán alias HOST_* cho địa chỉ IP.
    def sanitize_ip(self, ip: str) -> str:
        if not ip or ip in {"", "unknown"}:
            return ip
        with self._lock:
            if ip not in self._ip_map:
                self._ip_map[ip] = f"HOST_{_index_to_label(len(self._ip_map))}"
            return self._ip_map[ip]

    # Look up or assign a MAC_* alias for a MAC address. / Tra cứu hoặc gán alias MAC_* cho địa chỉ MAC.
    def sanitize_mac(self, mac: str) -> str:
        if not mac or mac in {"", "unknown"}:
            return mac
        with self._lock:
            if mac not in self._mac_map:
                self._mac_map[mac] = f"MAC_{_index_to_label(len(self._mac_map))}"
            return self._mac_map[mac]

    # Replace all registered IPs and MACs in a free-form string; snapshots the maps outside the lock to avoid holding it during substitution. / Thay thế IP/MAC đã đăng ký trong chuỗi bất kỳ bằng snapshot an toàn với lock.
    def sanitize_text(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            ip_snapshot = dict(self._ip_map)
            mac_snapshot = dict(self._mac_map)

        def _replace_ip(match):
            return ip_snapshot.get(match.group(0), match.group(0))

        text = _IPV4_PATTERN.sub(_replace_ip, text)
        for real_mac, alias in mac_snapshot.items():
            text = text.replace(real_mac, alias)
        return text

    # Pre-register all source and destination IPs in a flow list before printing output so sanitize_text finds every IP. / Đăng ký trước tất cả IP trong danh sách flow trước khi in output.
    def register_flows(self, ranked_flow_summaries) -> None:
        for flow in ranked_flow_summaries:
            if flow.source_ip:
                self.sanitize_ip(flow.source_ip)
            if flow.destination_ip:
                self.sanitize_ip(flow.destination_ip)

    # Return a thread-safe snapshot of the IP alias map for report output. / Trả về bản sao thread-safe của map alias IP dùng cho report.
    def get_ip_mapping(self) -> dict:
        with self._lock:
            return dict(self._ip_map)

    # Return a thread-safe snapshot of the MAC alias map for report output. / Trả về bản sao thread-safe của map alias MAC dùng cho report.
    def get_mac_mapping(self) -> dict:
        with self._lock:
            return dict(self._mac_map)
