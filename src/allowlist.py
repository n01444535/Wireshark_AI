import os

_ALLOWLIST_PATH = "config/allowlist.yml"
_ASSETS_PATH = "config/assets.yml"
_HIGH_CRITICALITY = {"critical", "high"}
_HIGH_VALUE_ROLES = {"domain_controller", "database", "file_server", "ics_hmi", "plc", "scada"}


# Load a YAML file safely; return empty dict if PyYAML is missing or file absent. / Đọc file YAML an toàn; trả dict rỗng nếu thiếu PyYAML hoặc file không tồn tại.
def _load_yaml(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        return {}
    except Exception:
        return {}


# Context derived from allowlist.yml and assets.yml that shapes alert severity and confidence scoring. / Ngữ cảnh từ allowlist và assets ảnh hưởng đến severity và điểm confidence.
class AllowlistContext:

    def __init__(self, allowlist_path=_ALLOWLIST_PATH, assets_path=_ASSETS_PATH):
        allowlist_data = _load_yaml(allowlist_path)
        assets_data = _load_yaml(assets_path)

        self._authorized_scanners: set = set(str(ip) for ip in allowlist_data.get("authorized_scanners", []))
        self._trusted_ports: set = {int(e["port"]) for e in allowlist_data.get("trusted_ports", [])}
        self._noisy_protocols: set = {str(p).lower() for p in allowlist_data.get("noisy_protocols", [])}

        self._assets: dict = {}
        for entry in assets_data.get("assets", []):
            if "ip" in entry:
                self._assets[str(entry["ip"])] = {
                    "name": entry.get("name", str(entry["ip"])),
                    "role": entry.get("role", "unknown"),
                    "criticality": entry.get("criticality", "medium"),
                }

    # Return True if the IP is in the authorized scanner list. / Trả True nếu IP là scanner được ủy quyền.
    def is_authorized_scanner(self, ip: str) -> bool:
        return ip in self._authorized_scanners

    # Return True if any ip in the list is an authorized scanner. / Trả True nếu có IP nào trong danh sách là scanner được ủy quyền.
    def any_authorized(self, ip_list: list) -> bool:
        return any(ip in self._authorized_scanners for ip in ip_list)

    # Return True if the port is in the trusted business ports list. / Trả True nếu port trong danh sách nghiệp vụ tin cậy.
    def is_trusted_port(self, port: int) -> bool:
        return port in self._trusted_ports

    # Return True if the protocol name is a known high-volume benign protocol. / Trả True nếu là giao thức ồn ào lành tính khối lượng cao.
    def is_noisy_protocol(self, proto: str) -> bool:
        return str(proto).lower() in self._noisy_protocols

    # Return asset metadata dict for a known IP, or None. / Trả metadata asset cho IP đã biết, hoặc None.
    def get_asset(self, ip: str) -> dict | None:
        return self._assets.get(ip)

    # Return True if any destination IP is a high-criticality or high-value-role asset. / Trả True nếu có IP đích nào là asset quan trọng.
    def touches_critical_asset(self, dst_ips: list) -> bool:
        for ip in dst_ips:
            asset = self._assets.get(ip)
            if asset and (asset["criticality"] in _HIGH_CRITICALITY or asset["role"] in _HIGH_VALUE_ROLES):
                return True
        return False

    # Return human-readable context string for notable destination assets, for display in alerts. / Trả chuỗi ngữ cảnh dễ đọc cho asset đích đáng chú ý, dùng trong alert.
    def format_asset_context(self, dst_ips: list, sanitizer=None) -> str | None:
        notable = []
        for ip in dst_ips[:5]:
            asset = self._assets.get(ip)
            if asset and asset["role"] != "unknown":
                display_ip = sanitizer.sanitize_ip(ip) if sanitizer else ip
                notable.append(f"{display_ip} ({asset['name']}, {asset['role']}, {asset['criticality']} criticality)")
        return ", ".join(notable) if notable else None
