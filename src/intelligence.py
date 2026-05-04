import ipaddress
import re
import threading
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from src.features import _is_ics_uri
from src.triage import AlertTriageEngine


INFERENCE_LABEL = "[Inference]"
UNVERIFIED_LABEL = "[Unverified]"
SPECULATION_LABEL = "[Speculation]"

_SELF_REFERENCE_PHRASES = {
    "this ip", "this machine", "this host", "this computer", "this device",
    "this server", "this pc", "my machine", "my host", "my ip", "my address",
    "local ip", "local machine", "local host",
}

_SELF_REFERENCE_SINGLE_WORDS = {"me", "my", "myself", "local"}


def _is_self_reference(normalized_question_text):
    if any(phrase in normalized_question_text for phrase in _SELF_REFERENCE_PHRASES):
        return True
    return any(
        re.search(rf"\b{re.escape(w)}\b", normalized_question_text)
        for w in _SELF_REFERENCE_SINGLE_WORDS
    )


SERVICE_PORTS = {
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "http": 80,
    "ntp": 123,
    "https": 443,
    "smb": 445,
    "rdp": 3389,
    "postgres": 5432,
    "postgresql": 5432,
    "mysql": 3306,
    "redis": 6379,
}


# Structured filter interpretation so answer formatting stays type-safe. / Cấu trúc diễn giải filter để format câu trả lời không còn stringly-typed.
@dataclass(frozen=True)
class DisplayFilterInterpretation:
    interpreted_intent: str
    display_filter_expression: str
    inference_explanation: str


# One analyzed capture window kept for live questions. / Một window capture đã phân tích để dùng cho hỏi đáp live.
@dataclass(frozen=True)
class TrafficWindow:
    window_start: float
    window_end: float
    window_feature_values: dict
    ranked_flow_summaries: list
    anomaly_score: float
    window_label: str
    inference_summary: str


# Keep certainty labels consistent and avoid double-prefixing. / Giữ nhãn mức độ chắc chắn nhất quán và tránh gắn trùng.
def _label_statement(label_text, statement_text):
    if not statement_text:
        return label_text
    if statement_text.startswith("["):
        return statement_text
    return f"{label_text} {statement_text}"


def format_inference_statement(statement_text):
    # Mark interpreted or model-produced statements explicitly. / Đánh dấu rõ các câu diễn giải hoặc do model tạo ra.
    return _label_statement(INFERENCE_LABEL, statement_text)


def format_unverified_statement(statement_text):
    # Mark statements that cannot be verified from completed windows. / Đánh dấu rõ các câu chưa thể xác minh từ window đã hoàn tất.
    return _label_statement(UNVERIFIED_LABEL, statement_text)


def format_speculation_statement(statement_text):
    # Reserve a separate label for intentionally hypothetical output. / Dành nhãn riêng cho output mang tính giả định có chủ ý.
    return _label_statement(SPECULATION_LABEL, statement_text)


# Format timestamps for human-readable terminal answers. / Định dạng timestamp để câu trả lời terminal dễ đọc.
def _clock(unix_timestamp):
    return datetime.fromtimestamp(unix_timestamp).strftime("%H:%M:%S")


# Detect whether an address should use Wireshark ipv6 fields. / Nhận biết địa chỉ cần dùng field ipv6 của Wireshark.
def _is_ipv6(address_text):
    try:
        return ipaddress.ip_address(address_text).version == 6
    except ValueError:
        return False


def _ip_filter_field(address_text, direction="addr"):
    # Choose ip.* or ipv6.* based on the address version. / Chọn ip.* hoặc ipv6.* dựa trên phiên bản địa chỉ.
    protocol_namespace = "ipv6" if _is_ipv6(address_text) else "ip"
    return f"{protocol_namespace}.{direction}"


def _protocol_port_filter_namespace(protocol_name):
    # Infer the display-filter port namespace from tshark protocol labels. / Suy luận namespace port trong display-filter từ nhãn protocol của tshark.
    lowered_protocol_name = protocol_name.lower()
    if lowered_protocol_name.startswith("tcp") or lowered_protocol_name in {"http", "https", "tls", "ssl", "ssh"}:
        return "tcp"
    if lowered_protocol_name.startswith("udp") or lowered_protocol_name in {"dns", "mdns", "dhcp", "bootp", "ntp", "quic", "ssdp", "stun"}:
        return "udp"
    return ""


# Build a Wireshark display filter from one ranked flow. / Tạo Wireshark display filter từ một flow đã xếp hạng.
def ranked_flow_to_filter(ranked_flow_summary):
    ip_version_namespace = "ipv6" if _is_ipv6(ranked_flow_summary.source_ip) or _is_ipv6(ranked_flow_summary.destination_ip) else "ip"
    display_filter_clauses = []

    # Add IP endpoint filters when the packet had known addresses. / Thêm filter IP khi packet có địa chỉ xác định.
    if ranked_flow_summary.source_ip != "unknown":
        display_filter_clauses.append(f"{ip_version_namespace}.src == {ranked_flow_summary.source_ip}")
    if ranked_flow_summary.destination_ip != "unknown":
        display_filter_clauses.append(f"{ip_version_namespace}.dst == {ranked_flow_summary.destination_ip}")

    # Map tshark protocol labels to Wireshark display-filter protocol names. / Ánh xạ nhãn protocol từ tshark sang tên filter của Wireshark.
    protocol_filter_namespace = _protocol_port_filter_namespace(ranked_flow_summary.protocol_name)

    # Add port filters only for protocols with ports. / Chỉ thêm filter port cho protocol có port.
    if protocol_filter_namespace:
        if ranked_flow_summary.source_port:
            display_filter_clauses.append(f"{protocol_filter_namespace}.srcport == {ranked_flow_summary.source_port}")
        if ranked_flow_summary.destination_port:
            display_filter_clauses.append(f"{protocol_filter_namespace}.dstport == {ranked_flow_summary.destination_port}")

    return " && ".join(display_filter_clauses) if display_filter_clauses else "frame"


def _port_filter(port_number, direction="addr"):
    # Build a protocol-agnostic TCP/UDP port filter. / Tạo filter port TCP/UDP không phụ thuộc protocol.
    if direction == "src":
        return f"(tcp.srcport == {port_number} || udp.srcport == {port_number})"
    if direction == "dst":
        return f"(tcp.dstport == {port_number} || udp.dstport == {port_number})"
    return f"(tcp.port == {port_number} || udp.port == {port_number})"


def _format_filter_builder_answer(filter_interpretation):
    # Render a filter-builder answer that can be pasted into Wireshark. / Định dạng câu trả lời tạo filter để paste vào Wireshark.
    response_line_collection = [
        "=== Wireshark Display Filter Builder ===",
        f"Interpreted Intent: {format_inference_statement(filter_interpretation.interpreted_intent)}",
        "Display Filter:",
        filter_interpretation.display_filter_expression,
        f"Why: {format_inference_statement(filter_interpretation.inference_explanation)}",
    ]
    return "\n".join(response_line_collection)


# Render one flow for terminal answers. / Định dạng một flow cho câu trả lời terminal.
def _format_ranked_flow(ranked_flow_summary, display_index=None):
    flow_prefix = f"{display_index}. " if display_index is not None else ""
    frame_info = ""
    if ranked_flow_summary.first_frame > 0:
        if ranked_flow_summary.first_frame == ranked_flow_summary.last_frame:
            frame_info = f" | frame #{ranked_flow_summary.first_frame}"
        else:
            frame_info = f" | frames #{ranked_flow_summary.first_frame}-#{ranked_flow_summary.last_frame}"
    return (
        f"{flow_prefix}{ranked_flow_summary.source_ip}:{ranked_flow_summary.source_port} -> "
        f"{ranked_flow_summary.destination_ip}:{ranked_flow_summary.destination_port} "
        f"{ranked_flow_summary.protocol_name} | "
        f"packets={ranked_flow_summary.packet_count} "
        f"bytes={ranked_flow_summary.byte_count} "
        f"syn={ranked_flow_summary.syn_count} "
        f"rst={ranked_flow_summary.reset_count}"
        f"{frame_info}\n"
        f"   Wireshark filter: {ranked_flow_to_filter(ranked_flow_summary)}"
    )


# Extract valid IP addresses from a user's question. / Lấy các địa chỉ IP hợp lệ từ câu hỏi của user.
def _extract_ips(question_text):
    matched_address_strings = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,}", question_text)
    extracted_ip_addresses = []
    for matched_address_string in matched_address_strings:
        try:
            ipaddress.ip_address(matched_address_string)
            extracted_ip_addresses.append(matched_address_string)
        except ValueError:
            continue
    return extracted_ip_addresses


# Extract the first valid IP address from a user's question. / Lấy địa chỉ IP hợp lệ đầu tiên từ câu hỏi của user.
def _extract_first_ip(question_text):
    extracted_ip_addresses = _extract_ips(question_text)
    if extracted_ip_addresses:
        return extracted_ip_addresses[0]
    return None


# Normalize user text so Vietnamese accents still match commands. / Chuẩn hoá text để tiếng Việt có dấu vẫn khớp command.
def _normalize_text(question_text):
    return unicodedata.normalize("NFKD", question_text).encode("ascii", "ignore").decode("ascii").lower()


def _percent(ratio_value):
    # Format ratios as Wireshark-style percentages. / Định dạng tỉ lệ thành phần trăm kiểu Wireshark.
    return f"{ratio_value * 100:.1f}%"


def _protocol_breakdown_from_flows(analyzed_capture_windows):
    # Count packets per protocol across all stored flows in all windows.
    protocol_counter = Counter()
    total_packets = 0
    for win in analyzed_capture_windows:
        for flow in win.ranked_flow_summaries:
            protocol_counter[flow.protocol_name] += flow.packet_count
            total_packets += flow.packet_count
    return protocol_counter, total_packets




_SENSITIVE_PORT_LABELS = {
    20: "FTP data", 21: "FTP control", 22: "SSH", 23: "Telnet (cleartext)",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    137: "NetBIOS", 139: "NetBIOS session", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB (lateral movement risk)", 1433: "MSSQL",
    1521: "Oracle DB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP alt", 9200: "Elasticsearch",
}


def _flow_why_suspicious(flow):
    reasons = []
    proto = flow.protocol_name.upper()
    dst, src = flow.destination_port, flow.source_port

    # ARP poisoning / MiTM — check before protocol rules
    if proto == "ARP":
        reasons.append(
            "ARP traffic — check for gratuitous ARP announcements indicating"
            " Ettercap / ARP cache poisoning MiTM attack against ICS devices"
        )

    # HTTP ICS/web recon — check before protocol-based rules
    if flow.http_uris:
        ics_uris = [u for u in flow.http_uris if _is_ics_uri(u)]
        if ics_uris:
            reasons.append(
                f"ICS/HMI endpoint accessed: {', '.join(ics_uris[:3])}"
                " — reconnaissance of industrial control system web interface"
            )
        else:
            uri_list = ", ".join(flow.http_uris[:3])
            reasons.append(f"Web requests to: {uri_list}")
        if "401" in flow.http_status_codes:
            reasons.append(
                "HTTP 401 challenge received — server required authentication"
                " (Digest Auth nonce exchange)"
            )

    if proto in {"SSH", "SSHV2"}:
        # Prefer the smaller non-standard port as the server/service port.
        # Ephemeral client ports are typically >32768; server alternate SSH ports are <10000.
        candidates = [p for p in [dst, src] if p not in {0, 22}]
        non_std = min(candidates) if candidates else None
        if non_std:
            reasons.append(f"SSH on non-standard port {non_std} — tunneling or evasion risk")
        elif flow.syn_count >= 3 and flow.packet_count < 15:
            reasons.append("Multiple SYN to SSH — possible brute force attempt")
        else:
            reasons.append("SSH session — verify authentication and access rights")
    elif proto == "TELNET":
        reasons.append("Telnet: cleartext protocol — credentials visible in plaintext")
    elif proto in {"RDP", "MS-WBT-SERVER"}:
        reasons.append("RDP: remote desktop — verify for unauthorized remote access")
    elif proto == "SMB":
        reasons.append("SMB: file-sharing — check for lateral movement or ransomware")

    if flow.syn_count > 0 and flow.packet_count <= 3 and flow.reset_count > 0:
        reasons.append("SYN then RST — port probe or scan attempt")
    elif flow.reset_count > 2:
        reasons.append(f"{flow.reset_count} TCP RSTs — connection repeatedly rejected")

    if not reasons:
        for p in [dst, src]:
            label = _SENSITIVE_PORT_LABELS.get(p)
            if label:
                reasons.append(f"Sensitive port {p} ({label}) targeted")
                break

    # Last resort: derive context from packet-level info strings if available
    if not reasons and flow.sample_infos:
        for raw_info in flow.sample_infos[:1]:
            if "[ACK]" in raw_info and "[SYN" not in raw_info:
                port_match = re.search(r'→\s*(\d+)', raw_info)
                if port_match:
                    port = int(port_match.group(1))
                    label = _SENSITIVE_PORT_LABELS.get(port, "")
                    if label:
                        reasons.append(
                            f"Sustained TCP session to {label} port {port} — "
                            "ongoing data transfer within an established connection"
                        )
                    elif port not in {80, 443, 8080, 8443}:
                        reasons.append(
                            f"Persistent TCP session on non-standard port {port} — "
                            "could be a tunneled service or evasion technique"
                        )

    return "; ".join(reasons) if reasons else "flagged by anomaly model — no single dominant indicator"


def _humanize_packet_info(raw_info: str, protocol: str) -> str:
    """Translate a raw tshark _ws.col.Info string into plain English for non-technical readers."""
    if not raw_info:
        return None
    info = raw_info.strip()

    # DNS
    if "Standard query response" in info:
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', info)
        name_match = re.search(r'(?:A|AAAA|CNAME|MX|TXT)\s+([\w.\-]+)', info)
        if name_match and ip_match:
            return f"DNS answer: '{name_match.group(1)}' is located at {ip_match.group()}"
        return "DNS query response received"
    if "Standard query" in info:
        name_match = re.search(r'(?:A|AAAA|CNAME|MX|PTR|TXT)\s+([\w.\-]+)', info)
        if name_match:
            return f"DNS lookup: asking where '{name_match.group(1)}' is on the internet"
        return "DNS lookup request sent to name server"

    # HTTP request
    http_req = re.match(r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', info)
    if http_req:
        method, path = http_req.group(1), http_req.group(2)
        verbs = {
            "GET": "Requesting page", "POST": "Submitting data to",
            "PUT": "Uploading to", "DELETE": "Deleting resource at",
            "PATCH": "Updating resource at", "HEAD": "Probing headers at",
            "OPTIONS": "Checking allowed methods for",
        }
        path_lower = path.lower()
        if any(kw in path_lower for kw in ("alarmlog", "alarmlogs", "eventlog", "eventlogs")):
            ics_hint = " [ICS alarm/event log — sensitive operational data]"
        elif any(kw in path_lower for kw in ("scrl", "scrs", "scrsi")):
            ics_hint = " [HMI screen data — shows physical process state]"
        elif any(kw in path_lower for kw in ("historian", "trend", "setpoint", "tagbrowser")):
            ics_hint = " [ICS process data endpoint]"
        else:
            ics_hint = ""
        return f"HTTP: {verbs.get(method, method)} {path}{ics_hint}"

    # HTTP response
    http_resp = re.match(r'HTTP/[\d.]+ (\d+)\s+(.*)', info)
    if http_resp:
        code, text = int(http_resp.group(1)), http_resp.group(2).strip()
        if code < 300:
            return f"HTTP success ({code}) — request completed, content returned"
        if code in (301, 302, 307, 308):
            return f"HTTP redirect ({code}) — content moved to a different URL"
        if code == 401:
            return (
                "HTTP 401: Server sent authentication challenge"
                " — client must reply with credentials (Digest Auth nonce exchange)"
            )
        if code == 403:
            return "HTTP 403: Access denied — client lacks permission for this resource"
        if code == 404:
            return "HTTP 404: Resource not found — URL does not exist on the server"
        if code >= 500:
            return f"HTTP server error ({code} {text}) — server-side failure"
        return f"HTTP response {code} {text}"

    # TCP flags (from Wireshark info column like "12345 → 443 [SYN] Seq=0 Win=64240 Len=0")
    if "[SYN]" in info and "[ACK]" not in info:
        dst_match = re.search(r'→\s*(\d+)', info)
        port_hint = f" to port {dst_match.group(1)}" if dst_match else ""
        return f"TCP SYN: new connection attempt{port_hint} — three-way handshake starting"
    if "[SYN, ACK]" in info:
        return "TCP SYN-ACK: server accepted the connection attempt — handshake step 2 of 3"
    if "[RST" in info:
        return "TCP RST: connection forcibly terminated — port closed, firewall blocked, or service unavailable"
    if "[FIN, ACK]" in info or "[FIN,ACK]" in info:
        return "TCP FIN-ACK: session closing gracefully — both sides acknowledged teardown"
    if "[FIN]" in info:
        return "TCP FIN: one side is requesting to end the connection"
    if "[ACK]" in info and "[SYN" not in info and "[RST" not in info and "[FIN" not in info:
        dst_match = re.search(r'→\s*(\d+)', info)
        len_match = re.search(r'\bLen=(\d+)\b', info)
        ack_match = re.search(r'\bAck=(\d+)\b', info)
        length = int(len_match.group(1)) if len_match else 0
        port = int(dst_match.group(1)) if dst_match else None
        port_label = _SENSITIVE_PORT_LABELS.get(port, "") if port else ""
        port_hint = (
            f" on port {port} [{port_label}]" if port and port_label
            else (f" on port {port}" if port else "")
        )
        if length == 0:
            ack_bytes = int(ack_match.group(1)) if ack_match else None
            byte_hint = f" — {ack_bytes:,} bytes received so far" if ack_bytes else ""
            return f"TCP acknowledgement{port_hint}{byte_hint}, no data payload, connection maintained"
        else:
            return f"TCP data packet{port_hint} — {length} bytes of application payload"

    # SSH
    if "Key Exchange" in info or "Key exchange" in info:
        return "SSH: negotiating encryption algorithm — channel setup in progress"
    if "New Keys" in info:
        return "SSH: encryption keys confirmed — channel is now fully encrypted"
    if "Encrypted packet" in info or "Encrypted Packet" in info:
        return "SSH: encrypted command or data being transmitted — payload not visible"

    # TLS / HTTPS
    if "Client Hello" in info:
        return "TLS: client starting encrypted handshake — listing supported cipher suites"
    if "Server Hello" in info:
        return "TLS: server chose a cipher suite and accepted the handshake"
    if "Certificate" in info and "Verify" not in info:
        return "TLS: server presenting its identity certificate for verification"
    if "Certificate Verify" in info:
        return "TLS: client proving it holds the private key matching the certificate"
    if "Application Data" in info:
        return "TLS: encrypted application data being transferred — payload is hidden"
    if "Change Cipher Spec" in info or "Change cipher spec" in info:
        return "TLS: switching to the agreed encryption — channel secured from this point"
    if "Finished" in info:
        return "TLS: handshake complete — encrypted session fully established"

    # ARP
    if "Who has" in info:
        target = re.search(r'Who has ([\d.]+)', info)
        if target:
            return f"ARP: searching the local network for device {target.group(1)}"
        return "ARP: broadcasting to find a device on the local network"
    if "is at" in info:
        return "ARP: device replied with its MAC address — location confirmed"

    # ICMP
    if "Echo (ping) request" in info:
        return "ICMP ping request: checking if a host is reachable"
    if "Echo (ping) reply" in info:
        return "ICMP ping reply: host is alive and responding"
    if "Destination unreachable" in info:
        return "ICMP: destination unreachable — host is down or traffic is blocked"
    if "Time-to-live exceeded" in info or "Time exceeded" in info:
        return "ICMP TTL exceeded: packet expired in transit — possible traceroute in progress"

    # DHCP
    if "DHCP Discover" in info:
        return "DHCP: new device broadcasting a request for an IP address"
    if "DHCP Offer" in info:
        return "DHCP: server offering an available IP address to the new device"
    if "DHCP Request" in info:
        return "DHCP: device formally requesting to use the offered IP address"
    if "DHCP ACK" in info:
        return "DHCP: server confirmed — IP address lease granted"

    return None


def _distinct_protocols_from_flows(ranked_flow_summaries):
    counter = Counter(f.protocol_name for f in ranked_flow_summaries)
    return ", ".join(proto for proto, _ in counter.most_common())


def _format_finding(ranked_flow_summary, display_index):
    if ranked_flow_summary.first_frame > 0:
        if ranked_flow_summary.first_frame == ranked_flow_summary.last_frame:
            frame_text = (
                f"#{ranked_flow_summary.first_frame}"
                f"  (Ctrl+G in Wireshark → {ranked_flow_summary.first_frame})"
            )
        else:
            frame_text = (
                f"#{ranked_flow_summary.first_frame} - #{ranked_flow_summary.last_frame}"
                f"  (Ctrl+G → {ranked_flow_summary.first_frame})"
            )
    else:
        frame_text = "not available"
    lines = [
        f"  {display_index}. Source:      {ranked_flow_summary.source_ip}",
        f"     Destination: {ranked_flow_summary.destination_ip}",
        f"     Protocol:    {ranked_flow_summary.protocol_name}",
        f"     Why:         {_flow_why_suspicious(ranked_flow_summary)}",
        f"     Frames:      {frame_text}",
    ]
    if ranked_flow_summary.http_uris:
        lines.append("     HTTP endpoints accessed:")
        for uri in ranked_flow_summary.http_uris[:6]:
            status_hint = ""
            if ranked_flow_summary.http_status_codes:
                status_hint = f" [{', '.join(ranked_flow_summary.http_status_codes)}]"
            ics_flag = " ⚠ ICS endpoint" if _is_ics_uri(uri) else ""
            lines.append(f"       • {uri}{status_hint}{ics_flag}")
        if len(ranked_flow_summary.http_uris) > 6:
            lines.append(f"       • ... and {len(ranked_flow_summary.http_uris) - 6} more")
    if ranked_flow_summary.sample_infos:
        lines.append("     Packet activity:")
        # Translate then deduplicate, showing a count when the same type repeats
        seen_order: list = []
        seen_count: dict = {}
        for raw_info in ranked_flow_summary.sample_infos:
            translated = _humanize_packet_info(raw_info, ranked_flow_summary.protocol_name)
            text = translated if translated else raw_info
            if text in seen_count:
                seen_count[text] += 1
            else:
                seen_count[text] = 1
                seen_order.append(text)
        for text in seen_order:
            count = seen_count[text]
            prefix = f"{count}× " if count > 1 else ""
            lines.append(f"       • {prefix}{text}")
    lines += [
        f"     Filter (paste in Wireshark display filter bar):",
        f"       {ranked_flow_to_filter(ranked_flow_summary)}",
    ]
    return "\n".join(lines)


def _is_suspicious_keyword(normalized_question_text):
    # Catch "suspicious" plus common typos like "suspicous", "suspisious".
    return (
        normalized_question_text.startswith("suspic")
        or any(kw in normalized_question_text for kw in ("nghi", "bat thuong", "alert", "canh bao"))
    )


def _has_phrase(normalized_question_text, phrase_text):
    # Match single-word phrases on word boundaries to avoid packet/ack collisions. / Khớp phrase một từ theo ranh giới từ để tránh packet bị hiểu thành ack.
    if " " in phrase_text:
        return phrase_text in normalized_question_text
    return re.search(rf"\b{re.escape(phrase_text)}\b", normalized_question_text) is not None


def _protocol_mix(window_feature_values):
    # Summarize protocol ratios from a capture window. / Tóm tắt tỉ lệ protocol từ một capture window.
    return (
        f"TCP={_percent(window_feature_values.get('protocol_tcp_ratio', 0.0))} "
        f"UDP={_percent(window_feature_values.get('protocol_udp_ratio', 0.0))} "
        f"ICMP={_percent(window_feature_values.get('protocol_icmp_ratio', 0.0))} "
        f"Other={_percent(window_feature_values.get('protocol_other_ratio', 0.0))}"
    )


def _window_panel(traffic_window, panel_title):
    # Render a capture window like a compact Wireshark statistics panel. / Hiển thị window như panel thống kê Wireshark rút gọn.
    window_feature_values = traffic_window.window_feature_values
    return [
        f"=== {panel_title} ===",
        "Capture Window:",
        f"  Time: {_clock(traffic_window.window_start)} - {_clock(traffic_window.window_end)}",
        f"  State: {traffic_window.window_label.upper()}",
        f"  Score: {traffic_window.anomaly_score:.4f}",
        "Statistics:",
        f"  Packets: {window_feature_values.get('packets', 0)}",
        f"  Bytes: {window_feature_values.get('bytes_total', 0)}",
        f"  Conversations: {window_feature_values.get('unique_flows', 0)}",
        f"  Unique Sources: {window_feature_values.get('unique_src_ips', 0)}",
        f"  Unique Destinations: {window_feature_values.get('unique_dst_ips', 0)}",
        f"  Protocol Mix: {_protocol_mix(window_feature_values)}",
        "Expert Info:",
        f"  {traffic_window.inference_summary}",
    ]


def _flow_has_port(ranked_flow_summary, port_number):
    # Check both source and destination ports. / Kiểm tra cả source port và destination port.
    return ranked_flow_summary.source_port == port_number or ranked_flow_summary.destination_port == port_number


def _flow_protocol_group(ranked_flow_summary):
    # Map Wireshark protocol labels to broad transport/application groups. / Ánh xạ nhãn protocol Wireshark thành nhóm transport/application rộng hơn.
    normalized_protocol_name = ranked_flow_summary.protocol_name.upper()
    if normalized_protocol_name in {"TCP", "HTTP", "HTTPS", "TLS", "SSL", "SSH"}:
        return "tcp"
    if normalized_protocol_name in {"UDP", "DNS", "MDNS", "DHCP", "BOOTP", "NTP", "QUIC", "SSDP", "STUN"}:
        return "udp"
    if normalized_protocol_name in {"ICMP", "ICMPV6"}:
        return "icmp"
    return normalized_protocol_name.lower()


def _flow_matches_question(ranked_flow_summary, original_question_text, normalized_question_text):
    # Match an aggregated flow against a live show/find request. / So khớp flow đã tổng hợp với câu hỏi show/find live.
    protocol_name_upper = ranked_flow_summary.protocol_name.upper()
    requested_ip_addresses = _extract_ips(original_question_text)

    if len(requested_ip_addresses) >= 2 and "between" in normalized_question_text:
        return (
            requested_ip_addresses[0] in {ranked_flow_summary.source_ip, ranked_flow_summary.destination_ip}
            and requested_ip_addresses[1] in {ranked_flow_summary.source_ip, ranked_flow_summary.destination_ip}
        )
    if requested_ip_addresses:
        requested_ip_address = requested_ip_addresses[0]
        if any(direction_word in normalized_question_text for direction_word in ("from", "src", "source")):
            return ranked_flow_summary.source_ip == requested_ip_address
        if any(direction_word in normalized_question_text for direction_word in ("to", "dst", "dest", "destination")):
            return ranked_flow_summary.destination_ip == requested_ip_address
        return requested_ip_address in {ranked_flow_summary.source_ip, ranked_flow_summary.destination_ip}

    source_port_match = re.search(r"\b(?:src|source)\s+port\s+(\d+)\b", normalized_question_text)
    if source_port_match:
        return ranked_flow_summary.source_port == int(source_port_match.group(1))
    destination_port_match = re.search(r"\b(?:dst|dest|destination)\s+port\s+(\d+)\b", normalized_question_text)
    if destination_port_match:
        return ranked_flow_summary.destination_port == int(destination_port_match.group(1))
    any_port_match = re.search(r"\bport\s+(\d+)\b", normalized_question_text)
    if any_port_match:
        return _flow_has_port(ranked_flow_summary, int(any_port_match.group(1)))

    for service_name, service_port_number in SERVICE_PORTS.items():
        if re.search(rf"\b{service_name}\b", normalized_question_text):
            return _flow_has_port(ranked_flow_summary, service_port_number)

    if _has_phrase(normalized_question_text, "mdns"):
        return protocol_name_upper == "MDNS" or _flow_has_port(ranked_flow_summary, 5353)
    if _has_phrase(normalized_question_text, "dns"):
        return protocol_name_upper == "DNS" or _flow_has_port(ranked_flow_summary, 53)
    if _has_phrase(normalized_question_text, "tcp"):
        return _flow_protocol_group(ranked_flow_summary) == "tcp"
    if _has_phrase(normalized_question_text, "udp"):
        return _flow_protocol_group(ranked_flow_summary) == "udp"
    if _has_phrase(normalized_question_text, "icmp") or _has_phrase(normalized_question_text, "ping"):
        return protocol_name_upper in {"ICMP", "ICMPV6"}
    if _has_phrase(normalized_question_text, "arp"):
        return protocol_name_upper == "ARP"
    if _has_phrase(normalized_question_text, "http"):
        return protocol_name_upper == "HTTP" or _flow_has_port(ranked_flow_summary, 80)
    if _has_phrase(normalized_question_text, "https") or _has_phrase(normalized_question_text, "tls"):
        return protocol_name_upper in {"HTTPS", "TLS", "SSL"} or _flow_has_port(ranked_flow_summary, 443)
    if _has_phrase(normalized_question_text, "dhcp") or _has_phrase(normalized_question_text, "bootp"):
        return protocol_name_upper in {"DHCP", "BOOTP"} or _flow_has_port(ranked_flow_summary, 67) or _flow_has_port(ranked_flow_summary, 68)
    if _has_phrase(normalized_question_text, "quic"):
        return protocol_name_upper == "QUIC" or _flow_has_port(ranked_flow_summary, 443)
    if _has_phrase(normalized_question_text, "syn"):
        return ranked_flow_summary.syn_count > 0
    if _has_phrase(normalized_question_text, "reset") or _has_phrase(normalized_question_text, "rst"):
        return ranked_flow_summary.reset_count > 0
    if any(
        _has_phrase(normalized_question_text, large_packet_phrase)
        for large_packet_phrase in ("large packet", "large packets", "big packet", "big packets")
    ):
        return ranked_flow_summary.packet_count > 0 and ranked_flow_summary.byte_count / ranked_flow_summary.packet_count > 1000
    if any(
        _has_phrase(normalized_question_text, small_packet_phrase)
        for small_packet_phrase in ("small packet", "small packets")
    ):
        return ranked_flow_summary.packet_count > 0 and ranked_flow_summary.byte_count / ranked_flow_summary.packet_count < 100
    return False


# Thread-safe memory of recent analyzed windows. / Bộ nhớ thread-safe cho các window đã phân tích gần đây.
class TrafficMemory:
    def __init__(self, max_windows=200):
        self.max_windows = max_windows
        self._windows = []
        self._lock = threading.Lock()

    def add_window(self, traffic_window):
        # Keep bounded memory so long captures do not grow forever. / Giới hạn bộ nhớ để capture lâu không tăng vô hạn.
        with self._lock:
            self._windows.append(traffic_window)
            if len(self._windows) > self.max_windows:
                self._windows = self._windows[-self.max_windows:]

    def snapshot(self):
        # Return a copy so readers do not hold the lock while formatting answers. / Trả bản sao để reader không giữ lock khi format câu trả lời.
        with self._lock:
            return list(self._windows)


# Turns recent traffic memory into terminal answers. / Chuyển bộ nhớ traffic gần đây thành câu trả lời trên terminal.
class TrafficAnswerEngine:
    def __init__(self, memory, local_ip=None):
        self.memory = memory
        self.local_ip = local_ip
        self.triage_engine = AlertTriageEngine()

    def answer(self, question_text):
        # Route natural-ish commands to focused answer methods. / Điều hướng command gần tự nhiên tới hàm trả lời phù hợp.
        original_question_text = question_text.strip()
        normalized_question_text = _normalize_text(original_question_text)
        analyzed_capture_windows = self.memory.snapshot()

        if normalized_question_text in {"help", "?", "commands"}:
            answer_body_text = self.help_text()
        elif normalized_question_text in {"quit", "exit", "stop"}:
            answer_body_text = "Use Ctrl+C to stop capture."
        elif normalized_question_text in {"triage", "assess", "risk", "danh gia"}:
            answer_body_text = self.answer_triage(analyzed_capture_windows)
        elif self.is_filter_help(normalized_question_text):
            answer_body_text = self.filter_help_text()
        else:
            # Resolve "from this ip" / "from me" to the detected local IP before routing.
            resolved_original, resolved_normalized = self._resolve_self_reference(
                original_question_text, normalized_question_text
            )
            filter_interpretation = self.build_display_filter_interpretation(
                resolved_original,
                resolved_normalized,
            )
            requested_ip_address = _extract_first_ip(resolved_original)

            if filter_interpretation and self.looks_like_live_show_request(resolved_normalized):
                answer_body_text = self.answer_live_matches(
                    resolved_original,
                    resolved_normalized,
                    analyzed_capture_windows,
                    filter_interpretation,
                )
            elif _is_suspicious_keyword(normalized_question_text):
                answer_body_text = self.answer_suspicious(analyzed_capture_windows)
            elif filter_interpretation and self.looks_like_filter_request(resolved_normalized):
                answer_body_text = _format_filter_builder_answer(filter_interpretation)
            elif normalized_question_text.startswith("ip ") and requested_ip_address:
                answer_body_text = self.answer_ip(requested_ip_address, analyzed_capture_windows)
            elif any(keyword in normalized_question_text for keyword in ("filter", "loc")):
                answer_body_text = self.answer_filters(analyzed_capture_windows)
            elif any(keyword in normalized_question_text for keyword in ("summary", "tom tat", "status", "latest", "gan nhat")):
                answer_body_text = self.answer_summary(analyzed_capture_windows)
            elif any(keyword in normalized_question_text for keyword in ("top", "flow", "flows")):
                answer_body_text = self.answer_top_flows(analyzed_capture_windows)
            elif requested_ip_address:
                answer_body_text = self.answer_ip(requested_ip_address, analyzed_capture_windows)
            else:
                answer_body_text = (
                    self.answer_summary(analyzed_capture_windows)
                    + "\n\nTip: type `suspicious`, `filter`, `top flows`, `ip <address>`, `show ...`, or `filter ...`."
                )

        return self._with_question(original_question_text, answer_body_text)

    def _resolve_self_reference(self, original_question_text, normalized_question_text):
        # Replace self-reference phrases with the actual local IP so routing works normally.
        if not self.local_ip or not _is_self_reference(normalized_question_text):
            return original_question_text, normalized_question_text
        if any(d in normalized_question_text for d in ("from", "src", "source")):
            synthetic = f"show traffic from {self.local_ip}"
        elif any(d in normalized_question_text for d in ("to", "dst", "dest", "destination")):
            synthetic = f"show traffic to {self.local_ip}"
        else:
            synthetic = f"show traffic {self.local_ip}"
        return synthetic, _normalize_text(synthetic)

    def _with_question(self, original_question_text, answer_body_text):
        return f"> {original_question_text}\n{answer_body_text}"

    def _no_analyzed_window_panel(self, panel_title, unverified_message_text):
        # Reuse one bounded message when no completed capture window exists yet. / Dùng lại một thông báo có giới hạn khi chưa có window capture hoàn tất.
        response_line_collection = [
            f"=== {panel_title} ===",
            format_unverified_statement(unverified_message_text),
        ]
        return "\n".join(response_line_collection)

    def help_text(self):
        local_ip_hint = f"  (your machine IP: {self.local_ip})" if self.local_ip else ""
        return (
            "Commands:\n"
            "  suspicious          — show anomaly windows\n"
            "  triage              — full risk assessment (TP vs FP, brute force vs user lockout)\n"
            "  summary             — latest window stats\n"
            "  top flows           — highest-risk conversations\n"
            "  filter              — display filters from recent conversations\n"
            "  filter help         — natural-language filter examples\n"
            "  ip <address>        — traffic for a specific IP\n"
            f"  show traffic from this ip  — outbound from this machine{local_ip_hint}\n"
            "  show traffic to <ip>       — inbound to a specific IP\n"
            "  show <protocol/port/...>   — live matches + Wireshark filter\n"
            "  filter <...>               — build Wireshark filter only\n"
            "  clear               — clear the screen\n"
            "  Ctrl+C              — stop capture"
        )

    def is_filter_help(self, normalized_question_text):
        # Detect requests for supported natural-language filters. / Nhận diện yêu cầu xem các filter ngôn ngữ tự nhiên được hỗ trợ.
        return normalized_question_text in {
            "filter help",
            "filters help",
            "display filter help",
            "wireshark filters",
            "filter examples",
        }

    def looks_like_filter_request(self, normalized_question_text):
        # Decide whether a recognized phrase should return a display filter. / Quyết định phrase đã nhận diện nên trả về display filter hay không.
        request_keywords = (
            "filter",
            "show",
            "find",
            "display",
            "packet",
            "packets",
            "traffic",
            "port",
            "protocol",
            "from",
            "to",
            "between",
        )
        return any(_has_phrase(normalized_question_text, request_keyword) for request_keyword in request_keywords)

    def looks_like_live_show_request(self, normalized_question_text):
        # Treat show/find/display questions as live traffic lookups. / Xem các câu show/find/display là truy vấn traffic live.
        return (
            normalized_question_text.startswith("show ")
            or normalized_question_text.startswith("find ")
            or normalized_question_text.startswith("display ")
        )

    def filter_help_text(self):
        # Document every natural-language filter builder supported by this app. / Ghi lại toàn bộ filter tự nhiên mà app hỗ trợ.
        return (
            "Natural-language Wireshark display filters:\n"
            "- show dns packets -> verify recent completed-window matches and return dns\n"
            "- filter dns -> dns\n"
            "- show mdns packets -> verify recent completed-window matches and return mdns\n"
            "- filter mdns -> mdns\n"
            "- filter tcp -> tcp\n"
            "- filter udp -> udp\n"
            "- filter icmp -> icmp || icmpv6\n"
            "- filter arp -> arp\n"
            "- filter http -> http\n"
            "- filter https -> tls || tcp.port == 443\n"
            "- filter tls handshake -> tls.handshake\n"
            "- filter dhcp -> dhcp || bootp\n"
            "- filter quic -> quic || udp.port == 443\n"
            "- filter syn -> tcp.flags.syn == 1 && tcp.flags.ack == 0\n"
            "- filter reset -> tcp.flags.reset == 1\n"
            "- filter fin -> tcp.flags.fin == 1\n"
            "- filter ack -> tcp.flags.ack == 1\n"
            "- filter tcp retransmissions -> tcp.analysis.retransmission || tcp.analysis.fast_retransmission\n"
            "- filter tcp errors -> tcp.analysis.flags\n"
            "- filter large packets -> frame.len > 1000\n"
            "- filter small packets -> frame.len < 100\n"
            "- filter broadcast packets -> eth.dst == ff:ff:ff:ff:ff:ff || ip.dst == 255.255.255.255\n"
            "- filter multicast packets -> eth.dst[0] & 1\n"
            "- filter port 443 -> (tcp.port == 443 || udp.port == 443)\n"
            "- filter source port 5353 -> (tcp.srcport == 5353 || udp.srcport == 5353)\n"
            "- filter destination port 53 -> (tcp.dstport == 53 || udp.dstport == 53)\n"
            "- filter ssh traffic -> (tcp.port == 22 || udp.port == 22)\n"
            "- filter telnet traffic -> (tcp.port == 23 || udp.port == 23)\n"
            "- filter smtp traffic -> (tcp.port == 25 || udp.port == 25)\n"
            "- filter ntp traffic -> (tcp.port == 123 || udp.port == 123)\n"
            "- filter smb traffic -> (tcp.port == 445 || udp.port == 445)\n"
            "- filter rdp traffic -> (tcp.port == 3389 || udp.port == 3389)\n"
            "- filter postgres traffic -> (tcp.port == 5432 || udp.port == 5432)\n"
            "- filter mysql traffic -> (tcp.port == 3306 || udp.port == 3306)\n"
            "- filter redis traffic -> (tcp.port == 6379 || udp.port == 6379)\n"
            "- show traffic from this ip -> traffic sent FROM this machine (auto-detects local IP)\n"
            "- show traffic from me -> same as above\n"
            "- show traffic from <ip> -> verify recent completed-window matches and return ip.src/ipv6.src\n"
            "- show traffic to <ip> -> verify recent completed-window matches and return ip.dst/ipv6.dst\n"
            "- show traffic between <ip1> and <ip2> -> verify recent completed-window matches and return ip.addr/ipv6.addr pair filter"
        )

    def build_display_filter_interpretation(self, original_question_text, normalized_question_text):
        # Convert common packet-inspection phrases into Wireshark filters. / Chuyển các câu hỏi soi packet phổ biến thành filter Wireshark.
        requested_ip_addresses = _extract_ips(original_question_text)
        if len(requested_ip_addresses) >= 2 and "between" in normalized_question_text:
            first_requested_address = requested_ip_addresses[0]
            second_requested_address = requested_ip_addresses[1]
            display_filter_expression = (
                f"{_ip_filter_field(first_requested_address)} == {first_requested_address} && "
                f"{_ip_filter_field(second_requested_address)} == {second_requested_address}"
            )
            return DisplayFilterInterpretation(
                interpreted_intent="traffic between two hosts",
                display_filter_expression=display_filter_expression,
                inference_explanation="Matches packets where both requested endpoints appear in the packet.",
            )

        if requested_ip_addresses and self.looks_like_filter_request(normalized_question_text):
            requested_ip_address = requested_ip_addresses[0]
            if any(direction_word in normalized_question_text for direction_word in ("from", "src", "source")):
                display_filter_expression = f"{_ip_filter_field(requested_ip_address, 'src')} == {requested_ip_address}"
                return DisplayFilterInterpretation(
                    interpreted_intent="traffic from a host",
                    display_filter_expression=display_filter_expression,
                    inference_explanation="Matches packets sent by the requested source address.",
                )
            if any(direction_word in normalized_question_text for direction_word in ("to", "dst", "dest", "destination")):
                display_filter_expression = f"{_ip_filter_field(requested_ip_address, 'dst')} == {requested_ip_address}"
                return DisplayFilterInterpretation(
                    interpreted_intent="traffic to a host",
                    display_filter_expression=display_filter_expression,
                    inference_explanation="Matches packets sent to the requested destination address.",
                )
            display_filter_expression = f"{_ip_filter_field(requested_ip_address)} == {requested_ip_address}"
            return DisplayFilterInterpretation(
                interpreted_intent="traffic for a host",
                display_filter_expression=display_filter_expression,
                inference_explanation="Matches packets where the requested address is either source or destination.",
            )

        source_port_match = re.search(r"\b(?:src|source)\s+port\s+(\d+)\b", normalized_question_text)
        if source_port_match:
            source_port_number = int(source_port_match.group(1))
            return DisplayFilterInterpretation(
                interpreted_intent="source port traffic",
                display_filter_expression=_port_filter(source_port_number, "src"),
                inference_explanation="Matches TCP or UDP packets using the requested source port.",
            )

        destination_port_match = re.search(r"\b(?:dst|dest|destination)\s+port\s+(\d+)\b", normalized_question_text)
        if destination_port_match:
            destination_port_number = int(destination_port_match.group(1))
            return DisplayFilterInterpretation(
                interpreted_intent="destination port traffic",
                display_filter_expression=_port_filter(destination_port_number, "dst"),
                inference_explanation="Matches TCP or UDP packets using the requested destination port.",
            )

        any_port_match = re.search(r"\bport\s+(\d+)\b", normalized_question_text)
        if any_port_match:
            port_number = int(any_port_match.group(1))
            return DisplayFilterInterpretation(
                interpreted_intent="port traffic",
                display_filter_expression=_port_filter(port_number),
                inference_explanation="Matches TCP or UDP packets using the requested port on either side.",
            )

        phrase_filter_mappings = [
            (
                ("retransmission", "retransmit"),
                "TCP retransmissions",
                "tcp.analysis.retransmission || tcp.analysis.fast_retransmission",
                "Matches TCP retransmission analysis flags.",
            ),
            (
                ("tcp error", "tcp errors", "analysis flags"),
                "TCP analysis flags",
                "tcp.analysis.flags",
                "Matches packets with Wireshark TCP analysis flags.",
            ),
            (
                ("tls handshake", "ssl handshake"),
                "TLS handshakes",
                "tls.handshake",
                "Matches TLS handshake records.",
            ),
            (
                ("https",),
                "HTTPS or TLS traffic",
                "tls || tcp.port == 443",
                "Matches decoded TLS plus common HTTPS port 443 traffic.",
            ),
            (
                ("http",),
                "HTTP traffic",
                "http",
                "Matches decoded HTTP packets.",
            ),
            (
                ("mdns",),
                "mDNS traffic",
                "mdns",
                "Matches multicast DNS packets.",
            ),
            (
                ("dns",),
                "DNS traffic",
                "dns",
                "Matches decoded DNS packets.",
            ),
            (
                ("dhcp", "bootp"),
                "DHCP traffic",
                "dhcp || bootp",
                "Matches DHCP or BOOTP packets.",
            ),
            (
                ("icmp", "ping"),
                "ICMP traffic",
                "icmp || icmpv6",
                "Matches IPv4 and IPv6 ICMP packets.",
            ),
            (
                ("arp",),
                "ARP traffic",
                "arp",
                "Matches ARP packets.",
            ),
            (
                ("quic",),
                "QUIC traffic",
                "quic || udp.port == 443",
                "Matches decoded QUIC plus common QUIC UDP port 443 traffic.",
            ),
            (
                ("syn",),
                "TCP SYN packets",
                "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "Matches initial TCP SYN packets.",
            ),
            (
                ("reset", "rst"),
                "TCP reset packets",
                "tcp.flags.reset == 1",
                "Matches TCP reset packets.",
            ),
            (
                ("fin",),
                "TCP FIN packets",
                "tcp.flags.fin == 1",
                "Matches TCP connection close packets.",
            ),
            (
                ("ack",),
                "TCP ACK packets",
                "tcp.flags.ack == 1",
                "Matches TCP ACK packets.",
            ),
            (
                ("large packet", "large packets", "big packet", "big packets"),
                "large packets",
                "frame.len > 1000",
                "Matches packets larger than 1000 bytes.",
            ),
            (
                ("small packet", "small packets"),
                "small packets",
                "frame.len < 100",
                "Matches packets smaller than 100 bytes.",
            ),
            (
                ("broadcast",),
                "broadcast packets",
                "eth.dst == ff:ff:ff:ff:ff:ff || ip.dst == 255.255.255.255",
                "Matches Ethernet or IPv4 broadcast packets.",
            ),
            (
                ("multicast",),
                "multicast packets",
                "eth.dst[0] & 1",
                "Matches Ethernet multicast destination addresses.",
            ),
            (
                ("udp",),
                "UDP traffic",
                "udp",
                "Matches UDP packets.",
            ),
            (
                ("tcp",),
                "TCP traffic",
                "tcp",
                "Matches TCP packets.",
            ),
        ]
        for keyword_variants, interpreted_intent, display_filter_expression, inference_explanation in phrase_filter_mappings:
            if any(_has_phrase(normalized_question_text, keyword_variant) for keyword_variant in keyword_variants):
                return DisplayFilterInterpretation(
                    interpreted_intent=interpreted_intent,
                    display_filter_expression=display_filter_expression,
                    inference_explanation=inference_explanation,
                )

        for service_name, service_port_number in SERVICE_PORTS.items():
            if re.search(rf"\b{service_name}\b", normalized_question_text):
                return DisplayFilterInterpretation(
                    interpreted_intent=f"{service_name.upper()} traffic",
                    display_filter_expression=_port_filter(service_port_number),
                    inference_explanation=f"Matches the common TCP or UDP port for {service_name.upper()}.",
                )
        return None

    def answer_live_matches(
        self,
        original_question_text,
        normalized_question_text,
        analyzed_capture_windows,
        filter_interpretation,
    ):
        # Show conversations that match a natural-language packet request. / Hiển thị conversation khớp yêu cầu packet bằng ngôn ngữ tự nhiên.
        if not analyzed_capture_windows:
            return self.answer_no_windows(filter_interpretation)

        matching_window_flow_pairs = []
        searched_capture_windows = analyzed_capture_windows[-50:]
        for analyzed_capture_window in searched_capture_windows:
            for ranked_flow_summary in analyzed_capture_window.ranked_flow_summaries:
                if _flow_matches_question(ranked_flow_summary, original_question_text, normalized_question_text):
                    matching_window_flow_pairs.append((analyzed_capture_window, ranked_flow_summary))

        intent = filter_interpretation.interpreted_intent
        display_filter = filter_interpretation.display_filter_expression

        if not matching_window_flow_pairs:
            protocol_counter, _ = _protocol_breakdown_from_flows(searched_capture_windows)
            lines = [
                f"=== {intent.title()} ===",
                f"Wireshark filter:  {display_filter}",
                f"Windows searched:  {len(searched_capture_windows)}",
                f"Result:  No {intent} flows detected in the analyzed data.",
            ]
            if protocol_counter:
                top_protocols = protocol_counter.most_common(6)
                breakdown = "  |  ".join(
                    f"{proto}: {cnt} pkts" for proto, cnt in top_protocols
                )
                lines.append(f"What IS in this data:  {breakdown}")
            return "\n".join(lines)

        matching_window_flow_pairs.sort(
            key=lambda pair: (pair[1].packet_count, pair[1].risk_score),
            reverse=True,
        )
        matching_packet_count = sum(f.packet_count for _, f in matching_window_flow_pairs)
        matching_byte_count = sum(f.byte_count for _, f in matching_window_flow_pairs)

        lines = [
            f"=== {intent.title()} ===",
            f"Wireshark filter:  {display_filter}",
            f"Windows searched:  {len(searched_capture_windows)}  |  "
            f"Matching flows: {len(matching_window_flow_pairs)}  |  "
            f"Packets: {matching_packet_count}  |  Bytes: {matching_byte_count}",
            "Conversations:",
        ]
        for i, (win, flow) in enumerate(matching_window_flow_pairs[:10], 1):
            lines.append(
                f"  {i}. [{_clock(win.window_start)}-{_clock(win.window_end)}] {win.window_label.upper()}"
            )
            lines.append("     " + _format_ranked_flow(flow).replace("\n", "\n     "))
        return "\n".join(lines)

    def answer_no_windows(self, filter_interpretation):
        return "\n".join([
            f"=== {filter_interpretation.interpreted_intent.title()} ===",
            f"Wireshark filter:  {filter_interpretation.display_filter_expression}",
            "No analyzed windows available yet — capture is still warming up.",
        ])

    def answer_summary(self, analyzed_capture_windows):
        # Summarize the newest analyzed window. / Tóm tắt window đã phân tích mới nhất.
        if not analyzed_capture_windows:
            return self._no_analyzed_window_panel(
                "Wireshark Live Summary",
                "I cannot verify live traffic context yet because no analyzed capture window is available.",
            )

        latest_capture_window = analyzed_capture_windows[-1]
        response_line_collection = _window_panel(latest_capture_window, "Wireshark Live Summary")
        if latest_capture_window.ranked_flow_summaries:
            response_line_collection.append("Most Relevant Conversation:")
            response_line_collection.append(
                "  " + _format_ranked_flow(latest_capture_window.ranked_flow_summaries[0], 1).replace("\n", "\n  ")
            )
        return "\n".join(response_line_collection)

    def answer_suspicious(self, analyzed_capture_windows):
        if not analyzed_capture_windows:
            return "No analyzed windows yet."

        model_scored_windows = [w for w in analyzed_capture_windows if w.window_label != "warmup"]
        suspicious_windows = [w for w in model_scored_windows if w.window_label == "suspicious"]

        if not model_scored_windows:
            return "Model has not scored any windows yet — still in warmup."

        if not suspicious_windows:
            lines = [
                "=== Suspicious Traffic Detected ===",
                f"No suspicious windows detected out of {len(model_scored_windows)} scored.",
                "",
                "Latest scored window:",
            ]
            latest = model_scored_windows[-1]
            fv = latest.window_feature_values
            protocols = _distinct_protocols_from_flows(latest.ranked_flow_summaries)
            lines += [
                f"  Time:      {_clock(latest.window_start)} - {_clock(latest.window_end)}",
                f"  Status:    NORMAL",
                f"  Packets:   {fv.get('packets', 0)}",
                f"  Protocols: {protocols or 'none'}",
            ]
            if latest.ranked_flow_summaries:
                top = latest.ranked_flow_summaries[0]
                lines.append(f"  Top:       {top.source_ip} -> {top.destination_ip} ({top.protocol_name})")
            return "\n".join(lines)

        shown_windows = suspicious_windows[-10:]
        lines = [
            "=== Suspicious Traffic Detected ===",
            f"Suspicious: {len(suspicious_windows)}  |  Normal: {len(model_scored_windows) - len(suspicious_windows)}  |  Total scored: {len(model_scored_windows)}",
        ]
        for alert_index, win in enumerate(shown_windows, 1):
            fv = win.window_feature_values
            reason = win.inference_summary.replace("[Inference] ", "").replace("[Inference]", "").strip()
            protocols = _distinct_protocols_from_flows(win.ranked_flow_summaries)
            triage_result = self.triage_engine.triage(win)
            lines += [
                "",
                f"[Alert {alert_index}]  {_clock(win.window_start)} - {_clock(win.window_end)}",
                f"  Threat:    {reason}",
                f"  Triage:    {triage_result.one_liner()}",
                f"  Packets:   {fv.get('packets', 0)}",
                f"  Protocols: {protocols or 'none'}",
            ]
            if win.ranked_flow_summaries:
                lines.append("  Findings:")
                for finding_index, flow in enumerate(win.ranked_flow_summaries[:5], 1):
                    lines.append(_format_finding(flow, finding_index))
        lines.append("\nType 'triage' for full risk breakdown of each alert.")
        return "\n".join(lines)

    def answer_triage(self, analyzed_capture_windows):
        if not analyzed_capture_windows:
            return "No analyzed windows yet."
        suspicious_windows = [
            w for w in analyzed_capture_windows
            if w.window_label == "suspicious"
        ]
        if not suspicious_windows:
            return "=== Risk Triage ===\nNo suspicious windows to triage."

        shown = suspicious_windows[-10:]
        lines = [
            "=== Risk Triage — Full Assessment ===",
            f"Assessing {len(shown)} suspicious window(s).",
            "",
            "─── How the Triage Engine Scores Each Alert ───────────────────────────",
            "  Each factor adds (+) or subtracts (−) points on a 0–100 scale.",
            "  High positive score = strong attack signals.",
            "  High negative contributions = false positive indicators.",
            "",
            "  Source origin",
            "    External IP(s) detected          +15 to +30  (more IPs = higher risk)",
            "    Internal-only source             −20         (likely authorized user/service)",
            "",
            "  Time of day",
            "    Off-hours activity               +15         (unusual — raises suspicion)",
            "    Business hours                   −10         (normal work activity pattern)",
            "",
            "  Connection attempt rate (SYN/min)",
            "    > 30/min                         +35         (automated tool — brute force/scanner)",
            "    10–30/min                        +20         (scripted activity)",
            "    3–10/min                         +8          (could be manual retry)",
            "    1–5 total SYN packets            −15         (forgot-password pattern)",
            "",
            "  Connection success rate",
            "    >80% of SYNs rejected (RST)      +20         (attack in progress — no entry yet)",
            "    <20% rejected, >3 SYNs           −25         (user authenticated → FP signal)",
            "",
            "  Port diversity",
            "    >20 destination ports            +30         (nmap/masscan wide sweep)",
            "    10–20 destination ports          +15         (targeted service discovery)",
            "",
            "  Source diversity (DDoS signal)",
            "    >10 unique source IPs + SYN      +40         (distributed flood — DDoS pattern)",
            "    5–10 unique source IPs + SYN     +20         (possible coordinated botnet)",
            "",
            "  Protocol risk",
            "    SSH on non-standard port         +15         (evasion / tunneling risk)",
            "    Telnet detected                  +20         (credentials in plaintext)",
            "    RDP detected                     +10         (remote desktop exposure)",
            "    Large packets to external IP     +20         (possible data exfiltration)",
            "",
            "  ARP / network layer attacks",
            "    Gratuitous ARP flood + high ARP  +60         (Ettercap-style MiTM — ICS traffic intercepted)",
            "    Elevated gratuitous ARP          +25         (possible ARP poisoning or misconfigured device)",
            "    MAC claiming multiple IPs        +30         (classic ARP spoofing indicator)",
            "    ARP host discovery sweep (>20)   +20         (automated host scan — nmap -sn or Ettercap)",
            "    ARP target diversity (10–20)     +10         (possible network mapping)",
            "",
            "  Lateral movement / host discovery",
            "    Fan-out to >5 hosts, short flows +25         (post-compromise host sweep — pivoted attacker)",
            "",
            "  Cross-subnet source (RFC1918)",
            "    Source from different /8 block   +10         (172.x.x.x attacking 10.x.x.x etc.)",
            "",
            "  HTTP / application-layer (web recon & ICS)",
            "    ICS/HMI endpoint accessed        +65         (alarm logs, screen data, event logs on industrial system)",
            "    Auth challenge pattern (401→200) +25         (valid creds replayed systematically — credential compromise indicator)",
            "    HTTP 401 failures only           +15         (repeated auth rejections)",
            "    Wide web path enumeration        +20         (>10 unique URLs — automated crawler or dirb/nikto)",
            "    Moderate web enumeration         +10         (5–10 unique URLs — targeted recon)",
            "    Sensitive path access            +20         (admin, config, backup, shell paths targeted)",
            "",
            "  Score bands:",
            "    0–14   → INFO     likely false positive or scheduled job",
            "    15–34  → LOW      user error, internal misconfiguration",
            "    35–54  → MEDIUM   ambiguous — verify before escalating",
            "    55–74  → HIGH     strong attack indicators — act soon",
            "    75–100 → CRITICAL confirmed attack pattern — act immediately",
            "────────────────────────────────────────────────────────────────────────",
            "",
        ]
        for i, win in enumerate(shown, 1):
            result = self.triage_engine.triage(win)
            lines.append(result.format_full(alert_index=i))
            lines.append("")
        return "\n".join(lines)

    def answer_filters(self, analyzed_capture_windows):
        # Collect the most recent flows that can become Wireshark filters. / Gom các flow gần nhất có thể chuyển thành filter Wireshark.
        if not analyzed_capture_windows:
            return self._no_analyzed_window_panel(
                "Wireshark Display Filters From Recent Conversations",
                "I cannot verify recent completed-window filters yet because no analyzed capture window is available.",
            )

        recent_window_flow_pairs = []
        for analyzed_capture_window in reversed(analyzed_capture_windows):
            for ranked_flow_summary in analyzed_capture_window.ranked_flow_summaries:
                recent_window_flow_pairs.append((analyzed_capture_window, ranked_flow_summary))
            if len(recent_window_flow_pairs) >= 5:
                break

        if not recent_window_flow_pairs:
            return self._no_analyzed_window_panel(
                "Wireshark Display Filters From Recent Conversations",
                "I cannot verify recent completed-window filters because no ranked conversations are available.",
            )

        response_line_collection = ["=== Wireshark Display Filters From Recent Conversations ==="]
        for filter_index, (analyzed_capture_window, ranked_flow_summary) in enumerate(recent_window_flow_pairs[:5], 1):
            response_line_collection.append(
                f"{filter_index}. Window: {_clock(analyzed_capture_window.window_start)}-"
                f"{_clock(analyzed_capture_window.window_end)} | "
                f"State: {analyzed_capture_window.window_label.upper()} | "
                f"Risk: {ranked_flow_summary.risk_score:.2f}\n"
                f"   Display Filter: {ranked_flow_to_filter(ranked_flow_summary)}"
            )
        return "\n".join(response_line_collection)

    def answer_top_flows(self, analyzed_capture_windows):
        # Rank flows across recent windows by local risk score. / Xếp hạng flow trong các window gần đây theo điểm rủi ro cục bộ.
        if not analyzed_capture_windows:
            return self._no_analyzed_window_panel(
                "Wireshark Conversations: Top Recent Risky Flows",
                "I cannot verify recent completed-window conversations yet because no analyzed capture window is available.",
            )

        ranked_recent_window_flow_pairs = []
        for analyzed_capture_window in analyzed_capture_windows[-10:]:
            for ranked_flow_summary in analyzed_capture_window.ranked_flow_summaries:
                ranked_recent_window_flow_pairs.append((analyzed_capture_window, ranked_flow_summary))
        ranked_recent_window_flow_pairs.sort(
            key=lambda ranked_window_flow_pair: ranked_window_flow_pair[1].risk_score,
            reverse=True,
        )
        if not ranked_recent_window_flow_pairs:
            return self._no_analyzed_window_panel(
                "Wireshark Conversations: Top Recent Risky Flows",
                "I cannot verify recent completed-window conversations because no ranked flow data is available.",
            )

        response_line_collection = ["=== Wireshark Conversations: Top Recent Risky Flows ==="]
        for flow_index, (analyzed_capture_window, ranked_flow_summary) in enumerate(ranked_recent_window_flow_pairs[:10], 1):
            response_line_collection.append("")
            response_line_collection.append(
                f"{flow_index}. Window {_clock(analyzed_capture_window.window_start)}-"
                f"{_clock(analyzed_capture_window.window_end)} "
                f"{analyzed_capture_window.window_label.upper()}"
            )
            response_line_collection.append(_format_ranked_flow(ranked_flow_summary, flow_index))
        return "\n".join(response_line_collection)

    def answer_ip(self, requested_ip_address, analyzed_capture_windows):
        # Drill into recent flows that involve a requested IP address. / Xem sâu các flow gần đây liên quan tới IP user hỏi.
        if not analyzed_capture_windows:
            return self._no_analyzed_window_panel(
                f"Wireshark Conversations For {requested_ip_address}",
                "I cannot verify live matches yet because no analyzed capture window is available.",
            )

        matching_window_flow_pairs = []
        for analyzed_capture_window in analyzed_capture_windows:
            for ranked_flow_summary in analyzed_capture_window.ranked_flow_summaries:
                if requested_ip_address in {ranked_flow_summary.source_ip, ranked_flow_summary.destination_ip}:
                    matching_window_flow_pairs.append((analyzed_capture_window, ranked_flow_summary))

        if not matching_window_flow_pairs:
            return "\n".join(
                [
                    f"=== Wireshark Conversations For {requested_ip_address} ===",
                    format_unverified_statement("I cannot verify a recent completed-window match for this request."),
                    f"Completed windows searched: {len(analyzed_capture_windows)}",
                ]
            )

        matching_window_flow_pairs.sort(
            key=lambda matching_window_flow_pair: matching_window_flow_pair[1].risk_score,
            reverse=True,
        )
        response_line_collection = [f"=== Wireshark Conversations For {requested_ip_address} ==="]
        for conversation_index, (analyzed_capture_window, ranked_flow_summary) in enumerate(matching_window_flow_pairs[:10], 1):
            response_line_collection.append("")
            response_line_collection.append(
                f"{conversation_index}. Window {_clock(analyzed_capture_window.window_start)}-"
                f"{_clock(analyzed_capture_window.window_end)} "
                f"{analyzed_capture_window.window_label.upper()} | "
                f"Expert Info: {analyzed_capture_window.inference_summary}"
            )
            response_line_collection.append(_format_ranked_flow(ranked_flow_summary, conversation_index))
        return "\n".join(response_line_collection)
