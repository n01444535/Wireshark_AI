import statistics
from collections import Counter, defaultdict

from src.models import RankedFlowSummary


# Ports that often matter during security triage. / Các port thường đáng chú ý khi phân tích bảo mật.
SUSPICIOUS_PORTS = {
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 138, 139, 143,
    161, 389, 443, 445, 512, 513, 514, 1433, 1521, 2049, 2375, 3306,
    3389, 5432, 5900, 6379, 8080, 8443, 9200,
}

# URL path fragments that indicate ICS/SCADA/HMI web interfaces.
_ICS_PATH_KEYWORDS = {
    # PeakHMI screen endpoints
    "scrl", "scrs", "scrsi",
    # Operational log pages
    "alarmlog", "alarmlogs", "eventlog", "eventlogs",
    # Process data endpoints
    "historian", "trend", "recipe", "setpoint",
    # ICS vendor web UIs
    "codesys", "wincc",
    # Tag/live-data browsers
    "realtime", "tagbrowser",
    # Allen-Bradley / Rockwell Automation RSLinx Classic embedded web server
    "navtree", "radevice", "ablogo", "ralogo", "diagover",
    "urlhdl", "dataview", "netset", "newdata",
    # Generic ICS/SCADA platform signatures
    "ovation", "wonderware", "ignition", "cimplicity",
}

# Generic sensitive HTTP path keywords (non-ICS).
_SENSITIVE_HTTP_KEYWORDS = {
    "admin", "config", "configuration", "settings",
    "password", "passwd", "credential",
    "backup", "export", "shell", "cmd", "exec",
    "debug", "console", ".env", "wp-admin", "phpinfo",
}


def _is_ics_uri(uri: str) -> bool:
    lower = uri.lower()
    return any(kw in lower for kw in _ICS_PATH_KEYWORDS)


def _is_sensitive_http_uri(uri: str) -> bool:
    lower = uri.lower()
    return any(kw in lower for kw in _SENSITIVE_HTTP_KEYWORDS)


# Mean helper that stays safe for empty lists. / Hàm tính trung bình an toàn khi danh sách rỗng.
def calculate_safe_mean(numeric_values):
    if not numeric_values:
        return 0.0
    return float(statistics.mean(numeric_values))


# Population standard deviation helper that stays safe for small lists. / Hàm độ lệch chuẩn an toàn cho danh sách nhỏ.
def calculate_safe_population_std(numeric_values):
    if not numeric_values or len(numeric_values) < 2:
        return 0.0
    return float(statistics.pstdev(numeric_values))


# Ordered feature names used by both scaler and model. / Danh sách feature có thứ tự dùng cho scaler và model.
def ordered_window_feature_names():
    return [
        "packets",
        "bytes_total",
        "bytes_mean",
        "bytes_std",
        "unique_src_ips",
        "unique_dst_ips",
        "unique_src_ports",
        "unique_dst_ports",
        "unique_flows",
        "protocol_tcp_ratio",
        "protocol_udp_ratio",
        "protocol_icmp_ratio",
        "protocol_other_ratio",
        "syn_ratio",
        "ack_ratio",
        "rst_ratio",
        "fin_ratio",
        "psh_ratio",
        "urg_ratio",
        "small_packet_ratio",
        "large_packet_ratio",
        "mean_ttl",
        "std_ttl",
        "mean_packets_per_flow",
        "max_packets_single_flow",
        "mean_bytes_per_flow",
        "max_bytes_single_flow",
        "suspicious_port_ratio",
        "arp_ratio",
        "dns_ratio",
        "enip_ratio",
        "telnet_ratio",
    ]


# Convert raw packets in one time window into model features and ranked flows. / Chuyển packet thô trong một window thành feature và flow đã xếp hạng.
def build_window_feature_values(packet_records):
    if not packet_records:
        return None, None, "no traffic captured"

    # Basic packet-level aggregates. / Các thống kê cơ bản ở mức packet.
    packet_count = len(packet_records)
    packet_lengths = [packet_record.length for packet_record in packet_records]
    hop_limit_values = [packet_record.ttl for packet_record in packet_records if packet_record.ttl > 0]
    source_ip_addresses = {packet_record.src_ip for packet_record in packet_records}
    destination_ip_addresses = {packet_record.dst_ip for packet_record in packet_records}
    source_port_numbers = {packet_record.src_port for packet_record in packet_records if packet_record.src_port > 0}
    destination_port_numbers = {packet_record.dst_port for packet_record in packet_records if packet_record.dst_port > 0}
    protocol_counter = Counter(packet_record.protocol for packet_record in packet_records)

    # Group packets by 5-tuple flow. / Gom packet theo flow 5 thành phần.
    packets_by_flow_identifier = defaultdict(list)
    for packet_record in packet_records:
        flow_identifier = (
            packet_record.src_ip,
            packet_record.dst_ip,
            packet_record.src_port,
            packet_record.dst_port,
            packet_record.protocol,
        )
        packets_by_flow_identifier[flow_identifier].append(packet_record)
    packet_counts_per_flow = [len(flow_packet_records) for flow_packet_records in packets_by_flow_identifier.values()]
    byte_totals_per_flow = [
        sum(flow_packet_record.length for flow_packet_record in flow_packet_records)
        for flow_packet_records in packets_by_flow_identifier.values()
    ]

    # Count traffic touching security-sensitive ports. / Đếm traffic chạm tới các port nhạy cảm về bảo mật.
    suspicious_port_hits = 0
    for packet_record in packet_records:
        if packet_record.src_port in SUSPICIOUS_PORTS or packet_record.dst_port in SUSPICIOUS_PORTS:
            suspicious_port_hits += 1

    # ARP storm / poisoning analysis. / Phân tích ARP storm / ARP poisoning.
    arp_packets = [p for p in packet_records if p.arp_opcode > 0]
    arp_count = len(arp_packets)
    arp_ratio = arp_count / packet_count
    # Map each MAC address to the set of IPs it claimed within this window.
    mac_to_claimed_ips: dict = {}
    for p in arp_packets:
        if p.src_mac and p.src_ip not in {"unknown", ""}:
            mac_to_claimed_ips.setdefault(p.src_mac, set()).add(p.src_ip)
    arp_max_ips_per_mac = max((len(ips) for ips in mac_to_claimed_ips.values()), default=0)

    # Gratuitous ARP detection: ARP request where sender IP == target IP.
    # Ettercap floods these to poison ARP caches across the ICS network.
    arp_gratuitous_count = 0
    arp_sweep_targets: set = set()
    for p in arp_packets:
        if p.arp_opcode == 1:  # ARP request
            if p.src_ip and p.arp_dst_ip and p.src_ip == p.arp_dst_ip:
                arp_gratuitous_count += 1
            if p.arp_dst_ip and p.arp_dst_ip not in {"unknown", ""}:
                arp_sweep_targets.add(p.arp_dst_ip)
    arp_gratuitous_ratio = arp_gratuitous_count / packet_count
    arp_sweep_unique_targets = len(arp_sweep_targets)

    # DNS PTR sweep analysis. / Phân tích quét DNS PTR.
    dns_packets = [p for p in packet_records if p.protocol.upper() == "DNS" or p.dst_port == 53 or p.src_port == 53]
    dns_count = len(dns_packets)
    dns_ratio = dns_count / packet_count
    ptr_packets = [p for p in packet_records if p.dns_ptr_query == 1]
    dns_ptr_ratio = len(ptr_packets) / dns_count if dns_count > 0 else 0.0

    # EtherNet/IP (ENIP) / CIP ICS protocol traffic ratio. / Tỉ lệ traffic giao thức ICS EtherNet/IP.
    enip_count = sum(
        1 for p in packet_records
        if p.protocol.upper() in {"ENIP"} or p.protocol.upper().startswith("CIP")
    )
    enip_ratio = enip_count / packet_count

    # Telnet ratio — cleartext credential risk. / Tỉ lệ Telnet — rủi ro lộ thông tin xác thực.
    telnet_count = sum(
        1 for p in packet_records
        if p.dst_port == 23 or p.src_port == 23 or p.protocol.upper() == "TELNET"
    )
    telnet_ratio = telnet_count / packet_count

    # Build the numeric vector consumed by the ML pipeline. / Tạo vector số để pipeline ML sử dụng.
    window_feature_values = {
        "packets": packet_count,
        "bytes_total": sum(packet_lengths),
        "bytes_mean": calculate_safe_mean(packet_lengths),
        "bytes_std": calculate_safe_population_std(packet_lengths),
        "unique_src_ips": len(source_ip_addresses),
        "unique_dst_ips": len(destination_ip_addresses),
        "unique_src_ports": len(source_port_numbers),
        "unique_dst_ports": len(destination_port_numbers),
        "unique_flows": len(packets_by_flow_identifier),
        "protocol_tcp_ratio": protocol_counter.get("TCP", 0) / packet_count,
        "protocol_udp_ratio": protocol_counter.get("UDP", 0) / packet_count,
        "protocol_icmp_ratio": (protocol_counter.get("ICMP", 0) + protocol_counter.get("ICMPV6", 0)) / packet_count,
        "protocol_other_ratio": 1.0 - (
            protocol_counter.get("TCP", 0) +
            protocol_counter.get("UDP", 0) +
            protocol_counter.get("ICMP", 0) +
            protocol_counter.get("ICMPV6", 0)
        ) / packet_count,
        "syn_ratio": sum(packet_record.tcp_flags_syn for packet_record in packet_records) / packet_count,
        "ack_ratio": sum(packet_record.tcp_flags_ack for packet_record in packet_records) / packet_count,
        "rst_ratio": sum(packet_record.tcp_flags_rst for packet_record in packet_records) / packet_count,
        "fin_ratio": sum(packet_record.tcp_flags_fin for packet_record in packet_records) / packet_count,
        "psh_ratio": sum(packet_record.tcp_flags_psh for packet_record in packet_records) / packet_count,
        "urg_ratio": sum(packet_record.tcp_flags_urg for packet_record in packet_records) / packet_count,
        "small_packet_ratio": sum(1 for packet_record in packet_records if packet_record.length < 100) / packet_count,
        "large_packet_ratio": sum(1 for packet_record in packet_records if packet_record.length > 1000) / packet_count,
        "mean_ttl": calculate_safe_mean(hop_limit_values),
        "std_ttl": calculate_safe_population_std(hop_limit_values),
        "mean_packets_per_flow": calculate_safe_mean(packet_counts_per_flow),
        "max_packets_single_flow": max(packet_counts_per_flow) if packet_counts_per_flow else 0,
        "mean_bytes_per_flow": calculate_safe_mean(byte_totals_per_flow),
        "max_bytes_single_flow": max(byte_totals_per_flow) if byte_totals_per_flow else 0,
        "suspicious_port_ratio": suspicious_port_hits / packet_count,
        "arp_ratio": arp_ratio,
        "arp_max_ips_per_mac": float(arp_max_ips_per_mac),
        "arp_gratuitous_ratio": arp_gratuitous_ratio,
        "arp_sweep_unique_targets": float(arp_sweep_unique_targets),
        "dns_ratio": dns_ratio,
        "dns_ptr_ratio": dns_ptr_ratio,
        "enip_ratio": enip_ratio,
        "telnet_ratio": telnet_ratio,
    }

    # HTTP application-layer analysis. / Phân tích ở tầng ứng dụng HTTP.
    http_requests = [p for p in packet_records if p.http_method]
    http_responses = [p for p in packet_records if p.http_status]
    http_count = len(http_requests) + len(http_responses)
    http_ratio = http_count / packet_count

    all_http_uris = [p.http_uri for p in http_requests if p.http_uri]
    # Preserve insertion order while deduplicating. / Dedup nhưng giữ thứ tự xuất hiện.
    unique_uris = list(dict.fromkeys(all_http_uris))
    http_unique_uri_count = len(unique_uris)
    http_ics_path_hit = int(any(_is_ics_uri(u) for u in unique_uris))

    http_401_count = sum(1 for p in http_responses if p.http_status.startswith("401"))
    http_401_ratio = http_401_count / len(http_responses) if http_responses else 0.0

    sensitive_uris = [u for u in unique_uris if _is_sensitive_http_uri(u)]
    http_sensitive_path_ratio = len(sensitive_uris) / http_unique_uri_count if http_unique_uri_count else 0.0

    window_feature_values["http_ratio"] = http_ratio
    window_feature_values["http_401_ratio"] = http_401_ratio
    window_feature_values["http_unique_uri_count"] = float(http_unique_uri_count)
    window_feature_values["http_ics_path_hit"] = float(http_ics_path_hit)
    window_feature_values["http_sensitive_path_ratio"] = http_sensitive_path_ratio

    # Add rule-based context so model output has readable reasons. / Thêm ngữ cảnh theo rule để output model có lý do dễ đọc.
    inference_reason_texts = []

    # ARP poisoning / host discovery checks run first — MAC-claiming takes priority.
    if arp_max_ips_per_mac > 2:
        inference_reason_texts.append(
            f"ARP Cache Poisoning: one MAC address is claiming {int(arp_max_ips_per_mac)} different IPs"
            " — Ettercap or similar MiTM tool intercepting traffic on the ICS network"
        )
    elif arp_gratuitous_count > 0 and arp_gratuitous_ratio > 0.1:
        inference_reason_texts.append(
            f"ARP Cache Poisoning: {arp_gratuitous_count} gratuitous ARP announcements"
            " — Ettercap-style MiTM attack poisoning ICS ARP caches"
        )
    elif arp_sweep_unique_targets > 10:
        inference_reason_texts.append(
            f"ARP Host Discovery: ARP requests to {arp_sweep_unique_targets} unique target IPs"
            " — possible nmap -sn or Ettercap host sweep after initial compromise"
        )

    if http_ics_path_hit:
        ics_uris = [u for u in unique_uris if _is_ics_uri(u)]
        inference_reason_texts.append(
            f"ICS/HMI Web Recon: HTTP requests to industrial control system endpoints"
            f" ({', '.join(ics_uris[:3])})"
        )
    elif http_401_ratio > 0.3 and http_unique_uri_count > 3:
        inference_reason_texts.append(
            f"Credential Probing: {http_401_ratio:.0%} of HTTP responses are 401"
            f" — systematic auth challenge across {http_unique_uri_count} endpoints"
        )
    elif http_unique_uri_count > 5:
        inference_reason_texts.append(
            f"Web Path Enumeration: {http_unique_uri_count} unique HTTP URLs accessed"
            " — possible directory traversal or automated crawler"
        )
    # Lateral movement / fan-out scan detection.
    if window_feature_values["unique_dst_ips"] > 5 and window_feature_values["mean_packets_per_flow"] < 5 and window_feature_values["unique_flows"] > 8:
        inference_reason_texts.append(
            f"Lateral Sweep: Traffic fans out to {window_feature_values['unique_dst_ips']} unique"
            f" destination IPs (avg {window_feature_values['mean_packets_per_flow']:.1f} pkts/flow)"
            " — post-compromise host discovery or automated network mapping"
        )

    if window_feature_values["syn_ratio"] > 0.35 and window_feature_values["unique_dst_ports"] > 10:
        inference_reason_texts.append(
            "Port Scan: SYN packets sent to many destination ports — nmap / masscan style attack"
        )
    if window_feature_values["rst_ratio"] > 0.25:
        inference_reason_texts.append(
            "RST Flood: Excessive TCP resets — connection refused storm or RST-based DoS"
        )
    if window_feature_values["unique_flows"] > max(20, window_feature_values["packets"] * 0.6):
        inference_reason_texts.append(
            "Sequential Probing: Many short-lived flows — rapid open/close scanning or bot sweep"
        )
    if window_feature_values["suspicious_port_ratio"] > 0.4:
        inference_reason_texts.append(
            "Sensitive Port Access: Traffic targeting exploit-prone services (SSH, RDP, SMB, SQL)"
        )
    if window_feature_values["large_packet_ratio"] > 0.6:
        inference_reason_texts.append(
            "Bulk Transfer Anomaly: High ratio of large packets — possible data exfiltration"
        )
    if not inference_reason_texts:
        inference_reason_texts.append("traffic within learned baseline")
    inference_summary_text = "; ".join(inference_reason_texts)

    # Score each flow so the terminal can point users to the most useful packets. / Chấm điểm từng flow để terminal chỉ user tới packet đáng xem nhất.
    ranked_flow_summaries = []
    for flow_identifier, flow_packet_records in packets_by_flow_identifier.items():
        source_ip_address, destination_ip_address, source_port_number, destination_port_number, protocol_name = flow_identifier
        packet_count_in_flow = len(flow_packet_records)
        byte_count_in_flow = sum(flow_packet_record.length for flow_packet_record in flow_packet_records)
        syn_count_in_flow = sum(flow_packet_record.tcp_flags_syn for flow_packet_record in flow_packet_records)
        reset_count_in_flow = sum(flow_packet_record.tcp_flags_rst for flow_packet_record in flow_packet_records)
        risk_score = packet_count_in_flow * 0.5 + syn_count_in_flow * 2.0 + reset_count_in_flow * 2.5
        if source_port_number in SUSPICIOUS_PORTS or destination_port_number in SUSPICIOUS_PORTS:
            risk_score += 2.0
        frame_numbers_in_flow = [p.frame_number for p in flow_packet_records if p.frame_number > 0]
        first_frame_in_flow = min(frame_numbers_in_flow) if frame_numbers_in_flow else 0
        last_frame_in_flow = max(frame_numbers_in_flow) if frame_numbers_in_flow else 0
        # Collect up to 3 unique representative info strings for plain-English display. / Thu thập tối đa 3 info string đại diện để hiển thị dễ đọc.
        seen_infos = set()
        sample_infos_for_flow = []
        for pkt in flow_packet_records:
            if pkt.info and pkt.info not in seen_infos:
                seen_infos.add(pkt.info)
                sample_infos_for_flow.append(pkt.info)
                if len(sample_infos_for_flow) >= 3:
                    break

        # Collect HTTP URIs, response codes, and user-agent for this flow. / Thu thập URI, mã phản hồi và user-agent HTTP cho flow này.
        flow_uri_seen = set()
        flow_http_uris = []
        flow_status_seen = set()
        flow_http_statuses = []
        flow_http_user_agent = ""
        for pkt in flow_packet_records:
            if pkt.http_uri and pkt.http_uri not in flow_uri_seen:
                flow_uri_seen.add(pkt.http_uri)
                flow_http_uris.append(pkt.http_uri)
            if pkt.http_status and pkt.http_status not in flow_status_seen:
                flow_status_seen.add(pkt.http_status)
                flow_http_statuses.append(pkt.http_status)
            if pkt.http_user_agent and not flow_http_user_agent:
                flow_http_user_agent = pkt.http_user_agent

        # Boost risk score when the flow touches ICS endpoints. / Tăng điểm rủi ro khi flow chạm tới endpoint ICS.
        if any(_is_ics_uri(u) for u in flow_http_uris):
            risk_score += 10.0

        ranked_flow_summaries.append(
            RankedFlowSummary(
                source_ip=source_ip_address,
                destination_ip=destination_ip_address,
                source_port=source_port_number,
                destination_port=destination_port_number,
                protocol_name=protocol_name,
                packet_count=packet_count_in_flow,
                byte_count=byte_count_in_flow,
                syn_count=syn_count_in_flow,
                reset_count=reset_count_in_flow,
                risk_score=risk_score,
                first_frame=first_frame_in_flow,
                last_frame=last_frame_in_flow,
                sample_infos=tuple(sample_infos_for_flow),
                http_uris=tuple(flow_http_uris),
                http_status_codes=tuple(flow_http_statuses),
                http_user_agent=flow_http_user_agent,
            )
        )
    ranked_flow_summaries.sort(key=lambda ranked_flow_summary: ranked_flow_summary.risk_score, reverse=True)

    return window_feature_values, ranked_flow_summaries, inference_summary_text
