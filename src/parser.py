import csv

from src.models import PacketRecord


# Convert an optional packet field into an integer. / Chuyển một field packet tuỳ chọn thành số nguyên.
def parse_optional_packet_int(packet_field_text):
    if packet_field_text is None or packet_field_text == "":
        return None
    try:
        # tshark can emit repeated field values; keep the first one. / tshark có thể xuất nhiều giá trị; giữ giá trị đầu tiên.
        if "," in packet_field_text:
            packet_field_text = packet_field_text.split(",")[0]
        return int(float(packet_field_text))
    except Exception:
        return None


# Convert an optional packet field into a float. / Chuyển một field packet tuỳ chọn thành số thực.
def parse_optional_packet_float(packet_field_text):
    if packet_field_text is None or packet_field_text == "":
        return None
    try:
        return float(packet_field_text)
    except Exception:
        return None


# Normalize tshark TCP flag fields into 0 or 1. / Chuẩn hoá cờ TCP từ tshark thành 0 hoặc 1.
def parse_tcp_flag_field(packet_field_text):
    if packet_field_text in ("1", "True", "true"):
        return 1
    return 0


# Parse one CSV line emitted by tshark into a PacketRecord. / Phân tích một dòng CSV từ tshark thành PacketRecord.
def parse_tshark_csv_line(packet_csv_line: str):
    try:
        # Use csv.reader because tshark fields are quoted CSV. / Dùng csv.reader vì field của tshark là CSV có quote.
        packet_field_values = next(csv.reader([packet_csv_line]))
    except Exception:
        return None
    if len(packet_field_values) < 18:
        return None

    # Prefer IPv4 fields, then fall back to IPv6 fields. / Ưu tiên trường IPv4, sau đó dùng IPv6 nếu có.
    packet_timestamp = parse_optional_packet_float(packet_field_values[0])
    source_ip_address = packet_field_values[1] or packet_field_values[3] or "unknown"
    destination_ip_address = packet_field_values[2] or packet_field_values[4] or "unknown"

    # Merge TCP and UDP ports into one normalized pair. / Gộp port TCP và UDP thành một cặp đã chuẩn hoá.
    source_port_number = parse_optional_packet_int(packet_field_values[5]) or parse_optional_packet_int(packet_field_values[6]) or 0
    destination_port_number = parse_optional_packet_int(packet_field_values[7]) or parse_optional_packet_int(packet_field_values[8]) or 0
    protocol_name = (packet_field_values[9] or "OTHER").upper()
    packet_length = parse_optional_packet_int(packet_field_values[10]) or 0

    # Convert TCP flags and TTL/hop-limit into model-ready numbers. / Chuyển cờ TCP và TTL/hop-limit thành số cho model.
    syn_flag = parse_tcp_flag_field(packet_field_values[11])
    ack_flag = parse_tcp_flag_field(packet_field_values[12])
    reset_flag = parse_tcp_flag_field(packet_field_values[13])
    fin_flag = parse_tcp_flag_field(packet_field_values[14])
    push_flag = parse_tcp_flag_field(packet_field_values[15])
    urgent_flag = parse_tcp_flag_field(packet_field_values[16])
    hop_limit_value = (
        parse_optional_packet_int(packet_field_values[17]) or parse_optional_packet_int(packet_field_values[18])
        if len(packet_field_values) > 18
        else parse_optional_packet_int(packet_field_values[17])
    )
    hop_limit_value = hop_limit_value or 0
    frame_number_value = (
        parse_optional_packet_int(packet_field_values[19])
        if len(packet_field_values) > 19
        else None
    ) or 0
    info_text = packet_field_values[20].strip() if len(packet_field_values) > 20 else ""
    http_method_text = packet_field_values[21].strip() if len(packet_field_values) > 21 else ""
    http_uri_text = packet_field_values[22].strip() if len(packet_field_values) > 22 else ""
    http_status_text = packet_field_values[23].strip() if len(packet_field_values) > 23 else ""
    http_user_agent_text = packet_field_values[24].strip() if len(packet_field_values) > 24 else ""

    # ARP fields — only populated for ARP packets; opcode 1=request, 2=reply.
    arp_opcode_value = parse_optional_packet_int(
        packet_field_values[25].strip() if len(packet_field_values) > 25 else ""
    ) or 0
    arp_src_mac_text = packet_field_values[26].strip() if len(packet_field_values) > 26 else ""
    arp_src_ip_text = packet_field_values[27].strip() if len(packet_field_values) > 27 else ""
    # For ARP packets ip.src is empty; promote arp.src.proto_ipv4 so flows are still tracked.
    if source_ip_address == "unknown" and arp_src_ip_text:
        source_ip_address = arp_src_ip_text

    # ARP target protocol address — equals src when gratuitous/announcement (index 28 after arp.dst.proto_ipv4 inserted).
    arp_dst_ip_text = packet_field_values[28].strip() if len(packet_field_values) > 28 else ""

    # DNS PTR query detection — type 12 is a reverse-lookup query.
    raw_dns_type = packet_field_values[29].strip() if len(packet_field_values) > 29 else ""
    dns_ptr_query_value = 1 if raw_dns_type == "12" else 0

    if packet_timestamp is None:
        return None

    # Return one consistent packet object for downstream features. / Trả về một object packet thống nhất cho phần tạo feature.
    return PacketRecord(
        timestamp=packet_timestamp,
        src_ip=source_ip_address,
        dst_ip=destination_ip_address,
        src_port=source_port_number,
        dst_port=destination_port_number,
        protocol=protocol_name,
        length=packet_length,
        tcp_flags_syn=syn_flag,
        tcp_flags_ack=ack_flag,
        tcp_flags_rst=reset_flag,
        tcp_flags_fin=fin_flag,
        tcp_flags_psh=push_flag,
        tcp_flags_urg=urgent_flag,
        ttl=hop_limit_value,
        frame_number=frame_number_value,
        info=info_text,
        http_method=http_method_text,
        http_uri=http_uri_text,
        http_status=http_status_text,
        http_user_agent=http_user_agent_text,
        arp_opcode=arp_opcode_value,
        src_mac=arp_src_mac_text,
        arp_dst_ip=arp_dst_ip_text,
        dns_ptr_query=dns_ptr_query_value,
    )
