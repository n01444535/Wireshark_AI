from dataclasses import dataclass


# Normalized packet fields used by the feature builder. / Các trường packet đã chuẩn hoá để dùng khi tạo feature.
@dataclass(frozen=True)
class PacketRecord:
    # Packet time and network endpoints. / Thời điểm packet và hai đầu kết nối mạng.
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    # Protocol, packet size, TCP flags, and hop limit. / Protocol, kích thước packet, cờ TCP và hop limit.
    protocol: str
    length: int
    tcp_flags_syn: int
    tcp_flags_ack: int
    tcp_flags_rst: int
    tcp_flags_fin: int
    tcp_flags_psh: int
    tcp_flags_urg: int
    ttl: int
    frame_number: int = 0
    info: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_status: str = ""
    http_user_agent: str = ""
    arp_opcode: int = 0       # 1=request 2=reply; 0 means not ARP
    src_mac: str = ""          # ARP sender MAC (for ARP poisoning detection)
    arp_dst_ip: str = ""       # ARP target protocol address (for gratuitous ARP detection)
    dns_ptr_query: int = 0    # 1 if this packet carries a DNS PTR query (type 12)


# Ranked conversation summary used across UI, CSV, and live answers. / Tóm tắt conversation đã xếp hạng dùng cho UI, CSV và câu trả lời live.
@dataclass(frozen=True)
class RankedFlowSummary:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol_name: str
    packet_count: int
    byte_count: int
    syn_count: int
    reset_count: int
    risk_score: float
    first_frame: int = 0
    last_frame: int = 0
    sample_infos: tuple = ()
    http_uris: tuple = ()
    http_status_codes: tuple = ()
    http_user_agent: str = ""
