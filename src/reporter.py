import csv
import os
from datetime import datetime

from src.intelligence import ranked_flow_to_filter

SIEM_LOG_PATH = "logs/siem.log"
_SIEM_LOG_FIELDS = [
    "timestamp", "alert_type", "severity", "mitre_id",
    "src_ips", "dst_ips", "packets", "window_start", "window_end",
]

_SOC_SEPARATOR = "═" * 56
_SOC_THIN_SEP  = "─" * 56


# CSV column order for persisted window summaries. / Thứ tự cột CSV cho các summary theo window.
CSV_FIELDS = [
    "timestamp",
    "window_start",
    "window_end",
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
    "arp_max_ips_per_mac",
    "arp_gratuitous_ratio",
    "arp_sweep_unique_targets",
    "dns_ratio",
    "dns_ptr_ratio",
    "enip_ratio",
    "telnet_ratio",
    "http_ratio",
    "http_401_ratio",
    "http_unique_uri_count",
    "http_ics_path_hit",
    "http_sensitive_path_ratio",
    "score",
    "label",
    "summary",
]


# Format timestamps consistently for terminal output. / Định dạng timestamp thống nhất cho output terminal.
def format_clock(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# Message for an empty capture window. / Thông báo cho window không có traffic.
def format_empty_window(window_end):
    return f"[{format_clock(window_end)}] No traffic captured in this window."


# Print warmup progress before the baseline model is trained. / In tiến trình warmup trước khi model baseline được train.
def print_warmup(window_end, window_feature_values, remaining_warmup_window_count):
    print(
        f"[{format_clock(window_end)}] Warmup window collected. "
        f"Packets={window_feature_values['packets']} "
        f"Flows={window_feature_values['unique_flows']} "
        f"Remaining={remaining_warmup_window_count}"
    )


# Notify when the baseline model is ready. / Thông báo khi model baseline đã sẵn sàng.
def print_baseline_ready(window_end):
    print(f"[{format_clock(window_end)}] Baseline model trained.")


def _build_alert_evidence(window_feature_values):
    fv = window_feature_values
    lines = []
    syn_ratio = fv.get("syn_ratio", 0)
    if syn_ratio > 0.1:
        lines.append(f"SYN ratio: {syn_ratio:.2f}")
    unique_dst_ips = int(fv.get("unique_dst_ips", 0))
    if unique_dst_ips > 1:
        lines.append(f"Unique destinations: {unique_dst_ips}")
    unique_dst_ports = int(fv.get("unique_dst_ports", 0))
    if unique_dst_ports > 3:
        lines.append(f"Destination ports: {unique_dst_ports}")
    arp_grat = fv.get("arp_gratuitous_ratio", 0)
    if arp_grat > 0.05:
        lines.append(f"Gratuitous ARP ratio: {arp_grat:.2f}")
    arp_max = int(fv.get("arp_max_ips_per_mac", 0))
    if arp_max > 1:
        lines.append(f"Max IPs per MAC: {arp_max}")
    lines.append(f"Packets: {int(fv.get('packets', 0))}")
    return lines


def print_detection(
    window_end,
    window_feature_values,
    ranked_flow_summaries,
    window_label,
    inference_summary,
    display_top_flows=5,
    alert_severity=None,
):
    from src.triage import get_mitre_id

    if window_label != "suspicious":
        pkts = window_feature_values.get("packets", 0)
        flows = window_feature_values.get("unique_flows", 0)
        print(f"[{format_clock(window_end)}] NORMAL | Packets={pkts} | Flows={flows}")
        return

    severity = alert_severity or "LOW"
    threat_text = inference_summary.replace("[Inference] ", "").replace("[Inference]", "").strip()
    mitre_id = get_mitre_id(threat_text)
    mitre_tag = f"  [{mitre_id}]" if mitre_id else ""

    src_ips = list({f.source_ip for f in ranked_flow_summaries if f.source_ip not in {"unknown", ""}})[:3]
    src_display = ", ".join(src_ips) if src_ips else "unknown"

    evidence_lines = _build_alert_evidence(window_feature_values)
    ts = datetime.fromtimestamp(window_end).strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{_SOC_SEPARATOR}")
    print(f"[{ts}] ALERT — {severity}")
    print(_SOC_THIN_SEP)
    print(f"Threat   : {threat_text}{mitre_tag}")
    print(f"Source   : {src_display}")
    print(f"Severity : {severity}")
    if evidence_lines:
        print("Evidence :")
        for line in evidence_lines:
            print(f"  - {line}")

    top_flows = ranked_flow_summaries[:display_top_flows]
    if top_flows:
        print("\nTop Flows:")
        for i, flow in enumerate(top_flows, 1):
            print(f"  {i}. {flow.source_ip} → {flow.destination_ip}  [{flow.protocol_name}, {flow.packet_count} pkts]")
            print(f"     Filter: {ranked_flow_to_filter(flow)}")
    print(_SOC_SEPARATOR)


def write_siem_log(siem_log_path, window_start, window_end, alert_type, severity, mitre_id, ranked_flow_summaries, packets):
    log_dir = os.path.dirname(siem_log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    src_ips = "|".join(sorted({f.source_ip for f in ranked_flow_summaries if f.source_ip not in {"unknown", ""}}))
    dst_ips = "|".join(sorted({f.destination_ip for f in ranked_flow_summaries if f.destination_ip not in {"unknown", ""}}))

    row = {
        "timestamp":    datetime.now().isoformat(),
        "alert_type":   alert_type,
        "severity":     severity,
        "mitre_id":     mitre_id,
        "src_ips":      src_ips,
        "dst_ips":      dst_ips,
        "packets":      int(packets),
        "window_start": datetime.fromtimestamp(window_start).isoformat(),
        "window_end":   datetime.fromtimestamp(window_end).isoformat(),
    }

    write_header = not os.path.exists(siem_log_path) or os.path.getsize(siem_log_path) == 0
    with open(siem_log_path, "a", newline="") as log_file:
        writer = csv.DictWriter(log_file, fieldnames=_SIEM_LOG_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


# Append one analyzed window to CSV output. / Ghi thêm một window đã phân tích vào file CSV.
def write_row(output_csv, window_start, window_end, window_feature_values, anomaly_score, window_label, inference_summary):
    # Mix runtime metadata with computed ML features. / Gộp metadata runtime với feature đã tính cho ML.
    csv_row_values = {
        "timestamp": datetime.now().isoformat(),
        "window_start": datetime.fromtimestamp(window_start).isoformat(),
        "window_end": datetime.fromtimestamp(window_end).isoformat(),
        "score": anomaly_score,
        "label": window_label,
        "summary": inference_summary,
    }
    csv_row_values.update(window_feature_values)

    # Create the output directory lazily. / Tạo thư mục output khi cần.
    output_dir = os.path.dirname(output_csv)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Write the header only for new or empty CSV files. / Chỉ ghi header cho file CSV mới hoặc đang rỗng.
    write_header = not os.path.exists(output_csv) or os.path.getsize(output_csv) == 0
    with open(output_csv, "a", newline="") as csv_file_handle:
        writer = csv.DictWriter(csv_file_handle, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(csv_row_values)
