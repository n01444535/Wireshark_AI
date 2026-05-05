import csv
import os
from datetime import datetime

from src.intelligence import ranked_flow_to_filter


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


# Print one post-warmup detection result. / In một kết quả detection sau giai đoạn warmup.
def print_detection(
    window_end,
    window_feature_values,
    ranked_flow_summaries,
    window_label,
    inference_summary,
    display_top_flows=5,
    alert_severity=None,
):
    if window_label == "suspicious":
        severity_tag = f"[{alert_severity}] " if alert_severity else ""
        banner = f"{severity_tag}ALERT"
    else:
        banner = "NORMAL"
    print(f"\n[{format_clock(window_end)}] {banner} | Packets={window_feature_values['packets']}")
    print(f"Threat: {inference_summary}")
    top_flows = ranked_flow_summaries[:display_top_flows]
    if top_flows:
        print("Findings:")
        for i, flow in enumerate(top_flows, 1):
            if flow.first_frame > 0:
                if flow.first_frame == flow.last_frame:
                    frame_info = f" | frame #{flow.first_frame}"
                else:
                    frame_info = f" | frames #{flow.first_frame}-#{flow.last_frame}"
            else:
                frame_info = ""
            print(f"  {i}. {flow.source_ip} -> {flow.destination_ip} | {flow.protocol_name}{frame_info}")
            print(f"     Filter: {ranked_flow_to_filter(flow)}")


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
