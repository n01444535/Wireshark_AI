import argparse


# Parse CLI values that must be positive integers. / Phân tích giá trị CLI bắt buộc là số nguyên dương.
def positive_int(candidate_text):
    parsed = int(candidate_text)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


# Validate IsolationForest contamination range. / Kiểm tra khoảng contamination hợp lệ cho IsolationForest.
def contamination_value(candidate_text):
    parsed = float(candidate_text)
    if parsed <= 0.0 or parsed > 0.5:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 0.5")
    return parsed


# Build all command-line options for the capture app. / Tạo toàn bộ tuỳ chọn dòng lệnh cho app capture.
def build_parser():
    parser = argparse.ArgumentParser()
    # Capture source: live interface or pcap file (exactly one required). / Nguồn capture: interface live hoặc file pcap (phải chọn đúng một).
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--interface", default=None, help="Network interface for live capture (e.g. en0)")
    source_group.add_argument("--pcap", default=None, metavar="FILE", help="Path to a .pcap file to analyse offline")
    parser.add_argument("--window-seconds", type=positive_int, default=10)
    parser.add_argument("--warmup-windows", type=positive_int, default=6)
    parser.add_argument("--contamination", type=contamination_value, default=0.15)

    # Output and display controls. / Cấu hình output và cách hiển thị kết quả.
    parser.add_argument("--output-csv", default="results/live_traffic_windows.csv")
    parser.add_argument("--display-top-flows", type=positive_int, default=5)

    # tshark and packet selection controls. / Cấu hình tshark và bộ lọc packet.
    parser.add_argument("--tshark-path", default="tshark")
    parser.add_argument("--filter", default="")
    parser.add_argument("--max-packets-per-window", type=positive_int, default=50000)

    # Disable live terminal questions for automation. / Tắt hỏi đáp live trong terminal khi chạy tự động.
    parser.add_argument("--no-interactive", action="store_true")
    # Show every window while interactive mode is active. / Hiển thị từng window khi chế độ tương tác đang bật.
    parser.add_argument("--show-window-events", action="store_true")
    # Replace real IPs and MACs in all output with HOST_A, HOST_B, ... aliases.
    parser.add_argument("--sanitize", action="store_true", help="Anonymize IPs and MACs in output (HOST_A, HOST_B, ...)")
    # Write a markdown analysis report to the specified path after processing completes.
    parser.add_argument("--report", default=None, metavar="PATH", help="Write a markdown analysis report to PATH after processing")
    return parser
