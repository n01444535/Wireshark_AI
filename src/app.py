import collections
import json
import os
import queue
import select
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

from src.capture import TsharkCapture
from src.config import build_parser
from src.features import build_window_feature_values, ordered_window_feature_names
from src.intelligence import (
    TrafficAnswerEngine,
    TrafficMemory,
    TrafficWindow,
    format_inference_statement,
)
from src.parser import parse_tshark_csv_line
from src.reporter import format_empty_window, print_baseline_ready, print_detection, print_warmup, write_row, write_siem_log, SIEM_LOG_PATH


SYN_FLOOD_SYN_RATIO_THRESHOLD = 0.5
SYN_FLOOD_MIN_DEST_IPS = 5
PORT_SCAN_MIN_DST_PORTS = 15
SUSPICIOUS_SERVICE_PORTS = {22, 3389, 445}


def _rule_based_label(window_feature_values, ranked_flow_summaries=None):
    fv = window_feature_values
    if fv.get("http_ics_path_hit", 0):
        return "suspicious"
    if fv.get("arp_max_ips_per_mac", 0) > 2:
        return "suspicious"
    if fv.get("arp_gratuitous_ratio", 0) > 0.05 and fv.get("arp_ratio", 0) > 0.05:
        return "suspicious"
    if fv.get("telnet_ratio", 0) > 0:
        return "suspicious"
    if fv.get("arp_sweep_unique_targets", 0) > 10:
        return "suspicious"
    if (
        fv.get("unique_dst_ips", 0) > 5
        and fv.get("mean_packets_per_flow", 99) < 5
        and fv.get("unique_flows", 0) > 8
    ):
        return "suspicious"
    if (
        fv.get("syn_ratio", 0) > SYN_FLOOD_SYN_RATIO_THRESHOLD
        and fv.get("unique_dst_ips", 0) > SYN_FLOOD_MIN_DEST_IPS
    ):
        return "suspicious"
    if fv.get("unique_dst_ports", 0) > PORT_SCAN_MIN_DST_PORTS:
        return "suspicious"
    if ranked_flow_summaries:
        for flow in ranked_flow_summaries:
            if (
                flow.destination_port in SUSPICIOUS_SERVICE_PORTS
                or flow.source_port in SUSPICIOUS_SERVICE_PORTS
            ):
                return "suspicious"
    return "normal"


def _derive_suspicious_reason(window_feature_values, ranked_flow_summaries):
    fv = window_feature_values

    # ARP poisoning / MiTM — check before anything else
    mac_ips = fv.get("arp_max_ips_per_mac", 0)
    if mac_ips > 2:
        return (
            f"ARP Cache Poisoning: one MAC address is claiming {int(mac_ips)} different IPs"
            " — Ettercap or similar MiTM tool intercepting traffic on the ICS network"
        )
    if fv.get("arp_gratuitous_ratio", 0) > 0.05 and fv.get("arp_ratio", 0) > 0.05:
        grat_pct = int(fv.get("arp_gratuitous_ratio", 0) * 100)
        return (
            f"ARP Cache Poisoning: {grat_pct}% of traffic is gratuitous ARP announcements"
            " — Ettercap or similar MiTM tool intercepting ICS network communication"
        )

    # ICS/HMI web reconnaissance — check before protocol loop
    if fv.get("http_ics_path_hit", 0):
        uri_count = int(fv.get("http_unique_uri_count", 0))
        return (
            f"ICS/HMI Web Reconnaissance: {uri_count} industrial control system endpoint(s) accessed via HTTP"
            " — possible credential compromise or insider threat"
        )

    # Lateral movement / host discovery
    unique_dsts = fv.get("unique_dst_ips", 0)
    mean_pkts = fv.get("mean_packets_per_flow", 99)
    if unique_dsts > 5 and mean_pkts < 5 and fv.get("unique_flows", 0) > 8:
        return (
            f"Lateral Movement: {unique_dsts} unique destination IPs probed"
            f" (avg {mean_pkts:.1f} pkts/flow) — post-compromise host sweep after pivot"
        )

    # ARP host discovery sweep
    sweep_targets = int(fv.get("arp_sweep_unique_targets", 0))
    if sweep_targets > 10:
        return (
            f"ARP Host Discovery: {sweep_targets} unique ARP target IPs"
            " — automated network sweep (nmap -sn or Ettercap host scan after initial compromise)"
        )

    # SYN Flood: high SYN ratio targeting many destinations
    syn_ratio = fv.get("syn_ratio", 0)
    if syn_ratio > SYN_FLOOD_SYN_RATIO_THRESHOLD and unique_dsts > SYN_FLOOD_MIN_DEST_IPS:
        return (
            f"SYN Flood Suspected: SYN ratio {syn_ratio:.2f},"
            f" {int(unique_dsts)} destination IPs targeted"
            " — TCP connection flood, possible DoS attack"
        )

    # Port Scan: many destination ports with few packets per flow
    unique_dst_ports = int(fv.get("unique_dst_ports", 0))
    if unique_dst_ports > PORT_SCAN_MIN_DST_PORTS:
        avg_pkts = fv.get("mean_packets_per_flow", 0)
        return (
            f"Port Scan: {unique_dst_ports} destination ports probed"
            f" (avg {avg_pkts:.1f} pkts/flow) — service discovery sweep"
        )

    for flow in ranked_flow_summaries:
        proto = flow.protocol_name.upper()
        if proto in {"SSH", "SSHV2"}:
            non_std = next((p for p in [flow.source_port, flow.destination_port] if p not in {0, 22}), None)
            if non_std:
                return (
                    f"SSH Tunneling Risk: SSH session on non-standard port {non_std}"
                    " — possible evasion or lateral movement"
                )
            if flow.syn_count >= 3 and flow.packet_count < 15:
                return "SSH Brute Force: Repeated SYN attempts to SSH port — possible credential stuffing"
            return "SSH Anomaly: SSH session pattern deviates from baseline — verify for unauthorized access"
        if proto == "TELNET":
            return "Cleartext Protocol: Telnet detected — unencrypted, credentials exposed in plaintext"
        if proto in {"RDP", "MS-WBT-SERVER"}:
            return "RDP Exposure: Remote desktop traffic — verify for brute force or unauthorized access"
        if proto == "SMB":
            return "SMB Activity: File-sharing traffic — check for lateral movement or ransomware staging"

        # Port-based detection when protocol label is generic (e.g., TCP)
        _SERVICE_PORT_LABELS = {22: "SSH", 3389: "RDP", 445: "SMB"}
        for svc_port, svc_name in _SERVICE_PORT_LABELS.items():
            if flow.destination_port == svc_port or flow.source_port == svc_port:
                return (
                    f"Suspicious Service Access: {svc_name} (port {svc_port})"
                    f" connection {flow.source_ip} → {flow.destination_ip}"
                    " — verify for unauthorized access or brute force"
                )

    unique_src = fv.get("unique_src_ips", 0)
    if unique_src > 5 and fv.get("syn_ratio", 0) > 0.3:
        return (
            f"Possible DDoS: {unique_src} source IPs sending SYN packets"
            " — distributed connection flood pattern"
        )
    unique_flows = fv.get("unique_flows", 0)
    packets = fv.get("packets", 0)
    if unique_flows == 1 and ranked_flow_summaries:
        flow = ranked_flow_summaries[0]
        return (
            f"Single-Flow Anomaly: All {packets} packets in one"
            f" {flow.protocol_name} conversation — unusual isolated pattern"
        )

    # HTTP path enumeration without ICS keywords
    http_unique_uris = int(fv.get("http_unique_uri_count", 0))
    if http_unique_uris > 5:
        return (
            f"Web Path Enumeration: {http_unique_uris} unique HTTP URLs accessed"
            " — possible directory traversal or automated web crawler"
        )

    return "Statistical Anomaly: Traffic pattern outside learned baseline — no single dominant indicator"


_HIGH_SEVERITY_REASON_PREFIXES = (
    "ARP Cache Poisoning",
    "ICS/HMI Web Reconnaissance",
    "Cleartext Protocol",
    "SSH Brute Force",
    "SYN Flood",
)

_MEDIUM_SEVERITY_REASON_PREFIXES = (
    "Lateral Movement",
    "ARP Host Discovery",
    "SSH Tunneling",
    "RDP Exposure",
    "Possible DDoS",
    "SMB Activity",
    "Port Scan",
    "Suspicious Service Access",
)


def _classify_alert_severity(window_label, reason_text):
    if window_label != "suspicious":
        return None
    for prefix in _HIGH_SEVERITY_REASON_PREFIXES:
        if reason_text.startswith(prefix):
            return "HIGH"
    for prefix in _MEDIUM_SEVERITY_REASON_PREFIXES:
        if reason_text.startswith(prefix):
            return "MEDIUM"
    return "LOW"


def _save_to_history(history_filename, session_windows, session_source):
    if not session_windows:
        return
    os.makedirs("history", exist_ok=True)
    base = os.path.splitext(history_filename)[0]
    dest = os.path.join("history", base + ".json")
    normal_count = sum(1 for w in session_windows if w["label"] == "normal")
    suspicious_count = sum(1 for w in session_windows if w["label"] == "suspicious")
    session_data = {
        "session": base,
        "source": session_source,
        "stats": {
            "total": len(session_windows),
            "normal": normal_count,
            "suspicious": suspicious_count,
        },
        "windows": session_windows,
    }
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=2, ensure_ascii=False, default=float)
    print(f"History saved: {dest}  ({normal_count} normal, {suspicious_count} suspicious)")


def load_history_vectors(history_dir="history"):
    """Load feature vectors of normal windows from all past sessions for baseline training."""
    vectors = []
    if not os.path.isdir(history_dir):
        return vectors
    feature_names = ordered_window_feature_names()
    for fname in sorted(os.listdir(history_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(history_dir, fname)
        try:
            with open(fpath, encoding="utf-8") as f:
                session = json.load(f)
            for w in session.get("windows", []):
                if w.get("label") == "normal" and "features" in w:
                    fv = [float(w["features"].get(name, 0.0)) for name in feature_names]
                    vectors.append(fv)
        except Exception:
            continue
    return vectors


def _detect_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


# Coordinates live capture, ML training, detection, and questions. / Điều phối capture live, train ML, detection và hỏi đáp.
class LiveTrafficMLApp:
    def __init__(
        self,
        interface,
        window_seconds,
        warmup_windows,
        contamination,
        output_csv,
        display_top_flows,
        tshark_path,
        bpf_filter,
        max_packets_per_window,
        interactive,
        show_window_events,
    ):
        # Store runtime configuration from CLI arguments. / Lưu cấu hình runtime từ tham số CLI.
        self.interface = interface
        self.window_seconds = window_seconds
        self.warmup_windows = warmup_windows
        self.contamination = contamination
        self.output_csv = output_csv
        self.display_top_flows = display_top_flows
        self.tshark_path = tshark_path
        self.bpf_filter = bpf_filter
        self.max_packets_per_window = max_packets_per_window
        self.interactive = interactive
        self.interactive_tty = self.interactive and sys.stdin.isatty()
        self.show_window_events = show_window_events

        # Queues decouple tshark reading from window processing and user questions. / Queue tách việc đọc tshark khỏi xử lý window và câu hỏi user.
        self.packet_queue = queue.Queue()
        self.query_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.shutdown_notice_printed = False
        self.prompt_active = False
        self.live_query_ready_printed = False
        self.model_ready_printed = False
        self.command_used = False

        # Memory powers the live question engine. / Bộ nhớ cung cấp dữ liệu cho engine hỏi đáp live.
        self.memory = TrafficMemory()
        self.local_ip = _detect_local_ip()
        self.answer_engine = TrafficAnswerEngine(self.memory, local_ip=self.local_ip)

        # ML model and warmup vectors define the learned baseline. / Model ML và vector warmup tạo baseline đã học.
        self.scaler, self.model = self.create_model(contamination)
        self.training_feature_vectors = []

        self._history_filename = datetime.now().strftime("%d_%m_%Y_%H_%M_%S") + ".json"
        self._session_windows = []
        self._session_source = f"live:{interface}"

        # Load normal windows from past sessions to improve the anomaly baseline.
        self._historical_vectors = load_history_vectors()
        if self._historical_vectors:
            print(f"Baseline history: {len(self._historical_vectors)} normal windows loaded from past sessions.")

        # tshark capture runs in background threads. / Capture bằng tshark chạy trong các thread nền.
        self.capture = TsharkCapture(
            interface=self.interface,
            tshark_path=self.tshark_path,
            bpf_filter=self.bpf_filter,
            packet_queue=self.packet_queue,
            stop_event=self.stop_event,
        )

    def create_model(self, contamination):
        # Import sklearn lazily so --help still works without dependencies. / Import sklearn muộn để --help vẫn chạy khi thiếu dependency.
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ModuleNotFoundError:
            print("scikit-learn not found. Install it with: python3 -m pip install scikit-learn")
            sys.exit(1)
        return StandardScaler(), IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
        )

    def fit_model(self):
        # Fit scaler on history + current warmup for accurate long-term feature ranges.
        # Train IsolationForest on current warmup only — historical data calibrates the scale,
        # not the anomaly boundary, so prior sessions don't create false positives.
        scaler_data = self._historical_vectors + self.training_feature_vectors if self._historical_vectors else self.training_feature_vectors
        self.scaler.fit(scaler_data)
        scaled_warmup = self.scaler.transform(self.training_feature_vectors)
        self.model.fit(scaled_warmup)

    def _record_window(self, window_start, window_end, window_feature_values, anomaly_score, window_label, labeled_inference_summary, alert_severity=None):
        write_row(self.output_csv, window_start, window_end, window_feature_values, anomaly_score, window_label, labeled_inference_summary)
        window_entry = {
            "time": datetime.fromtimestamp(window_end).strftime("%H:%M:%S"),
            "label": window_label,
            "score": round(anomaly_score, 4),
            "summary": labeled_inference_summary,
            "features": window_feature_values,
        }
        if alert_severity:
            window_entry["severity"] = alert_severity
        self._session_windows.append(window_entry)

    def run(self):
        # Start tshark, then enter the live windowing loop. / Khởi động tshark rồi vào vòng lặp chia window live.
        self.capture.ensure_tshark()
        self.capture.start()
        print(f"Starting live capture on interface: {self.interface}")
        if self.local_ip:
            print(f"Local IP: {self.local_ip}  (use 'show traffic from this ip' to trace outbound)")
        print(f"Window size: {self.window_seconds}s")
        print(f"Warmup windows: {self.warmup_windows}")
        if self.bpf_filter:
            print(f"Capture filter: {self.bpf_filter}")
        if self.interactive_tty:
            print("Live question mode starting. Available commands: suspicious, summary, filter, top flows, ip <address>, help")
            if not self.show_window_events:
                print("Window event output is hidden in interactive mode. Type `summary` or run with `--show-window-events`.")
            print(f"Live match commands will be ready after the first {self.window_seconds}s capture window.")
            print(f"Suspicious detection will be ready after about {self.window_seconds * self.warmup_windows}s.")
            print("Questions are disabled until all stages are ready.")
        current_window_packets = []
        window_start = time.time()
        try:
            while not self.stop_event.is_set():
                # Handle pending questions between packet reads. / Xử lý câu hỏi đang chờ giữa các lần đọc packet.
                self.poll_query_input()
                self.process_queries()
                packet_wait_timeout_seconds = min(0.5, max(0.1, self.window_seconds - (time.time() - window_start)))
                try:
                    captured_packet_record = self.packet_queue.get(timeout=packet_wait_timeout_seconds)
                    current_window_packets.append(captured_packet_record)
                    if len(current_window_packets) > self.max_packets_per_window:
                        # Keep the newest packets if a burst exceeds the window cap. / Giữ các packet mới nhất nếu burst vượt giới hạn window.
                        current_window_packets.pop(0)
                except queue.Empty:
                    pass
                current_timestamp = time.time()
                if current_timestamp - window_start >= self.window_seconds:
                    # Close the current window and start a fresh one. / Đóng window hiện tại và bắt đầu window mới.
                    self.process_window(current_window_packets, window_start, current_timestamp)
                    current_window_packets = []
                    window_start = current_timestamp
                self.poll_query_input()
                self.process_queries()
        except KeyboardInterrupt:
            self.request_shutdown("User cancelled. Stopping live capture.")
        finally:
            self.shutdown()

    def print_prompt(self):
        # Print a stable prompt only after pending output is done. / Chỉ in prompt ổn định sau khi output đang chờ đã xong.
        if self.interactive_tty and not self.stop_event.is_set():
            print("question> ", end="", flush=True)
            self.prompt_active = True

    def poll_query_input(self):
        # Poll stdin without blocking packet capture. / Poll stdin mà không chặn capture packet.
        if not self.interactive_tty:
            return
        ready, _, _ = select.select([sys.stdin], [], [], 0)
        if not ready:
            return
        input_line_text = sys.stdin.readline()
        self.prompt_active = False
        if input_line_text == "":
            self.request_shutdown("Input closed. Stopping live capture.")
            return
        if input_line_text.strip():
            self.query_queue.put(input_line_text)
        else:
            self.print_prompt()

    def process_queries(self):
        # Drain all queued questions so answers stay responsive. / Xử lý hết câu hỏi trong queue để phản hồi nhanh.
        while True:
            try:
                question_text = self.query_queue.get_nowait()
            except queue.Empty:
                return
            normalized_question_text = question_text.strip().lower()
            if normalized_question_text in {"quit", "exit", "stop"}:
                self.request_shutdown("User requested stop. Stopping live capture.")
                return
            if normalized_question_text == "clear":
                if self.command_used:
                    sys.stdout.write("\033[2J\033[H")
                    sys.stdout.flush()
                    print("Commands: suspicious, summary, top flows, filter, ip <addr>, show ..., clear, help, quit")
                    self.command_used = False
                self.print_prompt()
                continue
            print()
            if not self.model_ready_printed:
                remaining = self.warmup_windows - len(self.training_feature_vectors)
                print(f"System is still warming up ({remaining} window(s) remaining). Please wait until all stages are ready before asking questions.")
                print()
                self.print_prompt()
                continue
            print(self.answer_engine.answer(question_text))
            print()
            self.command_used = True
            self.print_prompt()

    def request_shutdown(self, notice_text):
        # Print the shutdown reason once, then signal all loops. / In lý do shutdown một lần rồi báo hiệu mọi vòng lặp.
        if notice_text and not self.shutdown_notice_printed:
            print(f"\n{notice_text}")
            self.shutdown_notice_printed = True
        self.stop_event.set()

    def should_print_window_events(self):
        # Hide automatic window logs in interactive mode unless requested. / Ẩn log window tự động trong interactive mode trừ khi user yêu cầu.
        return self.show_window_events or not self.interactive_tty

    def print_readiness_notice(self, notice_text):
        # Print readiness notices without corrupting the question prompt. / In thông báo sẵn sàng mà không làm hỏng prompt câu hỏi.
        if not self.interactive_tty:
            print(notice_text)
            return
        print(f"\n{notice_text}")
        self.prompt_active = False
        if self.model_ready_printed:
            self.print_prompt()

    def process_window(self, packet_records, window_start, window_end):
        # Convert packet records into features and human-readable flow context. / Chuyển packet record thành feature và ngữ cảnh flow dễ đọc.
        window_feature_values, ranked_flow_summaries, raw_inference_summary = build_window_feature_values(
            packet_records,
        )
        if window_feature_values is None:
            if self.should_print_window_events():
                print(format_empty_window(window_end))
            return
        feature_vector = [
            window_feature_values[feature_name]
            for feature_name in ordered_window_feature_names()
        ]
        labeled_inference_summary = format_inference_statement(raw_inference_summary)

        # Warmup windows train the baseline. Rule-based attacks are flagged immediately.
        if len(self.training_feature_vectors) < self.warmup_windows:
            self.training_feature_vectors.append(feature_vector)
            remaining_warmup_window_count = self.warmup_windows - len(self.training_feature_vectors)
            if len(self.training_feature_vectors) == self.warmup_windows:
                self.fit_model()

            # Apply rule-based detection even during warmup so attacks aren't silently swallowed.
            early_label = _rule_based_label(window_feature_values, ranked_flow_summaries)
            early_severity = None
            if early_label == "suspicious":
                raw_inference_summary = _derive_suspicious_reason(window_feature_values, ranked_flow_summaries)
                labeled_inference_summary = format_inference_statement(raw_inference_summary)
                early_severity = _classify_alert_severity(early_label, raw_inference_summary)
                if self.should_print_window_events():
                    print_detection(
                        window_end,
                        window_feature_values,
                        ranked_flow_summaries,
                        "suspicious",
                        labeled_inference_summary,
                        display_top_flows=self.display_top_flows,
                        alert_severity=early_severity,
                    )
                from src.triage import get_mitre_id
                write_siem_log(
                    SIEM_LOG_PATH, window_start, window_end,
                    raw_inference_summary, early_severity or "LOW",
                    get_mitre_id(raw_inference_summary),
                    ranked_flow_summaries, window_feature_values.get("packets", 0),
                )
            else:
                if self.should_print_window_events():
                    print_warmup(window_end, window_feature_values, remaining_warmup_window_count)
                if len(self.training_feature_vectors) == self.warmup_windows:
                    if self.should_print_window_events():
                        print_baseline_ready(window_end)

            self._record_window(window_start, window_end, window_feature_values, 0.0, early_label, labeled_inference_summary, early_severity)
            self.memory.add_window(
                TrafficWindow(
                    window_start=window_start,
                    window_end=window_end,
                    window_feature_values=window_feature_values,
                    ranked_flow_summaries=ranked_flow_summaries,
                    anomaly_score=0.0,
                    window_label=early_label,
                    inference_summary=labeled_inference_summary,
                )
            )
            if not self.live_query_ready_printed:
                self.live_query_ready_printed = True
                self.print_readiness_notice("Live match commands are ready.")
            if len(self.training_feature_vectors) == self.warmup_windows and not self.model_ready_printed:
                self.model_ready_printed = True
                self.print_readiness_notice("Suspicious detection is ready.")
            return

        # Score the current window against the learned baseline. / Chấm điểm window hiện tại so với baseline đã học.
        scaled_feature_vector = self.scaler.transform([feature_vector])
        anomaly_score = -float(self.model.decision_function(scaled_feature_vector)[0])
        model_prediction = int(self.model.predict(scaled_feature_vector)[0])
        window_label = "suspicious" if model_prediction == -1 else "normal"
        # Rule-based overrides — certain attack signatures always force suspicious.
        if window_label == "normal":
            window_label = _rule_based_label(window_feature_values, ranked_flow_summaries)
        if window_label == "suspicious" and raw_inference_summary == "traffic within learned baseline":
            # Keep suspicious model output from sounding normal. / Tránh output suspicious nhưng summary lại nghe như normal.
            raw_inference_summary = _derive_suspicious_reason(window_feature_values, ranked_flow_summaries)
        labeled_inference_summary = format_inference_statement(raw_inference_summary)
        alert_severity = _classify_alert_severity(window_label, raw_inference_summary)
        if self.should_print_window_events():
            print_detection(
                window_end,
                window_feature_values,
                ranked_flow_summaries,
                window_label,
                labeled_inference_summary,
                display_top_flows=self.display_top_flows,
                alert_severity=alert_severity,
            )
        if window_label == "suspicious":
            from src.triage import get_mitre_id
            write_siem_log(
                SIEM_LOG_PATH, window_start, window_end,
                raw_inference_summary, alert_severity or "LOW",
                get_mitre_id(raw_inference_summary),
                ranked_flow_summaries, window_feature_values.get("packets", 0),
            )
        self._record_window(window_start, window_end, window_feature_values, anomaly_score, window_label, labeled_inference_summary, alert_severity)
        self.memory.add_window(
            TrafficWindow(
                window_start=window_start,
                window_end=window_end,
                window_feature_values=window_feature_values,
                ranked_flow_summaries=ranked_flow_summaries,
                anomaly_score=anomaly_score,
                window_label=window_label,
                inference_summary=labeled_inference_summary,
            )
        )

    def shutdown(self):
        # Stop the app and release the tshark process. / Dừng app và giải phóng process tshark.
        self.stop_event.set()
        self.capture.shutdown()
        _save_to_history(self._history_filename, self._session_windows, self._session_source)


# Offline analysis of a .pcap file: reads all packets, slices by timestamp, then enters Q&A.
class PcapTrafficMLApp:
    def __init__(
        self,
        pcap_file,
        window_seconds,
        warmup_windows,
        contamination,
        output_csv,
        display_top_flows,
        tshark_path,
        display_filter,
        max_packets_per_window,
        interactive,
    ):
        self.pcap_file = pcap_file
        self.window_seconds = window_seconds
        self.warmup_windows = warmup_windows
        self.contamination = contamination
        self.output_csv = output_csv
        self.display_top_flows = display_top_flows
        self.tshark_path = tshark_path
        self.display_filter = display_filter
        self.max_packets_per_window = max_packets_per_window
        self.interactive = interactive
        self.interactive_tty = self.interactive and sys.stdin.isatty()

        self._history_filename = datetime.now().strftime("%d_%m_%Y_%H_%M_%S") + ".json"
        self._session_windows = []
        self._session_source = os.path.basename(pcap_file)
        self.memory = TrafficMemory()
        self.answer_engine = TrafficAnswerEngine(self.memory, local_ip=None)
        self.scaler, self.model = self._create_model(contamination)
        self.training_feature_vectors = []
        self._historical_vectors = load_history_vectors()
        if self._historical_vectors:
            print(f"Baseline history: {len(self._historical_vectors)} normal windows loaded from past sessions.")

    def _create_model(self, contamination):
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ModuleNotFoundError:
            print("scikit-learn not found. Install it with: python3 -m pip install scikit-learn")
            sys.exit(1)
        return StandardScaler(), IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
        )

    def _fit_model(self):
        scaler_data = self._historical_vectors + self.training_feature_vectors if self._historical_vectors else self.training_feature_vectors
        self.scaler.fit(scaler_data)
        scaled_warmup = self.scaler.transform(self.training_feature_vectors)
        self.model.fit(scaled_warmup)

    def run(self):
        if not os.path.isfile(self.pcap_file):
            print(f"File not found: {self.pcap_file}")
            sys.exit(1)

        print(f"Reading pcap: {self.pcap_file}")
        packets = self._read_all_packets()
        if not packets:
            print("No parseable packets found in the pcap file.")
            return

        print(f"Loaded {len(packets):,} packets.")
        windows = self._split_into_windows(packets)
        total_windows = len(windows)
        if total_windows == 0:
            print("No time windows could be built from the pcap data.")
            return

        # Auto-adjust warmup when pcap has fewer windows than requested.
        effective_warmup = min(self.warmup_windows, max(1, total_windows - 1))
        if effective_warmup != self.warmup_windows:
            print(
                f"Warmup adjusted: {self.warmup_windows} → {effective_warmup} "
                f"(pcap contains only {total_windows} windows)."
            )
            self.warmup_windows = effective_warmup

        print(
            f"Processing {total_windows} windows  "
            f"[window={self.window_seconds}s  warmup={self.warmup_windows}  "
            f"scored={total_windows - self.warmup_windows}]"
        )

        suspicious_count = 0
        normal_count = 0
        warmup_suspicious_count = 0
        warmup_budget = self.warmup_windows
        warmup_used = 0
        interrupted = False
        try:
            for window_packets, window_start, window_end in windows:
                is_warmup_slot = warmup_used < warmup_budget
                label = self._process_window(window_packets, window_start, window_end)
                if is_warmup_slot:
                    warmup_used += 1
                    if label == "suspicious":
                        warmup_suspicious_count += 1
                        suspicious_count += 1
                elif label == "suspicious":
                    suspicious_count += 1
                elif label == "normal":
                    normal_count += 1
        except KeyboardInterrupt:
            print("\nAnalysis interrupted by user.")
            interrupted = True
        finally:
            scored_count = suspicious_count + normal_count
            print("\n--- Analysis Complete ---")
            print(f"  Windows total  : {total_windows}")
            if warmup_suspicious_count > 0:
                print(f"  Warmup         : {self.warmup_windows}  ({warmup_suspicious_count} flagged during warmup)")
            else:
                print(f"  Warmup         : {self.warmup_windows}")
            print(f"  Scored         : {scored_count}")
            if scored_count > 0:
                print(f"    Normal       : {normal_count}")
                print(f"    Suspicious   : {suspicious_count}")
            print(f"  CSV output     : {self.output_csv}")
            _save_to_history(self._history_filename, self._session_windows, self._session_source)

        if not interrupted and self.interactive_tty:
            self._interactive_loop()
        elif not interrupted and self.interactive:
            print("\nStdin is not a TTY — interactive mode skipped.")

    def _read_all_packets(self):
        tshark_cmd = [
            self.tshark_path,
            "-r", self.pcap_file,
            "-T", "fields",
            "-E", "separator=,",
            "-E", "quote=d",
            "-E", "occurrence=f",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.flags.syn",
            "-e", "tcp.flags.ack",
            "-e", "tcp.flags.reset",
            "-e", "tcp.flags.fin",
            "-e", "tcp.flags.push",
            "-e", "tcp.flags.urg",
            "-e", "ip.ttl",
            "-e", "ipv6.hlim",
            "-e", "frame.number",
            "-e", "_ws.col.Info",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.response.code",
            "-e", "http.user_agent",
            "-e", "arp.opcode",
            "-e", "arp.src.hw_mac",
            "-e", "arp.src.proto_ipv4",
            "-e", "arp.dst.proto_ipv4",
            "-e", "dns.qry.type",
        ]
        if self.display_filter:
            tshark_cmd.extend(["-Y", self.display_filter])

        try:
            result = subprocess.run(
                tshark_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            print("tshark not found. Install Wireshark/tshark first.")
            sys.exit(1)

        if result.returncode != 0:
            stderr_text = result.stderr.strip()
            if stderr_text:
                print(f"tshark error: {stderr_text[:300]}")

        packets = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            pkt = parse_tshark_csv_line(line)
            if pkt is not None:
                packets.append(pkt)
        return packets

    def _split_into_windows(self, packets):
        if not packets:
            return []
        packets_sorted = sorted(packets, key=lambda p: p.timestamp)
        first_ts = packets_sorted[0].timestamp

        buckets = collections.defaultdict(list)
        for pkt in packets_sorted:
            idx = int((pkt.timestamp - first_ts) / self.window_seconds)
            buckets[idx].append(pkt)

        result = []
        for idx in sorted(buckets.keys()):
            window_start = first_ts + idx * self.window_seconds
            window_end = window_start + self.window_seconds
            pkts = buckets[idx]
            if len(pkts) > self.max_packets_per_window:
                pkts = pkts[-self.max_packets_per_window:]
            result.append((pkts, window_start, window_end))
        return result

    def _record_window(self, window_start, window_end, window_feature_values, anomaly_score, window_label, labeled_inference_summary, alert_severity=None):
        write_row(self.output_csv, window_start, window_end, window_feature_values, anomaly_score, window_label, labeled_inference_summary)
        window_entry = {
            "time": datetime.fromtimestamp(window_end).strftime("%H:%M:%S"),
            "label": window_label,
            "score": round(anomaly_score, 4),
            "summary": labeled_inference_summary,
            "features": window_feature_values,
        }
        if alert_severity:
            window_entry["severity"] = alert_severity
        self._session_windows.append(window_entry)

    def _process_window(self, packet_records, window_start, window_end):
        window_feature_values, ranked_flow_summaries, raw_inference_summary = build_window_feature_values(
            packet_records,
        )
        if window_feature_values is None:
            return None

        feature_vector = [
            window_feature_values[name] for name in ordered_window_feature_names()
        ]
        labeled_inference_summary = format_inference_statement(raw_inference_summary)

        if len(self.training_feature_vectors) < self.warmup_windows:
            self.training_feature_vectors.append(feature_vector)
            if len(self.training_feature_vectors) == self.warmup_windows:
                self._fit_model()

            # Apply rule-based detection even during warmup so attacks aren't silently swallowed.
            early_label = _rule_based_label(window_feature_values, ranked_flow_summaries)
            early_severity = None
            if early_label == "suspicious":
                raw_inference_summary = _derive_suspicious_reason(window_feature_values, ranked_flow_summaries)
                labeled_inference_summary = format_inference_statement(raw_inference_summary)
                early_severity = _classify_alert_severity(early_label, raw_inference_summary)
                print_detection(
                    window_end,
                    window_feature_values,
                    ranked_flow_summaries,
                    early_label,
                    labeled_inference_summary,
                    display_top_flows=self.display_top_flows,
                    alert_severity=early_severity,
                )
                from src.triage import get_mitre_id
                write_siem_log(
                    SIEM_LOG_PATH, window_start, window_end,
                    raw_inference_summary, early_severity or "LOW",
                    get_mitre_id(raw_inference_summary),
                    ranked_flow_summaries, window_feature_values.get("packets", 0),
                )
            self._record_window(window_start, window_end, window_feature_values, 0.0, early_label, labeled_inference_summary, early_severity)
            self.memory.add_window(TrafficWindow(
                window_start=window_start, window_end=window_end,
                window_feature_values=window_feature_values,
                ranked_flow_summaries=ranked_flow_summaries,
                anomaly_score=0.0, window_label=early_label,
                inference_summary=labeled_inference_summary,
            ))
            return early_label

        scaled = self.scaler.transform([feature_vector])
        anomaly_score = -float(self.model.decision_function(scaled)[0])
        prediction = int(self.model.predict(scaled)[0])
        window_label = "suspicious" if prediction == -1 else "normal"
        # Rule-based overrides — certain attack signatures always force suspicious.
        if window_label == "normal":
            window_label = _rule_based_label(window_feature_values, ranked_flow_summaries)
        if window_label == "suspicious" and raw_inference_summary == "traffic within learned baseline":
            raw_inference_summary = _derive_suspicious_reason(window_feature_values, ranked_flow_summaries)
        labeled_inference_summary = format_inference_statement(raw_inference_summary)
        alert_severity = _classify_alert_severity(window_label, raw_inference_summary)
        if window_label == "suspicious":
            print_detection(
                window_end,
                window_feature_values,
                ranked_flow_summaries,
                window_label,
                labeled_inference_summary,
                display_top_flows=self.display_top_flows,
                alert_severity=alert_severity,
            )
            from src.triage import get_mitre_id
            write_siem_log(
                SIEM_LOG_PATH, window_start, window_end,
                raw_inference_summary, alert_severity or "LOW",
                get_mitre_id(raw_inference_summary),
                ranked_flow_summaries, window_feature_values.get("packets", 0),
            )
        self._record_window(window_start, window_end, window_feature_values, anomaly_score, window_label, labeled_inference_summary, alert_severity)
        self.memory.add_window(TrafficWindow(
            window_start=window_start, window_end=window_end,
            window_feature_values=window_feature_values,
            ranked_flow_summaries=ranked_flow_summaries,
            anomaly_score=anomaly_score, window_label=window_label,
            inference_summary=labeled_inference_summary,
        ))
        return window_label

    def _interactive_loop(self):
        print("\nAll windows processed. Ready for questions.")
        print("Commands: suspicious, summary, top flows, filter, ip <addr>, show ..., help, quit")
        command_used = False
        while True:
            try:
                question = input("question> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not question:
                continue
            if question.lower() in {"quit", "exit", "stop"}:
                break
            if question.lower() == "clear":
                if command_used:
                    sys.stdout.write("\033[2J\033[H")
                    sys.stdout.flush()
                    print("Commands: suspicious, summary, top flows, filter, ip <addr>, show ..., clear, help, quit")
                    command_used = False
                continue
            print()
            print(self.answer_engine.answer(question))
            print()
            command_used = True


# Parse CLI arguments and run the application. / Phân tích tham số CLI và chạy ứng dụng.
def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.pcap:
        app = PcapTrafficMLApp(
            pcap_file=args.pcap,
            window_seconds=args.window_seconds,
            warmup_windows=args.warmup_windows,
            contamination=args.contamination,
            output_csv=args.output_csv,
            display_top_flows=args.display_top_flows,
            tshark_path=args.tshark_path,
            display_filter=args.filter,
            max_packets_per_window=args.max_packets_per_window,
            interactive=not args.no_interactive,
        )
    else:
        app = LiveTrafficMLApp(
            interface=args.interface,
            window_seconds=args.window_seconds,
            warmup_windows=args.warmup_windows,
            contamination=args.contamination,
            output_csv=args.output_csv,
            display_top_flows=args.display_top_flows,
            tshark_path=args.tshark_path,
            bpf_filter=args.filter,
            max_packets_per_window=args.max_packets_per_window,
            interactive=not args.no_interactive,
            show_window_events=args.show_window_events,
        )
    app.run()
