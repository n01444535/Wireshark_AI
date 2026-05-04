import queue
import subprocess
import sys
import threading

from src.parser import parse_tshark_csv_line


# Wrap tshark as a live packet source for the Python app. / Bọc tshark thành nguồn packet live cho app Python.
class TsharkCapture:
    def __init__(self, interface, tshark_path, bpf_filter, packet_queue, stop_event):
        # Store capture settings and shared queues/events. / Lưu cấu hình capture và queue/event dùng chung.
        self.interface = interface
        self.tshark_path = tshark_path
        self.bpf_filter = bpf_filter
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.tshark_process = None

    def ensure_tshark(self):
        # Verify tshark exists before starting live capture. / Kiểm tra tshark tồn tại trước khi bắt đầu capture live.
        try:
            tshark_version_check_result = subprocess.run(
                [self.tshark_path, "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            print("tshark not found. Install Wireshark/tshark first.")
            sys.exit(1)
        if tshark_version_check_result.returncode != 0:
            print("Unable to run tshark.")
            sys.exit(1)

    def start(self):
        # Ask tshark for only the fields the parser and model need. / Yêu cầu tshark chỉ xuất các field parser và model cần.
        tshark_capture_command = [
            self.tshark_path,
            "-i",
            self.interface,
            "-l",
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "frame.len",
            "-e",
            "tcp.flags.syn",
            "-e",
            "tcp.flags.ack",
            "-e",
            "tcp.flags.reset",
            "-e",
            "tcp.flags.fin",
            "-e",
            "tcp.flags.push",
            "-e",
            "tcp.flags.urg",
            "-e",
            "ip.ttl",
            "-e",
            "ipv6.hlim",
            "-e",
            "frame.number",
            "-e",
            "_ws.col.Info",
            "-e",
            "http.request.method",
            "-e",
            "http.request.uri",
            "-e",
            "http.response.code",
            "-e",
            "http.user_agent",
            "-e",
            "arp.opcode",
            "-e",
            "arp.src.hw_mac",
            "-e",
            "arp.src.proto_ipv4",
            "-e",
            "arp.dst.proto_ipv4",
            "-e",
            "dns.qry.type",
        ]
        if self.bpf_filter:
            # Apply a capture-time BPF filter when requested. / Áp dụng BPF filter ở thời điểm capture nếu được yêu cầu.
            tshark_capture_command.extend(["-f", self.bpf_filter])

        # Run tshark with line-buffered output so windows update live. / Chạy tshark với output theo từng dòng để cập nhật live.
        self.tshark_process = subprocess.Popen(
            tshark_capture_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        # Read stdout and stderr in background threads. / Đọc stdout và stderr bằng thread nền.
        threading.Thread(target=self._reader_loop, daemon=True).start()
        threading.Thread(target=self._stderr_loop, daemon=True).start()

    def _reader_loop(self):
        # Convert each tshark CSV line into a packet record. / Chuyển từng dòng CSV của tshark thành packet record.
        if not self.tshark_process or not self.tshark_process.stdout:
            return
        for tshark_output_line in self.tshark_process.stdout:
            if self.stop_event.is_set():
                break
            packet_csv_line = tshark_output_line.strip()
            if not packet_csv_line:
                continue
            parsed_packet_record = parse_tshark_csv_line(packet_csv_line)
            if parsed_packet_record is not None:
                self.packet_queue.put(parsed_packet_record)

    def _stderr_loop(self):
        # Surface only actionable tshark errors to the user. / Chỉ hiển thị lỗi tshark có thể hành động cho user.
        if not self.tshark_process or not self.tshark_process.stderr:
            return
        for tshark_error_line in self.tshark_process.stderr:
            if self.stop_event.is_set():
                break
            tshark_error_text = tshark_error_line.strip()
            if not tshark_error_text:
                continue
            lowered_error_text = tshark_error_text.lower()
            if "permission denied" in lowered_error_text or "there are no interfaces" in lowered_error_text:
                print(tshark_error_text)

    def shutdown(self):
        # Stop tshark cleanly, then force-kill if it hangs. / Dừng tshark gọn gàng, rồi kill nếu bị treo.
        if self.tshark_process is not None:
            try:
                self.tshark_process.terminate()
                self.tshark_process.wait(timeout=5)
            except Exception:
                try:
                    self.tshark_process.kill()
                except Exception:
                    pass
