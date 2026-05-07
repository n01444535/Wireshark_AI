import collections
import os
from datetime import datetime

from src.intelligence import ranked_flow_to_filter
from src.triage import get_mitre_id

_SOC_SEPARATOR = "═" * 56
_SOC_THIN_SEP = "─" * 56

# Known threat label prefixes used to classify alert summaries into display categories. / Danh sách prefix nhãn threat để phân loại summary alert thành nhóm hiển thị.
_DETECTION_PREFIXES = [
    "SYN Flood", "Port Scan", "ARP Cache Poisoning", "Lateral Movement",
    "SSH Brute Force", "RDP Exposure", "SMB Activity", "Cleartext Protocol",
    "ICS/HMI Web Reconnaissance", "Possible DDoS", "ARP Host Discovery",
    "SSH Tunneling", "Web Path Enumeration", "Single-Flow Anomaly",
]


# Map an inference summary string to its primary threat category label. / Ánh xạ chuỗi summary inference thành nhãn danh mục threat chính.
def _detection_label(summary: str) -> str:
    for prefix in _DETECTION_PREFIXES:
        if prefix in summary:
            return prefix
    return "Statistical Anomaly"


# Print an end-of-session SOC summary block to the terminal. / In khối tóm tắt SOC cuối phiên ra terminal.
def print_session_summary(session_windows: list, sanitizer=None, kill_chain_tracker=None) -> None:
    total = len(session_windows)
    if total == 0:
        return

    suspicious_windows = [w for w in session_windows if w.get("label") == "suspicious"]
    normal_count = total - len(suspicious_windows)

    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest_sev = "N/A"
    for w in suspicious_windows:
        sev = w.get("severity") or "LOW"
        if severity_order.get(sev, 0) > severity_order.get(highest_sev, 0):
            highest_sev = sev

    src_counter: collections.Counter = collections.Counter()
    for w in suspicious_windows:
        for ip in w.get("src_ips", []):
            src_counter[ip] += 1

    top_src_display = "N/A"
    if src_counter:
        ip, count = src_counter.most_common(1)[0]
        alias = sanitizer.sanitize_ip(ip) if sanitizer else ip
        top_src_display = f"{alias} ({count} window{'s' if count > 1 else ''})"

    detection_counter: collections.Counter = collections.Counter()
    for w in suspicious_windows:
        detection_counter[_detection_label(w.get("summary", ""))] += 1
    top_detection = detection_counter.most_common(1)[0][0] if detection_counter else "N/A"

    # Collect up to 3 unique filter strings across the most recent suspicious windows. / Thu thập tối đa 3 filter duy nhất từ các window suspicious gần nhất.
    seen_filters: set = set()
    top_filters: list = []
    for w in suspicious_windows[:5]:
        for f in w.get("top_filters", []):
            display = sanitizer.sanitize_text(f) if sanitizer else f
            if display not in seen_filters:
                top_filters.append(display)
                seen_filters.add(display)
            if len(top_filters) >= 3:
                break

    print(f"\n{_SOC_SEPARATOR}")
    print("SESSION SUMMARY")
    print(_SOC_THIN_SEP)
    print(f"  Total windows    : {total}")
    print(f"  Normal           : {normal_count}")
    print(f"  Suspicious       : {len(suspicious_windows)}")
    print(f"  Highest severity : {highest_sev}")
    print(f"  Top source       : {top_src_display}")
    print(f"  Top detection    : {top_detection}")
    if top_filters:
        print("  Recommended filters:")
        for i, f in enumerate(top_filters, 1):
            print(f"    {i}. {f}")

    if kill_chain_tracker:
        notable_chains = kill_chain_tracker.get_notable_chains(min_events=2, sanitizer=sanitizer)
        if notable_chains:
            print(_SOC_THIN_SEP)
            print("Kill Chain Activity:")
            for chain in notable_chains:
                for line in chain.splitlines():
                    print(f"  {line}")
    print(_SOC_SEPARATOR)


# Generate and write a structured markdown analysis report to disk, with exec summary, per-alert sections, kill chain, and optional IP mapping table. / Tạo và ghi báo cáo markdown có cấu trúc ra đĩa, gồm tóm tắt, chi tiết alert, kill chain, và bảng ánh xạ IP tuỳ chọn.
def write_markdown_report(
    report_path: str,
    session_source: str,
    session_windows: list,
    alert_store,
    sanitizer=None,
    kill_chain_tracker=None,
) -> None:
    os.makedirs(os.path.dirname(report_path) if os.path.dirname(report_path) else ".", exist_ok=True)

    total = len(session_windows)
    suspicious_windows = [w for w in session_windows if w.get("label") == "suspicious"]
    normal_count = total - len(suspicious_windows)

    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest_sev = "N/A"
    for w in suspicious_windows:
        sev = w.get("severity") or "LOW"
        if severity_order.get(sev, 0) > severity_order.get(highest_sev, 0):
            highest_sev = sev

    src_counter: collections.Counter = collections.Counter()
    for w in suspicious_windows:
        for ip in w.get("src_ips", []):
            src_counter[ip] += 1
    top_src_display = "N/A"
    if src_counter:
        ip, count = src_counter.most_common(1)[0]
        alias = sanitizer.sanitize_ip(ip) if sanitizer else ip
        top_src_display = f"{alias} ({count} windows)"

    detection_counter: collections.Counter = collections.Counter()
    for w in suspicious_windows:
        detection_counter[_detection_label(w.get("summary", ""))] += 1
    top_detection = detection_counter.most_common(1)[0][0] if detection_counter else "N/A"

    lines = [
        "# Network Traffic Analysis Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Source:** {session_source}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Windows analyzed | {total} |",
        f"| Normal | {normal_count} |",
        f"| Suspicious | {len(suspicious_windows)} |",
        f"| Highest severity | {highest_sev} |",
        f"| Top source | {top_src_display} |",
        f"| Top detection | {top_detection} |",
        "",
        "---",
        "",
        "## Alert Details",
        "",
    ]

    from src.explainer import _get_next_steps
    from src.confidence import get_benign_causes

    alerts = alert_store.all() if alert_store else []
    if not alerts:
        lines.append("*No suspicious alerts recorded.*")
    else:
        for idx, alert in enumerate(alerts, 1):
            threat = alert.get("threat", "Unknown")
            severity = alert.get("severity", "LOW")
            confidence = alert.get("confidence")
            fp_risk = alert.get("fp_risk")
            mitre_id = alert.get("mitre_id", "") or get_mitre_id(threat)
            window_time = alert.get("window_time", "")
            features = alert.get("features", {})
            flows = alert.get("flows", [])
            baseline_multiples = alert.get("baseline_multiples", {})
            correlation_count = alert.get("correlation_count", 0)
            is_allowlisted = alert.get("is_allowlisted", False)

            conf_str = f" | Confidence: {confidence}% | FP Risk: {fp_risk}" if confidence is not None else ""
            mitre_tag = f" [{mitre_id}]" if mitre_id else ""
            lines.append(f"### Alert {idx} — [{severity}]{conf_str} {threat}{mitre_tag}")
            lines.append("")
            if window_time:
                lines.append(f"**Time:** {window_time}  ")
            if correlation_count >= 3:
                lines.append(f"**Correlation:** Source triggered {correlation_count} suspicious windows  ")
            if is_allowlisted:
                lines.append("**Note:** Source is on the authorized-scanner allowlist — verify before escalating  ")
            lines.append("")

            # Evidence table — gives an "explainable AI" view of what drove the alert
            _EVIDENCE_SIGNALS = [
                ("unique_dst_ports", "Unique dest ports", "Unique dest ports"),
                ("syn_ratio",        "SYN ratio",         "SYN ratio"),
                ("unique_dst_ips",   "Unique dest IPs",   "Unique dest IPs"),
                ("mean_packets_per_flow", "Avg pkts/flow", None),
                ("packets",          "Packet rate",       "Packet rate"),
                ("arp_max_ips_per_mac", "Max IPs per MAC", None),
            ]
            table_rows = []
            for feat_key, label, baseline_key in _EVIDENCE_SIGNALS:
                val = features.get(feat_key, 0)
                if val == 0:
                    continue
                val_str = f"{val:.2f}" if isinstance(val, float) and val < 10 else str(int(val)) if isinstance(val, float) else str(val)
                mult = baseline_multiples.get(baseline_key, 0) if baseline_key else 0
                baseline_str = f"{mult:.1f}x" if mult else "—"
                table_rows.append((label, val_str, baseline_str))

            if table_rows:
                lines.append("**Evidence Table:**")
                lines.append("")
                lines.append("| Signal | Value | Baseline |")
                lines.append("|--------|-------|----------|")
                for row_label, row_val, row_base in table_rows:
                    lines.append(f"| {row_label} | {row_val} | {row_base} |")
                lines.append("")

            if flows:
                top_flow = flows[0]
                src = sanitizer.sanitize_ip(top_flow.source_ip) if sanitizer else top_flow.source_ip
                dst = sanitizer.sanitize_ip(top_flow.destination_ip) if sanitizer else top_flow.destination_ip
                raw_filter = ranked_flow_to_filter(top_flow)
                display_filter = sanitizer.sanitize_text(raw_filter) if sanitizer else raw_filter
                lines.append(f"**Top Flow:** `{src} -> {dst}` [{top_flow.protocol_name}, {top_flow.packet_count} pkts]  ")
                lines.append(f"**Wireshark Filter:** `{display_filter}`")
                lines.append("")

            if mitre_id:
                mitre_url = f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}"
                lines.append(f"**MITRE ATT&CK:** [{mitre_id}]({mitre_url})")
                lines.append("")

            benign = get_benign_causes(threat)
            lines.append("**Possible Benign Causes:**")
            for cause in benign:
                lines.append(f"- {cause}")
            lines.append("")

            steps = _get_next_steps(threat)
            lines.append("**Recommended Actions:**")
            for i, step in enumerate(steps, 1):
                step_text = step
                if flows and "<src>" in step_text:
                    src_ip = flows[0].source_ip
                    if sanitizer:
                        src_ip = sanitizer.sanitize_ip(src_ip)
                    step_text = step_text.replace("<src>", src_ip)
                lines.append(f"{i}. {step_text}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # Kill chain section if notable multi-event sources were observed
    if kill_chain_tracker:
        notable_chains = kill_chain_tracker.get_notable_chains(min_events=2, sanitizer=sanitizer)
        if notable_chains:
            lines += ["## Kill Chain Activity", ""]
            for chain_text in notable_chains:
                lines.append("```")
                lines.append(chain_text)
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")

    if sanitizer:
        ip_mapping = sanitizer.get_ip_mapping()
        mac_mapping = sanitizer.get_mac_mapping()
        if ip_mapping or mac_mapping:
            lines += [
                "## IP / MAC Address Mapping",
                "",
                "> ⚠️ Remove this section before sharing externally.",
                "",
            ]
            if ip_mapping:
                lines += ["| Alias | Real IP |", "|-------|---------|"]
                for real_ip, alias in sorted(ip_mapping.items(), key=lambda kv: kv[1]):
                    lines.append(f"| {alias} | {real_ip} |")
                lines.append("")
            if mac_mapping:
                lines += ["| Alias | Real MAC |", "|-------|----------|"]
                for real_mac, alias in sorted(mac_mapping.items(), key=lambda kv: kv[1]):
                    lines.append(f"| {alias} | {real_mac} |")
                lines.append("")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Report written: {report_path}")
