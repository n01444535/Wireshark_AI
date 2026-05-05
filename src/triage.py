import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

RISK_CRITICAL = "CRITICAL"
RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_LOW      = "LOW"
RISK_INFO     = "INFO"

MITRE_ATTACK_MAP = {
    "ARP Cache Poisoning":              "T1557.002",
    "ICS/SCADA HMI Web Reconnaissance": "T1071.001",
    "ICS/HMI Web Reconnaissance":       "T1071.001",
    "Lateral Movement":                 "T1021",
    "DDoS":                             "T1498.001",
    "SYN Flood":                        "T1498.001",
    "Port Scan":                        "T1046",
    "Brute Force":                      "T1110",
    "SSH Brute Force":                  "T1110",
    "SSH Tunneling":                    "T1572",
    "Cleartext Protocol":               "T1040",
    "Suspicious Service Access":        "T1021",
    "SMB Activity":                     "T1021.002",
    "RDP Exposure":                     "T1021.001",
    "Web Path Enumeration":             "T1595.003",
    "ARP Host Discovery":               "T1018",
    "Possible DDoS":                    "T1498.001",
    "Statistical Anomaly":              "",
}


def get_mitre_id(threat_text: str) -> str:
    for prefix, mitre_id in MITRE_ATTACK_MAP.items():
        if threat_text.startswith(prefix):
            return mitre_id
    return ""

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_RISK_BADGE = {
    RISK_CRITICAL: "🔴 CRITICAL",
    RISK_HIGH:     "🟠 HIGH",
    RISK_MEDIUM:   "🟡 MEDIUM",
    RISK_LOW:      "🟢 LOW",
    RISK_INFO:     "⚪ INFO",
}


@dataclass
class TriageEvidence:
    factor: str
    points: int
    detail: str


@dataclass
class TriageResult:
    risk_level: str
    classification: str
    confidence: int      # 0-100
    raw_score: int       # 0-100
    evidence: List[TriageEvidence]
    recommendation: str
    window_start: float
    window_end: float

    def one_liner(self):
        badge = _RISK_BADGE.get(self.risk_level, self.risk_level)
        return f"{badge}  ({self.confidence}% confidence) — {self.classification}"

    def format_full(self, alert_index=None):
        from src.intelligence import _clock
        prefix = f"[Triage {alert_index}]" if alert_index is not None else "[Triage]"
        time_str = f"{_clock(self.window_start)} - {_clock(self.window_end)}"
        lines = [
            f"{prefix}  {time_str}",
            f"  Risk:           {_RISK_BADGE.get(self.risk_level, self.risk_level)}",
            f"  Confidence:     {self.confidence}%",
            f"  Classification: {self.classification}",
            f"  Score:          {self.raw_score}/100",
            "  Evidence breakdown:",
        ]
        for ev in self.evidence:
            sign = "+" if ev.points >= 0 else ""
            lines.append(f"    {sign}{ev.points:+3d}  [{ev.factor}]  {ev.detail}")
        lines += [
            "",
            f"  Action:  {self.recommendation}",
        ]
        return "\n".join(lines)


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _infer_home_first_octet(flows) -> int:
    """Return the most common first octet among destination IPs (the 'home' network)."""
    octets: Counter = Counter()
    for f in flows:
        try:
            dst_octet = int(f.destination_ip.split(".")[0])
            octets[dst_octet] += f.packet_count
        except (ValueError, AttributeError, IndexError):
            pass
    return octets.most_common(1)[0][0] if octets else -1


def _is_cross_subnet_rfc1918(src_ip: str, home_octet: int) -> bool:
    """True if src_ip is RFC1918 but from a different /8 than the home network octet."""
    if not _is_private_ip(src_ip) or home_octet < 0:
        return False
    try:
        src_octet = int(src_ip.split(".")[0])
        return src_octet != home_octet
    except (ValueError, AttributeError, IndexError):
        return False


def _is_business_hours(unix_ts: float, start_hour: int, end_hour: int) -> bool:
    dt = datetime.fromtimestamp(unix_ts)
    return start_hour <= dt.hour < end_hour and dt.weekday() < 5


_BUSINESS_SERVER_PORTS = {25, 110, 143, 389, 445, 636, 1433, 1521, 3268, 3269}

def _classify_network_type(fv, flows) -> str:
    if fv.get("enip_ratio", 0) > 0:
        return "ics"
    flow_ports = set()
    proto_names = set()
    for f in flows:
        if f.source_port:
            flow_ports.add(f.source_port)
        if f.destination_port:
            flow_ports.add(f.destination_port)
        proto_names.add(f.protocol_name.upper())
    has_business_indicator = (
        bool(flow_ports & _BUSINESS_SERVER_PORTS)
        or bool(proto_names & {"SMB", "LDAP", "SYSLOG"})
        or fv.get("unique_dst_ips", 0) > 20
    )
    if has_business_indicator:
        return "business"
    return "home"


def _attempts_per_minute(syn_count: int, window_seconds: float) -> float:
    if window_seconds <= 0:
        return 0.0
    return syn_count / (window_seconds / 60.0)


class AlertTriageEngine:
    """
    Scores each suspicious window and classifies it as attack vs false positive.

    Key distinctions:
    - Brute force attack:   external IP, high rate (>10/min), all connections rejected
    - User lockout:         internal IP, few attempts (<10), business hours, eventually succeeds
    - Port scan:            many destination ports, few packets per connection
    - DDoS:                 many source IPs all sending SYN
    - Scheduled automation: regular timing, internal IP, known service port
    - False positive:       internal IP, business hours, low volume, connection completes
    """

    def __init__(self, business_hours_start: int = 8, business_hours_end: int = 18):
        self.biz_start = business_hours_start
        self.biz_end = business_hours_end

    def triage(self, traffic_window) -> TriageResult:
        fv = traffic_window.window_feature_values
        flows = traffic_window.ranked_flow_summaries
        duration = max(1.0, traffic_window.window_end - traffic_window.window_start)
        is_biz = _is_business_hours(traffic_window.window_start, self.biz_start, self.biz_end)

        network_type = _classify_network_type(fv, flows)
        evidence: List[TriageEvidence] = []
        score = 0

        # ── Source IP origin ────────────────────────────────────────────────
        src_ips = {f.source_ip for f in flows if f.source_ip not in {"unknown", ""}}
        external = [ip for ip in src_ips if not _is_private_ip(ip)]
        all_private = [ip for ip in src_ips if _is_private_ip(ip)]

        # Cross-subnet: RFC1918 source from a different /8 than the observed destination network.
        # e.g. 172.31.x.x attacking 10.1.x.x — technically private but clearly lateral/external.
        home_octet = _infer_home_first_octet(flows)
        cross_subnet = [ip for ip in all_private if _is_cross_subnet_rfc1918(ip, home_octet)]
        internal = [ip for ip in all_private if ip not in cross_subnet]

        if external:
            pts = min(30, 15 + len(external) * 5)
            evidence.append(TriageEvidence(
                "External Source IP",
                pts,
                f"{len(external)} external IP(s): {', '.join(sorted(external)[:3])}"
                + (" ..." if len(external) > 3 else ""),
            ))
            score += pts
        if cross_subnet:
            pts = 10
            evidence.append(TriageEvidence(
                "Cross-Subnet Source (RFC1918)",
                pts,
                f"Source IP(s) from different RFC1918 block than home network (/{home_octet}.x.x.x):"
                f" {', '.join(sorted(cross_subnet)[:3])} — lateral entry from separate network segment",
            ))
            score += pts
        if not external and not cross_subnet and internal:
            pts = -20
            evidence.append(TriageEvidence(
                "Internal Source Only",
                pts,
                f"Traffic from internal IP(s) {', '.join(sorted(internal)[:3])} — likely authorized user or misconfigured service",
            ))
            score += pts

        # ── Time of day (only meaningful for business/ICS networks) ────────
        dt = datetime.fromtimestamp(traffic_window.window_start)
        if network_type != "home":
            if not is_biz:
                pts = 15
                evidence.append(TriageEvidence(
                    "Off-Hours Activity",
                    pts,
                    f"Detected at {dt.strftime('%H:%M')} — outside business hours ({self.biz_start}:00–{self.biz_end}:00 Mon–Fri)",
                ))
            else:
                pts = -10
                evidence.append(TriageEvidence(
                    "Business Hours",
                    pts,
                    f"Detected at {dt.strftime('%H:%M')} during working hours — user activity plausible",
                ))
            score += pts

        # ── Attempt rate ─────────────────────────────────────────────────────
        total_syn = int(round(fv.get("syn_ratio", 0) * fv.get("packets", 0)))
        rate = _attempts_per_minute(total_syn, duration)

        if rate > 30:
            pts = 35
            label = f"{rate:.0f} SYN/min — automated tool signature (brute force / scanner)"
        elif rate > 10:
            pts = 20
            label = f"{rate:.0f} SYN/min — scripted activity (>10/min threshold)"
        elif rate > 3:
            pts = 8
            label = f"{rate:.1f} SYN/min — moderate; could be human retry or slow scanner"
        elif total_syn <= 5 and total_syn > 0:
            pts = -15
            label = f"Only {total_syn} SYN packet(s) — typical of user mistake (e.g. forgot password)"
        else:
            pts = 0
            label = f"{total_syn} total SYN packets in {duration:.0f}s"

        if pts != 0 or total_syn > 0:
            evidence.append(TriageEvidence("Attempt Rate", pts, label))
            score += pts

        # ── Connection success/rejection rate ────────────────────────────────
        total_rst = int(round(fv.get("rst_ratio", 0) * fv.get("packets", 0)))
        if total_syn > 0:
            rejection_rate = total_rst / total_syn
            if rejection_rate > 0.8:
                pts = 20
                evidence.append(TriageEvidence(
                    "All Connections Rejected",
                    pts,
                    f"{rejection_rate:.0%} of SYN attempts received RST — no successful logins yet, attack in progress",
                ))
            elif rejection_rate < 0.2 and total_syn > 3:
                pts = -25
                evidence.append(TriageEvidence(
                    "Connections Completing",
                    pts,
                    f"Low RST rate ({rejection_rate:.0%}) — user likely authenticated at some point (FP indicator)",
                ))
            else:
                pts = 0
            score += pts

        # ── Port diversity (scan) ────────────────────────────────────────────
        unique_dst_ports = fv.get("unique_dst_ports", 0)
        if unique_dst_ports > 20:
            pts = 30
            evidence.append(TriageEvidence(
                "Wide Port Scan",
                pts,
                f"{unique_dst_ports} destination ports targeted — nmap/masscan full-range sweep",
            ))
            score += pts
        elif unique_dst_ports > 10:
            pts = 15
            evidence.append(TriageEvidence(
                "Targeted Port Scan",
                pts,
                f"{unique_dst_ports} destination ports — selective service discovery",
            ))
            score += pts

        # ── Source diversity (DDoS) ──────────────────────────────────────────
        unique_src_ips = fv.get("unique_src_ips", 0)
        syn_ratio = fv.get("syn_ratio", 0)
        if unique_src_ips > 10 and syn_ratio > 0.3:
            pts = 40
            evidence.append(TriageEvidence(
                "Distributed SYN Flood",
                pts,
                f"{unique_src_ips} unique source IPs all sending SYN — DDoS pattern",
            ))
            score += pts
        elif unique_src_ips > 5 and syn_ratio > 0.3:
            pts = 20
            evidence.append(TriageEvidence(
                "Multi-Source SYN",
                pts,
                f"{unique_src_ips} sources sending SYN — could be coordinated or botnet",
            ))
            score += pts

        # ── Protocol-specific indicators ─────────────────────────────────────
        seen_proto_flags = set()
        for flow in flows[:5]:
            proto = flow.protocol_name.upper()
            if proto in {"SSH", "SSHV2"} and "ssh" not in seen_proto_flags:
                seen_proto_flags.add("ssh")
                non_std = next((p for p in [flow.source_port, flow.destination_port] if p not in {0, 22}), None)
                if non_std:
                    pts = 15
                    evidence.append(TriageEvidence(
                        "Non-Standard SSH Port",
                        pts,
                        f"SSH on port {non_std} — intentional obfuscation or tunneling attempt",
                    ))
                    score += pts
            elif proto == "TELNET" and "telnet" not in seen_proto_flags:
                seen_proto_flags.add("telnet")
                pts = 20
                evidence.append(TriageEvidence(
                    "Cleartext Protocol (Telnet)",
                    pts,
                    "Unencrypted — credentials transmitted in plaintext, trivial to intercept",
                ))
                score += pts
            elif proto in {"RDP", "MS-WBT-SERVER"} and "rdp" not in seen_proto_flags:
                seen_proto_flags.add("rdp")
                pts = 10
                evidence.append(TriageEvidence(
                    "RDP Traffic",
                    pts,
                    "Remote desktop — verify for unauthorized remote access or brute force",
                ))
                score += pts

        # ── ARP Poisoning / MiTM layer ───────────────────────────────────────
        arp_gratuitous_ratio = fv.get("arp_gratuitous_ratio", 0)
        arp_sweep_unique = int(fv.get("arp_sweep_unique_targets", 0))
        arp_max_ips = int(fv.get("arp_max_ips_per_mac", 0))
        arp_ratio_val = fv.get("arp_ratio", 0)

        if arp_gratuitous_ratio > 0.2 and arp_ratio_val > 0.3:
            pts = 60
            evidence.append(TriageEvidence(
                "ARP Poisoning / Gratuitous ARP Flood",
                pts,
                f"{arp_gratuitous_ratio:.0%} of traffic is gratuitous ARP"
                " — Ettercap or similar tool flooding ARP caches;"
                " all ICS device traffic is being silently intercepted (MiTM)",
            ))
            score += pts
        elif arp_gratuitous_ratio > 0.05 and arp_ratio_val > 0.2:
            pts = 25
            evidence.append(TriageEvidence(
                "Elevated Gratuitous ARP",
                pts,
                f"{arp_gratuitous_ratio:.0%} gratuitous ARP — possible ARP poisoning or misconfigured device",
            ))
            score += pts

        if arp_max_ips > 2:
            pts = 30
            evidence.append(TriageEvidence(
                "ARP Spoofing — MAC Claiming Multiple IPs",
                pts,
                f"One MAC address claimed {arp_max_ips} different IP addresses"
                " — classic ARP spoofing / man-in-the-middle indicator",
            ))
            score += pts

        if arp_sweep_unique > 20:
            pts = 20
            evidence.append(TriageEvidence(
                "ARP Host Discovery Sweep",
                pts,
                f"ARP requests targeting {arp_sweep_unique} unique IPs"
                " — automated host discovery sweep (nmap -sn or Ettercap auto-scan)",
            ))
            score += pts
        elif arp_sweep_unique > 10:
            pts = 10
            evidence.append(TriageEvidence(
                "ARP Target Diversity",
                pts,
                f"ARP requests to {arp_sweep_unique} unique IPs — possible network mapping",
            ))
            score += pts

        # ── Lateral Movement / Fan-out Scan ──────────────────────────────────
        unique_dst_ips_count = int(fv.get("unique_dst_ips", 0))
        mean_pkts_per_flow = fv.get("mean_packets_per_flow", 99)
        unique_flows_count = int(fv.get("unique_flows", 0))

        if unique_dst_ips_count > 5 and mean_pkts_per_flow < 5 and unique_flows_count > 8:
            pts = 25
            evidence.append(TriageEvidence(
                "Lateral Movement / Host Discovery",
                pts,
                f"Traffic fans out to {unique_dst_ips_count} unique destination IPs"
                f" (avg {mean_pkts_per_flow:.1f} pkts/flow, {unique_flows_count} flows)"
                " — post-compromise host sweep or automated network mapping",
            ))
            score += pts

        # ── Large packet / exfiltration signal ───────────────────────────────
        large_ratio = fv.get("large_packet_ratio", 0)
        if large_ratio > 0.6 and external:
            pts = 20
            evidence.append(TriageEvidence(
                "Outbound Large Packets",
                pts,
                f"{large_ratio:.0%} of packets are large (>1000B) going to external IP — possible data exfiltration",
            ))
            score += pts

        # ── HTTP / ICS web layer ──────────────────────────────────────────────
        http_ics_hit = fv.get("http_ics_path_hit", 0)
        http_401_ratio = fv.get("http_401_ratio", 0)
        http_unique_uri_count = int(fv.get("http_unique_uri_count", 0))
        http_sensitive_path_ratio = fv.get("http_sensitive_path_ratio", 0)

        if http_ics_hit:
            pts = 65
            evidence.append(TriageEvidence(
                "ICS/SCADA HMI Web Access",
                pts,
                f"HTTP requests targeting industrial control system endpoints"
                f" (alarm logs, event logs, screen data) — {http_unique_uri_count} endpoint(s) accessed"
                " on an industrial HMI web interface",
            ))
            score += pts

        if http_401_ratio > 0.3 and http_unique_uri_count > 2:
            pts = 25
            evidence.append(TriageEvidence(
                "Systematic Auth Challenge Pattern",
                pts,
                f"{http_401_ratio:.0%} of HTTP responses are 401 followed by successful re-authentication"
                f" — credential-based access replayed across {http_unique_uri_count} endpoints",
            ))
            score += pts
        elif http_401_ratio > 0.5:
            pts = 15
            evidence.append(TriageEvidence(
                "Repeated HTTP Auth Failures",
                pts,
                f"{http_401_ratio:.0%} of HTTP responses are 401 Access Denied",
            ))
            score += pts

        if http_unique_uri_count > 10 and not http_ics_hit:
            pts = 20
            evidence.append(TriageEvidence(
                "Wide Web Path Enumeration",
                pts,
                f"{http_unique_uri_count} unique URLs accessed — systematic web directory traversal",
            ))
            score += pts
        elif http_unique_uri_count > 5 and not http_ics_hit:
            pts = 10
            evidence.append(TriageEvidence(
                "Multiple Web Endpoints",
                pts,
                f"{http_unique_uri_count} unique URLs — possible web reconnaissance",
            ))
            score += pts

        if http_sensitive_path_ratio > 0.3 and not http_ics_hit:
            pts = 20
            evidence.append(TriageEvidence(
                "Sensitive Web Path Access",
                pts,
                f"{http_sensitive_path_ratio:.0%} of URLs target sensitive paths (admin, config, backup, etc.)",
            ))
            score += pts

        score = max(0, min(100, score))
        classification, recommendation = self._classify(
            score, fv, flows, external, internal, is_biz, total_syn, unique_dst_ports, network_type
        )

        if score >= 75:
            risk_level, confidence = RISK_CRITICAL, min(95, 70 + score // 5)
        elif score >= 55:
            risk_level, confidence = RISK_HIGH, min(88, 60 + score // 5)
        elif score >= 35:
            risk_level, confidence = RISK_MEDIUM, min(72, 50 + score // 5)
        elif score >= 15:
            risk_level, confidence = RISK_LOW, min(60, 40 + score // 5)
        else:
            risk_level, confidence = RISK_INFO, max(35, 25 + score)

        return TriageResult(
            risk_level=risk_level,
            classification=classification,
            confidence=confidence,
            raw_score=score,
            evidence=evidence,
            recommendation=recommendation,
            window_start=traffic_window.window_start,
            window_end=traffic_window.window_end,
        )

    def _classify(self, score, fv, flows, external, internal, is_biz, total_syn, unique_dst_ports, network_type="business"):
        unique_src = fv.get("unique_src_ips", 0)
        syn_ratio = fv.get("syn_ratio", 0)
        rst_ratio = fv.get("rst_ratio", 0)

        # ARP Poisoning / MiTM — highest priority in ICS environments
        if fv.get("arp_gratuitous_ratio", 0) > 0.1 or fv.get("arp_max_ips_per_mac", 0) > 2:
            enip_present = fv.get("enip_ratio", 0) > 0
            ics_note = (
                " ICS/OT device communication (EtherNet/IP CIP) is actively being intercepted."
                if enip_present else ""
            )
            return (
                "ARP Cache Poisoning / Man-in-the-Middle",
                f"ESCALATE TO ICS/OT SECURITY TEAM — ARP poisoning detected.{ics_note}"
                " Tool signature consistent with Ettercap or similar ARP MiTM framework."
                " Attacker is silently positioned between ICS devices, reading and potentially"
                " modifying control traffic in real-time."
                " Immediately flush ARP caches on all affected devices."
                " Enable Dynamic ARP Inspection (DAI) on managed switches."
                " Identify and isolate the attacking host via MAC address in switch port tables."
                " Review CIP/ENIP session logs for unauthorized command injection.",
            )

        # ICS/SCADA HMI web reconnaissance — highest priority
        if fv.get("http_ics_path_hit", 0):
            uri_count = int(fv.get("http_unique_uri_count", 0))
            auth_pattern = fv.get("http_401_ratio", 0) > 0.2
            src_desc = "External" if external else "Internal"
            cred_note = " using valid credentials (401→200 auth pattern)" if auth_pattern else ""
            return (
                "ICS/SCADA HMI Web Reconnaissance",
                f"ESCALATE TO ICS/OT SECURITY TEAM — {src_desc} actor{cred_note} is systematically"
                f" crawling an industrial HMI web interface ({uri_count} endpoint(s) accessed)."
                " Resources include alarm logs, event logs, and screen captures — high-value"
                " intelligence for planning a follow-on physical process attack."
                " Verify whether account credentials are compromised."
                " Isolate HMI web interface from the network immediately."
                " Check DHCP/AD logs to identify the source host.",
            )

        # Lateral movement / host discovery sweep
        unique_dst_ips_c = int(fv.get("unique_dst_ips", 0))
        mean_pkts = fv.get("mean_packets_per_flow", 99)
        if unique_dst_ips_c > 5 and mean_pkts < 5 and int(fv.get("unique_flows", 0)) > 8:
            src_note = "External-origin" if external else "Internal"
            return (
                "Lateral Movement / Internal Host Discovery",
                f"INVESTIGATE — {src_note} source is sweeping the network, connecting to"
                f" {unique_dst_ips_c} different hosts with short-lived flows (avg {mean_pkts:.1f} pkts)."
                " Indicator of post-compromise reconnaissance from a pivoted host."
                " Identify the originating host via DHCP/AD logs and MAC address tables."
                " Isolate immediately if unauthorized."
                " Inspect for persistence mechanisms (scheduled tasks, cron jobs, startup entries)."
                " Cross-reference with IDS/EDR alerts on the suspected compromised host.",
            )

        # SYN Flood — single source hammering many destinations
        if syn_ratio > 0.5 and unique_dst_ips_c > 5 and unique_src <= 3:
            src_desc = "External" if external else "Internal"
            return (
                "SYN Flood — Targeted DoS",
                f"BLOCK and MONITOR — {src_desc} source sending high SYN volume (ratio {syn_ratio:.2f})"
                f" to {unique_dst_ips_c} destinations. Possible DoS/DDoS attack."
                " Block source IP at firewall. Check for amplification or botnet vectors.",
            )

        # DDoS — many sources flooding SYN
        if unique_src > 10 and syn_ratio > 0.3:
            return (
                "DDoS / Distributed SYN Flood",
                "ESCALATE IMMEDIATELY — Block source subnet at perimeter firewall. Notify network team and management.",
            )

        # Wide port scan
        if unique_dst_ports > 15:
            src_desc = "external" if external else "internal"
            return (
                f"Port Scan / Reconnaissance ({src_desc} source)",
                "INVESTIGATE — If external: block source IP, check for follow-up exploitation. "
                "If internal: verify if authorized pentest, else treat as compromised endpoint.",
            )

        # External brute force
        if external and score >= 55:
            return (
                "Brute Force Attack — External",
                "BLOCK source IP at firewall immediately. Check auth logs for any successful login. "
                "If login succeeded: rotate credentials, isolate affected host, escalate to IR team.",
            )

        # External but low score — could be false positive
        if external and score < 35:
            return (
                "Low-Risk External Traffic",
                "MONITOR — Likely benign but from external IP. Verify with asset owner. "
                "Check if IP is a known CDN, cloud service, or partner network.",
            )

        # Internal, few attempts, business hours — classic user lockout (not applicable to home)
        if network_type != "home" and internal and not external and total_syn <= 10 and is_biz:
            return (
                "Likely User Lockout (Internal)",
                "VERIFY with user/HR — probable forgotten password during work hours. "
                "Unlock account via helpdesk if confirmed. No escalation needed.",
            )

        # Internal but high score — suspicious internal
        if internal and score >= 40:
            return (
                "Suspicious Internal Activity",
                "INVESTIGATE — Could be compromised endpoint, rogue employee, or misconfigured service. "
                "Check endpoint AV/EDR logs and correlate with AD/LDAP auth logs.",
            )

        # Low overall score — likely false positive
        if score < 20:
            return (
                "Likely False Positive / Scheduled Automation",
                "LOG and MONITOR — Probable scheduled job, backup, software update, or normal variance. "
                "Verify with asset owner before closing.",
            )

        # External, medium score — elevated suspicion but not conclusive
        if external and 35 <= score < 55:
            return (
                "External Traffic — Elevated Suspicion (Below Threshold)",
                "INVESTIGATE — Score elevated but below confirmed attack threshold. "
                "Verify source IP reputation (VirusTotal / Shodan). "
                "If unrecognized: block at perimeter and open a monitoring ticket.",
            )

        # Internal, off-hours but low volume — only flag for business/ICS networks
        if network_type != "home" and internal and not external and not is_biz:
            return (
                "Internal Off-Hours Activity — Abnormal Timing",
                "INVESTIGATE — Internal traffic outside business hours. "
                "Could be a scheduled job, VPN session, or compromised endpoint. "
                "Verify with asset owner; check endpoint EDR and Windows Event Logs.",
            )

        # Internal, high SYN volume but doesn't meet lockout criteria
        if internal and not external and total_syn > 10:
            return (
                "Internal High-Volume Connections — Service or Misconfiguration",
                "INVESTIGATE — Repeated connection attempts from internal source. "
                "Likely a misconfigured service, update agent, or backup job. "
                "Check DHCP/AD logs to identify the endpoint, then verify with the owner.",
            )

        # True fallback — mixed signals, genuinely ambiguous
        return (
            "Inconclusive — Multi-Vector Correlation Required",
            "CORRELATE — Gather: firewall logs (same time window), AD/SIEM auth logs, "
            "endpoint EDR alerts, and DHCP lease records. "
            "Assign to L2 analyst. If unresolved in 30 min, escalate to L3.",
        )
