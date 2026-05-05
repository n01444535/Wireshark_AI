# Wireshark AI Traffic Assistant

Captures or reads network traffic, learns a baseline, detects anomalies, and answers plain-language questions — without manually reading every packet.

---

## SOC Use Cases

This system is designed to support real Security Operations Center (SOC) workflows. It combines **rule-based detection** with **ML anomaly scoring** — the same hybrid approach used in production SIEM platforms.

| Scenario | Detection Method | MITRE ATT&CK |
|----------|-----------------|--------------|
| SYN Flood / DoS attack | High SYN ratio + many destination IPs | T1498.001 |
| Port scanning activity | Many destination ports + short-lived flows | T1046 |
| Suspicious service access (SSH/RDP/SMB) | Connections to critical ports 22, 3389, 445 | T1021 |
| ARP cache poisoning / MiTM | Gratuitous ARP flood, MAC claiming multiple IPs | T1557.002 |
| Lateral movement / host sweep | Fan-out to many hosts with few packets per flow | T1021 |
| ICS/SCADA HMI reconnaissance | HTTP access to industrial control endpoints | T1071.001 |
| Brute force (SSH/RDP) | High SYN rate, all connections rejected | T1110 |
| Cleartext credential exposure | Telnet protocol detected | T1040 |
| Data exfiltration | Large outbound packets to external IPs | T1041 |
| Distributed SYN flood (DDoS) | Many source IPs all sending SYN | T1498.001 |

### Alert Output Format

Every suspicious detection prints a structured SOC alert block:

```
════════════════════════════════════════════════════════
[2026-05-04 21:04:32] ALERT — HIGH
────────────────────────────────────────────────────────
Threat   : SYN Flood Suspected  [T1498.001]
Source   : 192.168.xxx.xxx
Severity : HIGH
Evidence :
  - SYN ratio: 0.78
  - Unique destinations: 45
  - Packets: 342

Top Flows:
  1. 192.168.xxx.xxx → 192.168.xxx.xxx  [TCP, 120 pkts]
     Filter: ip.src == 192.168.xxx.xxx && ip.dst == 192.168.xxx.xxx
════════════════════════════════════════════════════════
```

Normal windows produce a single quiet line:

```
[21:04:42] NORMAL | Packets=87 | Flows=12
```

### SIEM-Style Log

Every alert is appended to `logs/siem.log` in CSV format for integration with external SIEM tools:

```
timestamp,alert_type,severity,mitre_id,src_ips,dst_ips,packets,window_start,window_end
2026-05-04T21:04:32,SYN Flood Suspected,HIGH,T1498.001,192.168.xxx.xxx,192.168.xxx.xxx,342,...
```

### Detection Architecture

```
Packet stream
     │
     ▼
Rule-based engine ──► Immediate flag for known attack signatures
     │                (ARP poisoning, ICS recon, SYN flood, port scan)
     ▼
ML anomaly scorer ──► IsolationForest trained on baseline traffic
     │                (catches unknown patterns the rules miss)
     ▼
Triage engine ──► Scores evidence, classifies TP vs FP
                  (external IP +pts, business hours -pts, etc.)
     │
     ▼
SIEM-style alert (HIGH / MEDIUM / LOW) + MITRE ATT&CK mapping
```

---

## Requirements

- Python 3.9+
- tshark (install Wireshark to get it)
- scikit-learn

```
python3 -m pip install -r requirements.txt
```

---

## Two Modes

| Mode | Use When |
|------|----------|
| `--interface` | Capture live traffic from a network interface |
| `--pcap` | Analyse an existing `.pcap` / `.pcapng` file offline |

Exactly one of `--interface` or `--pcap` is required.

---

## Live Capture Mode

```
python3 main.py --interface en0
```

If packet capture requires elevated permissions:

```
sudo python3 main.py --interface en0
```

The app prints startup info, warms up over several windows, then unlocks the question prompt:

```
Starting live capture on interface: en0
Local IP: 192.xxx.x.x  (use 'show traffic from this ip' to trace outbound)
Window size: 10s
Warmup windows: 6
Live question mode starting. Available commands: suspicious, summary, ...
Questions are disabled until all stages are ready.

Live match commands are ready.

Suspicious detection is ready.
question>
```

---

## Pcap File Mode

Read and analyse a saved `.pcap` or `.pcapng` file:

```
python3 main.py --pcap capture.pcap
```

With options:

```
python3 main.py --pcap capture.pcap --window-seconds 10 --warmup-windows 3
```

Apply a Wireshark display filter when reading (filters which packets are loaded):

```
python3 main.py --pcap capture.pcap --filter "tcp"
python3 main.py --pcap capture.pcap --filter "ip.addr == 192.168.xxx.xxx"
python3 main.py --pcap capture.pcap --filter "dns or http"
```

> Note: in pcap mode `--filter` uses **Wireshark display filter** syntax, not BPF.

Example output:

```
Reading pcap: capture.pcap
Loaded 12,450 packets.
Processing 47 windows  [window=10s  warmup=3  scored=44]

--- Analysis Complete ---
  Windows total  : 47
  Warmup         : 3
  Scored         : 44
    Normal       : 41
    Suspicious   : 3
  CSV output     : results/live_traffic_windows.csv

All windows processed. Ready for questions.
Commands: suspicious, summary, top flows, filter, ip <addr>, show ..., help, quit
question>
```

If the pcap has fewer windows than `--warmup-windows`, warmup is adjusted automatically.

---

## Interactive Questions

Questions are only accepted after all warmup stages are ready.

```
question> suspicious
question> summary
question> top flows
question> filter
question> filter help
question> ip 192.xxx.x.xxx
question> show dns packets
question> show traffic from this ip
question> show traffic from 10.x.x.xx
question> show traffic to 8.8.8.8
question> show traffic between 10.x.x.xx and 8.8.8.8
question> show https traffic
question> show port 443
question> help
question> quit
```

### Self-reference commands (live mode only)

`show traffic from this ip` and `show traffic from me` automatically use the detected local machine IP — no need to know or type the IP address.

---

## Common Options

| Option | Default | Description |
|--------|---------|-------------|
| `--window-seconds N` | 10 | Time window size in seconds |
| `--warmup-windows N` | 6 | Windows used to learn the baseline |
| `--contamination F` | 0.15 | IsolationForest contamination (0.01–0.50) |
| `--display-top-flows N` | 5 | Top-N flows shown per window in terminal |
| `--output-csv PATH` | results/live_traffic_windows.csv | CSV output path |
| `--filter EXPR` | — | BPF filter (live) or Wireshark display filter (pcap) |
| `--tshark-path PATH` | tshark | Path to tshark binary |
| `--max-packets-per-window N` | 50000 | Cap packets kept per window |
| `--no-interactive` | — | Disable question prompt (for automation) |
| `--show-window-events` | — | Show per-window logs in interactive mode |

---

## Example: Analyse a Pcap File

```
# Basic analysis with default 10s windows
python3 main.py --pcap ~/Downloads/traffic.pcap

# Smaller windows for a short capture
python3 main.py --pcap ~/Downloads/traffic.pcap --window-seconds 5 --warmup-windows 2

# Only analyse TCP traffic
python3 main.py --pcap ~/Downloads/traffic.pcap --filter "tcp"

# Save results to a custom CSV
python3 main.py --pcap ~/Downloads/traffic.pcap --output-csv results/my_analysis.csv

# Non-interactive (batch analysis only, no question prompt)
python3 main.py --pcap ~/Downloads/traffic.pcap --no-interactive
```

---

## Example Question Output

**Match found:**

```
question> show dns packets

> show dns packets
=== Dns Traffic ===
Wireshark filter:  dns
Windows searched:  20  |  Matching flows: 3  |  Packets: 45  |  Bytes: 2700
Conversations:
  1. [14:22:10-14:22:20] NORMAL
     192.168.xxx.xxx:54321 -> 8.8.8.8:53 DNS | packets=20 bytes=1200 syn=0 rst=0 risk=10.00
        Wireshark filter: ip.src == 192.168.xxx.xxx && ip.dst == 8.8.8.8 && udp.dstport == 53
```

**No match:**

```
question> show dns packets

> show dns packets
=== Dns Traffic ===
Wireshark filter:  dns
Windows searched:  20
Result:  No matching flows found in the analyzed data.
         Apply the filter above in Wireshark to verify manually.
```

**Filter builder only:**

```
question> filter dns

> filter dns
=== Wireshark Display Filter Builder ===
Interpreted Intent: [Inference] DNS traffic
Display Filter:
dns
Why: [Inference] Matches decoded DNS packets.
```

**Suspicious windows:**

```
question> suspicious

> suspicious
=== Wireshark Expert Info ===
Observed suspicious windows: 1

Alert 1: SUSPICIOUS | 21:40:10-21:40:20 | Score=0.7214
Statistics:
  Packets: 300
  Bytes: 24000
  Conversations: 80
  Unique Sources: 25
  Unique Destinations: 30
  Protocol Mix: TCP=95.0% UDP=5.0% ICMP=0.0% Other=0.0%
Expert Info:
  [Inference] possible port scan pattern
Conversations:
  1. 10.xxx.xxx.xxx:49152 -> 10.xxx.xxx.xxx:22 TCP | packets=20 bytes=1200 syn=20 rst=0 risk=52.00
     Wireshark filter: ip.src == 10.xxx.xxx.xxx && ip.dst == 10.xxx.xxx.xxx && tcp.srcport == 49152 && tcp.dstport == 22
```

---

## Supported Filter Phrases

| Command | Wireshark Filter |
|---------|-----------------|
| `filter tcp` | `tcp` |
| `filter udp` | `udp` |
| `filter dns` | `dns` |
| `filter mdns` | `mdns` |
| `filter icmp` | `icmp \|\| icmpv6` |
| `filter arp` | `arp` |
| `filter http` | `http` |
| `filter https` | `tls \|\| tcp.port == 443` |
| `filter tls handshake` | `tls.handshake` |
| `filter dhcp` | `dhcp \|\| bootp` |
| `filter quic` | `quic \|\| udp.port == 443` |
| `filter syn` | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| `filter reset` | `tcp.flags.reset == 1` |
| `filter fin` | `tcp.flags.fin == 1` |
| `filter ack` | `tcp.flags.ack == 1` |
| `filter tcp retransmissions` | `tcp.analysis.retransmission \|\| tcp.analysis.fast_retransmission` |
| `filter tcp errors` | `tcp.analysis.flags` |
| `filter large packets` | `frame.len > 1000` |
| `filter small packets` | `frame.len < 100` |
| `filter broadcast packets` | `eth.dst == ff:ff:ff:ff:ff:ff \|\| ip.dst == 255.255.255.255` |
| `filter multicast packets` | `eth.dst[0] & 1` |
| `filter port 443` | `(tcp.port == 443 \|\| udp.port == 443)` |
| `filter source port 5353` | `(tcp.srcport == 5353 \|\| udp.srcport == 5353)` |
| `filter destination port 53` | `(tcp.dstport == 53 \|\| udp.dstport == 53)` |
| `filter ssh traffic` | `(tcp.port == 22 \|\| udp.port == 22)` |
| `filter smtp traffic` | `(tcp.port == 25 \|\| udp.port == 25)` |
| `filter rdp traffic` | `(tcp.port == 3389 \|\| udp.port == 3389)` |
| `filter mysql traffic` | `(tcp.port == 3306 \|\| udp.port == 3306)` |
| `filter redis traffic` | `(tcp.port == 6379 \|\| udp.port == 6379)` |
| `show traffic from <ip>` | `ip.src == <ip>` (with live match) |
| `show traffic from this ip` | `ip.src == <local IP>` (auto-detect, live mode) |
| `show traffic to <ip>` | `ip.dst == <ip>` (with live match) |
| `show traffic between <ip1> and <ip2>` | `ip.addr == <ip1> && ip.addr == <ip2>` |

---

## Output Labels

| Label | Meaning |
|-------|---------|
| `[Inference]` | Interpreted or model-produced statement |
| `[Unverified]` | Cannot be confirmed from completed capture windows |
| `[Speculation]` | Intentionally hypothetical output |

---

## CSV Output

Each analyzed window is appended to the CSV file with columns: timestamp, window_start, window_end, packets, bytes_total, unique_flows, protocol ratios, TCP flag ratios, anomaly score, label (`warmup` / `normal` / `suspicious`), and summary.

---

## Shutdown

Press `Ctrl+C` to stop, or type `quit` / `exit` / `stop` at the question prompt.

---

## Files

```
main.py
src/
  app.py          — live capture app + pcap analysis app (rule-based + ML hybrid)
  capture.py      — tshark process wrapper
  config.py       — CLI argument definitions
  features.py     — packet-to-feature conversion
  intelligence.py — question routing and answer formatting
  models.py       — data classes
  parser.py       — tshark CSV line parser
  reporter.py     — SOC alert output, CSV, and SIEM log writer
  triage.py       — alert triage engine with MITRE ATT&CK mapping
results/
  live_traffic_windows.csv   — default CSV output per window
logs/
  siem.log                   — SIEM-style alert log (appended each session)
```
