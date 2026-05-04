import unittest

from src.intelligence import TrafficAnswerEngine, TrafficMemory, TrafficWindow, format_inference_statement
from src.models import RankedFlowSummary


def make_ranked_flow(
    source_ip="192.0.2.10",
    destination_ip="8.8.8.8",
    source_port=53000,
    destination_port=53,
    protocol_name="DNS",
    packet_count=8,
    byte_count=900,
    syn_count=0,
    reset_count=0,
    risk_score=4.5,
):
    return RankedFlowSummary(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol_name=protocol_name,
        packet_count=packet_count,
        byte_count=byte_count,
        syn_count=syn_count,
        reset_count=reset_count,
        risk_score=risk_score,
    )


def make_window(
    ranked_flow_summaries,
    window_label="normal",
    anomaly_score=0.12,
    start_timestamp=100.0,
    end_timestamp=110.0,
    inference_summary_text=None,
):
    if inference_summary_text is None:
        inference_summary_text = format_inference_statement("traffic within learned baseline")
    protocol_name_counter = {ranked_flow_summary.protocol_name.upper() for ranked_flow_summary in ranked_flow_summaries}
    return TrafficWindow(
        window_start=start_timestamp,
        window_end=end_timestamp,
        window_feature_values={
            "packets": sum(ranked_flow_summary.packet_count for ranked_flow_summary in ranked_flow_summaries),
            "bytes_total": sum(ranked_flow_summary.byte_count for ranked_flow_summary in ranked_flow_summaries),
            "unique_flows": len(ranked_flow_summaries),
            "unique_src_ips": len({ranked_flow_summary.source_ip for ranked_flow_summary in ranked_flow_summaries}),
            "unique_dst_ips": len({ranked_flow_summary.destination_ip for ranked_flow_summary in ranked_flow_summaries}),
            "protocol_tcp_ratio": 1.0 if "TCP" in protocol_name_counter else 0.0,
            "protocol_udp_ratio": 1.0 if {"DNS", "MDNS", "UDP"} & protocol_name_counter else 0.0,
            "protocol_icmp_ratio": 1.0 if {"ICMP", "ICMPV6"} & protocol_name_counter else 0.0,
            "protocol_other_ratio": 0.0,
        },
        ranked_flow_summaries=ranked_flow_summaries,
        anomaly_score=anomaly_score,
        window_label=window_label,
        inference_summary=inference_summary_text,
    )


class TrafficAnswerEngineTests(unittest.TestCase):
    def make_engine(self, *traffic_windows):
        traffic_memory = TrafficMemory()
        for traffic_window in traffic_windows:
            traffic_memory.add_window(traffic_window)
        return TrafficAnswerEngine(traffic_memory)

    def test_show_dns_packets_without_completed_windows_is_unverified_and_returns_dns_filter(self):
        traffic_answer_engine = self.make_engine()

        answer_text = traffic_answer_engine.answer("show dns packets")

        self.assertIn("Question: show dns packets", answer_text)
        self.assertIn(
            "[Unverified] I cannot verify live matches yet because no analyzed capture window is available.",
            answer_text,
        )
        self.assertIn("Display Filter:\ndns", answer_text)

    def test_show_dns_packets_matches_dns_but_not_mdns(self):
        dns_window = make_window(
            [
                make_ranked_flow(
                    source_ip="192.0.2.10",
                    destination_ip="8.8.8.8",
                    source_port=53000,
                    destination_port=53,
                    protocol_name="DNS",
                ),
                make_ranked_flow(
                    source_ip="192.0.2.20",
                    destination_ip="224.0.0.251",
                    source_port=5353,
                    destination_port=5353,
                    protocol_name="MDNS",
                ),
            ]
        )
        traffic_answer_engine = self.make_engine(dns_window)

        answer_text = traffic_answer_engine.answer("show dns packets")

        self.assertIn("Question: show dns packets", answer_text)
        self.assertIn("Interpreted Intent: [Inference] DNS traffic", answer_text)
        self.assertIn("8.8.8.8:53 DNS", answer_text)
        self.assertNotIn("224.0.0.251:5353 MDNS", answer_text)

    def test_show_mdns_packets_matches_only_mdns(self):
        mdns_window = make_window(
            [
                make_ranked_flow(
                    source_ip="192.0.2.20",
                    destination_ip="224.0.0.251",
                    source_port=5353,
                    destination_port=5353,
                    protocol_name="MDNS",
                ),
                make_ranked_flow(
                    source_ip="192.0.2.10",
                    destination_ip="8.8.8.8",
                    source_port=53000,
                    destination_port=53,
                    protocol_name="DNS",
                ),
            ]
        )
        traffic_answer_engine = self.make_engine(mdns_window)

        answer_text = traffic_answer_engine.answer("show mdns packets")

        self.assertIn("Question: show mdns packets", answer_text)
        self.assertIn("224.0.0.251:5353 MDNS", answer_text)
        self.assertNotIn("8.8.8.8:53 DNS", answer_text)

    def test_filter_dns_returns_builder_only(self):
        traffic_answer_engine = self.make_engine(
            make_window([make_ranked_flow(protocol_name="DNS")])
        )

        answer_text = traffic_answer_engine.answer("filter dns")

        self.assertIn("Question: filter dns", answer_text)
        self.assertIn("=== Wireshark Display Filter Builder ===", answer_text)
        self.assertIn("Display Filter:\ndns", answer_text)
        self.assertNotIn("Live Matches:", answer_text)

    def test_suspicious_before_model_readiness_stays_unverified(self):
        warmup_window = make_window(
            [make_ranked_flow(protocol_name="DNS")],
            window_label="warmup",
        )
        traffic_answer_engine = self.make_engine(warmup_window)

        answer_text = traffic_answer_engine.answer("suspicious")

        self.assertIn("Question: suspicious", answer_text)
        self.assertIn(
            "[Unverified] I cannot verify suspicious live matches yet because no model-scored capture window is available.",
            answer_text,
        )
        self.assertIn("[Inference] traffic within learned baseline", answer_text)

    def test_suspicious_after_model_readiness_labels_inference(self):
        suspicious_window = make_window(
            [
                make_ranked_flow(
                    source_ip="198.51.100.50",
                    destination_ip="203.0.113.22",
                    source_port=49152,
                    destination_port=22,
                    protocol_name="TCP",
                    packet_count=20,
                    byte_count=1200,
                    syn_count=20,
                    risk_score=52.0,
                )
            ],
            window_label="suspicious",
            anomaly_score=0.7214,
            inference_summary_text=format_inference_statement("possible port scan pattern"),
        )
        traffic_answer_engine = self.make_engine(suspicious_window)

        answer_text = traffic_answer_engine.answer("suspicious")

        self.assertIn("Observed suspicious windows: 1", answer_text)
        self.assertIn("Statistics:", answer_text)
        self.assertIn("Expert Info:\n  [Inference] possible port scan pattern", answer_text)

    def test_ip_and_directional_queries_use_requested_addresses(self):
        traffic_window = make_window(
            [
                make_ranked_flow(
                    source_ip="203.0.113.10",
                    destination_ip="198.51.100.77",
                    source_port=40000,
                    destination_port=443,
                    protocol_name="TLS",
                    packet_count=11,
                    byte_count=2200,
                    risk_score=10.5,
                )
            ]
        )
        traffic_answer_engine = self.make_engine(traffic_window)

        direct_answer_text = traffic_answer_engine.answer("ip 203.0.113.10")
        directional_answer_text = traffic_answer_engine.answer("show traffic from 203.0.113.10")
        between_answer_text = traffic_answer_engine.answer("show traffic between 203.0.113.10 and 198.51.100.77")

        self.assertIn("203.0.113.10", direct_answer_text)
        self.assertIn("203.0.113.10:40000 -> 198.51.100.77:443 TLS", directional_answer_text)
        self.assertIn("Display Filter:\nip.src == 203.0.113.10", directional_answer_text)
        self.assertIn("203.0.113.10:40000 -> 198.51.100.77:443 TLS", between_answer_text)
        self.assertIn(
            "Display Filter:\nip.addr == 203.0.113.10 && ip.addr == 198.51.100.77",
            between_answer_text,
        )
