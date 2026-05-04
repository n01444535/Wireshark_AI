import unittest

from src.features import build_window_feature_values
from src.models import PacketRecord, RankedFlowSummary
from src.parser import (
    parse_optional_packet_float,
    parse_optional_packet_int,
    parse_tcp_flag_field,
    parse_tshark_csv_line,
)


class ParserAndFeatureTests(unittest.TestCase):
    def test_packet_field_helpers_parse_expected_values(self):
        self.assertEqual(parse_optional_packet_int("53,54"), 53)
        self.assertEqual(parse_optional_packet_int(""), None)
        self.assertEqual(parse_optional_packet_float("10.25"), 10.25)
        self.assertEqual(parse_tcp_flag_field("True"), 1)
        self.assertEqual(parse_tcp_flag_field("0"), 0)

    def test_parse_tshark_csv_line_returns_packet_record(self):
        packet_csv_line = (
            '"1710000000.123","192.0.2.10","8.8.8.8","","","53000","","53","","DNS","74","0","0","0","0","0","0","64",""'
        )

        packet_record = parse_tshark_csv_line(packet_csv_line)

        self.assertIsNotNone(packet_record)
        self.assertEqual(packet_record.timestamp, 1710000000.123)
        self.assertEqual(packet_record.src_ip, "192.0.2.10")
        self.assertEqual(packet_record.dst_ip, "8.8.8.8")
        self.assertEqual(packet_record.src_port, 53000)
        self.assertEqual(packet_record.dst_port, 53)
        self.assertEqual(packet_record.protocol, "DNS")
        self.assertEqual(packet_record.length, 74)
        self.assertEqual(packet_record.ttl, 64)

    def test_build_window_feature_values_returns_ranked_flow_dataclasses(self):
        packet_records = [
            PacketRecord(
                timestamp=1.0,
                src_ip="192.0.2.10",
                dst_ip="8.8.8.8",
                src_port=53000,
                dst_port=53,
                protocol="DNS",
                length=74,
                tcp_flags_syn=0,
                tcp_flags_ack=0,
                tcp_flags_rst=0,
                tcp_flags_fin=0,
                tcp_flags_psh=0,
                tcp_flags_urg=0,
                ttl=64,
            ),
            PacketRecord(
                timestamp=2.0,
                src_ip="192.0.2.10",
                dst_ip="8.8.8.8",
                src_port=53000,
                dst_port=53,
                protocol="DNS",
                length=90,
                tcp_flags_syn=0,
                tcp_flags_ack=0,
                tcp_flags_rst=0,
                tcp_flags_fin=0,
                tcp_flags_psh=0,
                tcp_flags_urg=0,
                ttl=64,
            ),
        ]

        window_feature_values, ranked_flow_summaries, inference_summary_text = build_window_feature_values(
            packet_records,
            display_top_flow_count=5,
        )

        self.assertIsInstance(window_feature_values, dict)
        self.assertEqual(window_feature_values["packets"], 2)
        self.assertEqual(len(ranked_flow_summaries), 1)
        self.assertIsInstance(ranked_flow_summaries[0], RankedFlowSummary)
        self.assertEqual(ranked_flow_summaries[0].source_ip, "192.0.2.10")
        self.assertEqual(ranked_flow_summaries[0].destination_ip, "8.8.8.8")
        self.assertEqual(ranked_flow_summaries[0].destination_port, 53)
        self.assertEqual(ranked_flow_summaries[0].packet_count, 2)
        self.assertEqual(ranked_flow_summaries[0].byte_count, 164)
        self.assertIsInstance(inference_summary_text, str)
