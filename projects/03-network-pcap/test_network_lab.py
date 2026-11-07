"""Focused fixture, parser, false-positive and corruption tests. No network use."""
import json
import struct
import unittest
from pathlib import Path

from analyze_pcap import MAX_FILE, analyze, decode_frame, detect, read_name, read_packets
from generate_fixture import build_capture

HERE = Path(__file__).parent
EXPECTED_SHA = '5fc309499252677ba5cd31106b611edde5fd1b941aed3cc2f87f216da4dd707c'


def events():
    return [event for ts, frame in read_packets(build_capture())
            if (event := decode_frame(ts, frame)) is not None]


class PacketLabTests(unittest.TestCase):
    def test_capture_determinism(self):
        self.assertEqual(build_capture(), build_capture())
        self.assertEqual(analyze(build_capture())['capture_sha256'], EXPECTED_SHA)

    def test_packet_and_event_counts(self):
        result = analyze(build_capture())
        self.assertEqual(result['packet_count'], 20)
        self.assertEqual(result['decoded_event_count'], 12)

    def test_expected_findings(self):
        expected = json.loads((HERE / 'expected_findings.json').read_text())
        self.assertEqual(analyze(build_capture())['findings'], expected['findings'])

    def test_five_valid_and_invalid_dns_pairs(self):
        messages = [e for e in events() if e['kind'] == 'dns']
        self.assertEqual((len(messages), sum(e['response'] for e in messages)), (10, 5))
        self.assertEqual(sum(e['response'] and e['rcode'] == 3 for e in messages), 4)

    def test_no_dns_alert_without_matching_queries(self):
        replies = [e for e in events() if e['kind'] == 'dns' and e['response']]
        self.assertEqual(detect(replies), [])

    def test_duplicate_dns_reply_is_not_counted_twice(self):
        items = events()
        response = next(e for e in items if e['kind'] == 'dns' and e['response'] and e['rcode'] == 3)
        output = detect(items + [dict(response)])
        dns = [e for e in output if e['rule_id'] == 'NET_DNS_NXDOMAIN_BURST']
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]['nxdomain_count_in_window'], 4)

    def test_nxdomain_responses_spread_past_window(self):
        items = events()
        for e in items:
            if e['kind'] == 'dns' and (e['name'] == 'bad-4.invalid'):
                e['ts'] += 120
        dns = [r for r in detect(items) if r['rule_id'] == 'NET_DNS_NXDOMAIN_BURST']
        self.assertEqual(dns, [])

    def test_http_get_is_not_flagged(self):
        http = [e for e in events() if e['kind'] == 'http']
        self.assertEqual(len(http), 2)
        self.assertEqual(detect([e for e in http if e['method'] == 'GET']), [])

    def test_http_post_to_nonreserved_host_not_flagged(self):
        http = next(e for e in events() if e['kind'] == 'http' and e['method'] == 'POST')
        self.assertEqual(detect([dict(http, host='portal.example')]), [])

    def test_pcap_magic_is_validated(self):
        with self.assertRaisesRegex(ValueError, 'little-endian'):
            list(read_packets(b'\0' * 24))

    def test_truncated_record_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            list(read_packets(build_capture()[:-4]))

    def test_extra_partial_packet_header_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated PCAP packet header'):
            list(read_packets(build_capture() + b'\x00'))

    def test_link_type_mismatch_rejected(self):
        damaged = bytearray(build_capture())
        struct.pack_into('<I', damaged, 20, 101)
        with self.assertRaisesRegex(ValueError, 'Unsupported PCAP'):
            list(read_packets(damaged))

    def test_oversize_rejected(self):
        with self.assertRaisesRegex(ValueError, 'safety limit'):
            list(read_packets(bytes(MAX_FILE + 1)))

    def test_fragmented_ipv4_ignored(self):
        ts, frame = next(iter(read_packets(build_capture())))
        modified = bytearray(frame)
        struct.pack_into('!H', modified, 20, 0x2000)
        self.assertIsNone(decode_frame(ts, modified))

    def test_dns_compression_pointer_in_question_rejected(self):
        with self.assertRaisesRegex(ValueError, 'compressed'):
            read_name(b'\xc0\x0c', 0)

    def test_dns_normal_success_not_alerted(self):
        normal = [e for e in events() if e['kind'] == 'dns' and e['name'] == 'portal.example']
        self.assertEqual(detect(normal), [])

    def test_split_by_client_identity(self):
        items = events()
        for e in items:
            if e['kind'] == 'dns' and e['name'] in {'bad-3.invalid', 'bad-4.invalid'}:
                if e['response']:
                    e['dst'] = '192.0.2.77'
                else:
                    e['src'] = '192.0.2.77'
        self.assertEqual([r for r in detect(items) if r['rule_id'] == 'NET_DNS_NXDOMAIN_BURST'], [])


if __name__ == '__main__':
    unittest.main()
