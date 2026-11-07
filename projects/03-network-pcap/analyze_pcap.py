"""Bounded, read-only PCAP parser for the synthetic DNS/HTTP portfolio fixture.

Supports classic little-endian microsecond PCAP, Ethernet II, unfragmented
IPv4, UDP DNS A queries/responses and unencrypted single-packet HTTP requests.
It is NOT a full PCAP parser, IDS, TCP reassembler or production tool.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import struct
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE = 2 * 1024 * 1024
MAX_PACKETS = 10000
DNS_THRESHOLD = 4
DNS_WINDOW_SECONDS = 60


def read_packets(raw: bytes):
    if len(raw) > MAX_FILE:
        raise ValueError('Capture exceeds 2 MiB safety limit')
    if len(raw) < 24 or raw[:4] != b'\xd4\xc3\xb2\xa1':
        raise ValueError('Only classic little-endian microsecond PCAP is supported')
    _magic, major, minor, _zone, _sig, snaplen, linktype = struct.unpack_from('<IHHIIII', raw)
    if (major, minor, linktype) != (2, 4, 1) or not 1 <= snaplen <= 65535:
        raise ValueError('Unsupported PCAP version, link type, or snaplen')
    offset, count = 24, 0
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise ValueError('Truncated PCAP packet header')
        secs, micros, incl, orig = struct.unpack_from('<IIII', raw, offset)
        offset += 16
        if micros >= 1000000 or incl > snaplen or incl > orig or offset + incl > len(raw):
            raise ValueError('Invalid or truncated PCAP packet record')
        count += 1
        if count > MAX_PACKETS:
            raise ValueError('PCAP packet count exceeds safety limit')
        yield secs + micros / 1_000_000, raw[offset:offset + incl]
        offset += incl


def read_name(data: bytes, start: int) -> tuple[str, int]:
    labels, offset = [], start
    for _ in range(128):
        if offset >= len(data):
            raise ValueError('Truncated DNS query name')
        size = data[offset]
        offset += 1
        if size == 0:
            return '.'.join(labels).lower(), offset
        if size > 63 or offset + size > len(data):
            raise ValueError('Unsupported compressed or invalid DNS question name')
        try:
            labels.append(data[offset:offset + size].decode('ascii'))
        except UnicodeDecodeError as exc:
            raise ValueError('Non-ASCII DNS label') from exc
        offset += size
    raise ValueError('DNS label count exceeds limit')


def decode_frame(ts: float, frame: bytes) -> dict | None:
    if len(frame) < 34 or frame[12:14] != b'\x08\x00':
        return None
    vihl = frame[14]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(frame) < 14 + ihl:
        return None
    total = struct.unpack_from('!H', frame, 16)[0]
    flags = struct.unpack_from('!H', frame, 20)[0]
    if total < ihl or len(frame) < 14 + total or (flags & 0x3FFF):
        return None
    proto = frame[23]
    src = str(ipaddress.IPv4Address(frame[26:30]))
    dst = str(ipaddress.IPv4Address(frame[30:34]))
    data = frame[14 + ihl:14 + total]
    if proto == 17:
        if len(data) < 8:
            return None
        sport, dport, ulen = struct.unpack_from('!HHH', data)
        if min(sport, dport) != 53 or ulen < 8 or ulen > len(data):
            return None
        dns = data[8:ulen]
        if len(dns) < 12:
            return None
        txid, word, questions = struct.unpack_from('!HHH', dns)
        if questions != 1:
            return None
        try:
            name, offset = read_name(dns, 12)
        except ValueError:
            return None
        if offset + 4 > len(dns):
            return None
        qtype, qclass = struct.unpack_from('!HH', dns, offset)
        if (qtype, qclass) != (1, 1):
            return None
        return {'kind': 'dns', 'ts': ts, 'src': src, 'dst': dst, 'sport': sport,
                'dport': dport, 'txid': txid, 'name': name,
                'response': bool(word & 0x8000), 'rcode': word & 0xF}
    if proto == 6:
        if len(data) < 20:
            return None
        sport, dport = struct.unpack_from('!HH', data)
        offset = (data[12] >> 4) * 4
        if offset < 20 or offset > len(data) or dport != 80:
            return None
        body = data[offset:]
        # This fixture uses one unencrypted HTTP request per TCP payload.
        if len(body) > 2048 or b'\r\n\r\n' not in body:
            return None
        try:
            header_text = body.split(b'\r\n\r\n', 1)[0].decode('ascii')
        except UnicodeDecodeError:
            return None
        lines = header_text.split('\r\n')
        match = re.fullmatch(r'(GET|POST) (/[^ ]{0,200}) HTTP/1\.[01]', lines[0])
        if not match:
            return None
        hosts = [line.split(':', 1)[1].strip().lower() for line in lines[1:]
                 if line.lower().startswith('host:')]
        if len(hosts) != 1:
            return None
        return {'kind': 'http', 'ts': ts, 'src': src, 'dst': dst, 'sport': sport,
                'dport': dport, 'method': match.group(1), 'path': match.group(2), 'host': hosts[0]}
    return None


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def detect(events: list[dict]) -> list[dict]:
    queries: dict[tuple, float] = {}
    nxdomain: dict[str, deque] = defaultdict(deque)
    flagged_dns: set[str] = set()
    results = []
    for ev in sorted(events, key=lambda e: e['ts']):
        if ev['kind'] == 'dns':
            if not ev['response'] and ev['dport'] == 53:
                queries[(ev['src'], ev['dst'], ev['sport'], ev['txid'], ev['name'])] = ev['ts']
            elif ev['response'] and ev['sport'] == 53:
                key = (ev['dst'], ev['src'], ev['dport'], ev['txid'], ev['name'])
                qt = queries.pop(key, None)
                if qt is None or ev['ts'] < qt or ev['ts'] - qt > 10 or ev['rcode'] != 3:
                    continue
                client = ev['dst']
                history = nxdomain[client]
                while history and history[0] < ev['ts'] - DNS_WINDOW_SECONDS:
                    history.popleft()
                history.append(ev['ts'])
                if len(history) >= DNS_THRESHOLD and client not in flagged_dns:
                    results.append({'rule_id': 'NET_DNS_NXDOMAIN_BURST',
                                    'observed_at_utc': utc(ev['ts']), 'source_ip': client,
                                    'nxdomain_count_in_window': len(history),
                                    'attack_hypothesis': 'T1071.004 DNS',
                                    'assessment': 'Synthetic triage signal; not evidence of DNS tunneling'})
                    flagged_dns.add(client)
        elif ev['kind'] == 'http' and ev['method'] == 'POST' and ev['host'].endswith('.invalid'):
            results.append({'rule_id': 'NET_HTTP_POST_RESERVED_HOST',
                            'observed_at_utc': utc(ev['ts']), 'source_ip': ev['src'],
                            'destination_ip': ev['dst'], 'host': ev['host'], 'path': ev['path'],
                            'attack_hypothesis': 'T1071.001 Web Protocols',
                            'assessment': 'Synthetic triage signal; not evidence of exfiltration'})
    return results


def analyze(raw: bytes) -> dict:
    packet_count, events = 0, []
    for ts, frame in read_packets(raw):
        packet_count += 1
        item = decode_frame(ts, frame)
        if item is not None:
            events.append(item)
    return {'capture_sha256': hashlib.sha256(raw).hexdigest(),
            'packet_count': packet_count,
            'decoded_event_count': len(events),
            'findings': detect(events)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path)
    args = parser.parse_args()
    try:
        if args.pcap.stat().st_size > MAX_FILE:
            raise ValueError('PCAP exceeds 2 MiB safety limit')
        report = analyze(args.pcap.read_bytes())
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
