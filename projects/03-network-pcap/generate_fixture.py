"""Generate an entirely offline, deterministic synthetic Ethernet/IPv4 PCAP.

The packets never cross a network. All addresses use RFC 5737 documentation ranges;
domains use RFC 2606 reserved names. This is an educational fixture only.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import struct
from datetime import datetime, timezone
from pathlib import Path

BASE = int(datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc).timestamp())
SRC = '192.0.2.10'
DNS = '198.51.100.53'
WEB = '203.0.113.80'


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\0'
    words = struct.unpack('!' + 'H' * (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    s, d = ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', checksum(h)) + h[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + h + payload


def udp(src: str, dst: str, sport: int, dport: int, data: bytes, ident: int) -> bytes:
    # IPv4 UDP checksum zero denotes not computed; all lengths are valid.
    datagram = struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data
    return ipv4(src, dst, 17, datagram, ident)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, data: bytes, ident: int) -> bytes:
    header = struct.pack('!HHIIHHHH', sport, dport, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    srcb, dstb = ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed
    pseudo = srcb + dstb + struct.pack('!BBH', 0, 6, len(header) + len(data))
    verified = checksum(pseudo + header + data)
    header = header[:16] + struct.pack('!H', verified) + header[18:]
    return ipv4(src, dst, 6, header + data, ident)


def dns_name(host: str) -> bytes:
    chunks = host.encode('ascii').split(b'.')
    if not chunks or any(not 0 < len(s) <= 63 for s in chunks):
        raise ValueError('invalid synthetic DNS name')
    return b''.join(bytes([len(s)]) + s for s in chunks) + b'\0'


def dns_payload(host: str, txid: int, *, response: bool, rcode: int = 0) -> bytes:
    q = dns_name(host) + struct.pack('!HH', 1, 1)
    flags = (0x8180 | rcode) if response else 0x0100
    answer_count = 1 if response and rcode == 0 else 0
    header = struct.pack('!HHHHHH', txid, flags, 1, answer_count, 0, 0)
    answer = (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) +
              ipaddress.IPv4Address('203.0.113.10').packed) if answer_count else b''
    return header + q + answer


def build_capture() -> bytes:
    frames: list[tuple[int, int, bytes]] = []
    ident = 100

    def add(second: int, micros: int, frame: bytes) -> None:
        frames.append((BASE + second, micros, frame))

    for i in range(5):
        invalid = i < 4
        host = f'bad-{i+1}.invalid' if invalid else 'portal.example'
        client = SRC if invalid else '192.0.2.11'
        port, txid, second = 53000 + i, 0x1200 + i, i * 12
        add(second, 0, udp(client, DNS, port, 53, dns_payload(host, txid, response=False), ident)); ident += 1
        add(second, 200000, udp(DNS, client, 53, port,
                                dns_payload(host, txid, response=True, rcode=3 if invalid else 0), ident)); ident += 1

    for second, client, port, path, host, method in [
        (60, '192.0.2.11', 51000, '/index.html', 'portal.example', 'GET'),
        (75, SRC, 51001, '/upload', 'collector.invalid', 'POST')
    ]:
        body = b'SAFE' if method == 'POST' else b''
        content_length = f'Content-Length: {len(body)}\r\n' if body else ''
        request = (f'{method} {path} HTTP/1.1\r\nHost: {host}\r\n'
                   f'{content_length}Connection: close\r\n\r\n').encode() + body
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        add(second, 0, tcp(client, WEB, port, 80, 100, 0, 0x02, b'', ident)); ident += 1
        add(second, 10000, tcp(WEB, client, 80, port, 800, 101, 0x12, b'', ident)); ident += 1
        add(second, 20000, tcp(client, WEB, port, 80, 101, 801, 0x10, b'', ident)); ident += 1
        add(second, 30000, tcp(client, WEB, port, 80, 101, 801, 0x18, request, ident)); ident += 1
        add(second, 40000, tcp(WEB, client, 80, port, 801, 101 + len(request), 0x18, response, ident)); ident += 1

    frames.sort(key=lambda row: (row[0], row[1]))
    capture = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for seconds, micros, frame in frames:
        capture += struct.pack('<IIII', seconds, micros, len(frame), len(frame)) + frame
    return capture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('synthetic_traffic.pcap'))
    args = parser.parse_args()
    data = build_capture()
    args.output.write_bytes(data)
    print(f'{args.output}: {len(data)} bytes; sha256={hashlib.sha256(data).hexdigest()}')

if __name__ == '__main__':
    main()
