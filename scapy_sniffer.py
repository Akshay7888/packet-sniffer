#!/usr/bin/env python3
"""
scapy_sniffer.py
- Requires: scapy (pip install scapy)
- On Windows install Npcap and run console as admin.
- On Linux run with sudo/root.
"""

from scapy.all import sniff, rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
import binascii
import time
import argparse
import sys

def hexdump_payload(payload, max_len=160):
    if not payload:
        return ""
    b = bytes(payload)
    txt = ''.join((chr(c) if 32 <= c <= 126 else '.') for c in b[:max_len])
    hexs = binascii.hexlify(b[:max_len]).decode()
    return f"hex={hexs} ascii={txt}"

def analyze_packet(pkt, stats):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        stats['hosts'][src] += 1
        stats['hosts'][dst] += 0  # ensure key exists
        stats['protocols'][proto] += 1

        line = f"[{ts}] {src} -> {dst} proto={proto}"

        # TCP
        if TCP in pkt:
            t = pkt[TCP]
            line += f" TCP sport={t.sport} dport={t.dport} flags={t.flags}"
            payload = bytes(t.payload)
            if payload:
                line += " payload=" + hexdump_payload(payload, max_len=80)
            stats['flows'][(src, t.sport, dst, t.dport, 'TCP')] += 1

        # UDP
        elif UDP in pkt:
            u = pkt[UDP]
            line += f" UDP sport={u.sport} dport={u.dport}"
            payload = bytes(u.payload)
            if payload:
                line += " payload=" + hexdump_payload(payload, max_len=80)
            stats['flows'][(src, u.sport, dst, u.dport, 'UDP')] += 1

        # ICMP
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            line += f" ICMP type={icmp.type} code={icmp.code}"
            stats['flows'][(src, None, dst, None, 'ICMP')] += 1

        else:
            # other IP protocols
            line += f" (other IP proto layer)"
            stats['flows'][(src, None, dst, None, f'IP-{proto}')] += 1

        print(line)

    else:
        # non-IP packet (ARP, etc.)
        print(f"[{ts}] Non-IP packet: {pkt.summary()}")
        stats['non_ip'] += 1

def summary_report(stats):
    print("\n\n=== Summary Report ===")
    print("Total packets captured:", stats['total'])
    print("Non-IP packets:", stats['non_ip'])
    print("\nTop protocols (by count):")
    # map numeric proto to names when possible
    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    for proto, count in stats['protocols'].most_common(10):
        name = proto_map.get(proto, str(proto))
        print(f"  {name} ({proto}): {count}")

    print("\nTop hosts (by packets sent/seen):")
    for host, cnt in stats['hosts'].most_common(10):
        print(f"  {host}: {cnt}")

    print("\nTop flows (src, sport, dst, dport, proto):")
    for flow, cnt in sorted(stats['flows'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {flow}: {cnt}")
    print("======================\n")

def main():
    parser = argparse.ArgumentParser(description="Simple Scapy-based packet sniffer + analyzer")
    parser.add_argument("-i", "--iface", help="Interface to sniff on (default: scapy chooses)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (default: 0 = forever)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g. 'tcp and port 80')", default=None)
    parser.add_argument("-o", "--out", help="Write captured packets to pcap file", default=None)
    parser.add_argument("--promisc", action="store_true", help="Enable promiscuous mode")
    args = parser.parse_args()

    stats = {
        'total': 0,
        'non_ip': 0,
        'protocols': Counter(),
        'hosts': Counter(),
        'flows': Counter(),
    }

    captured = []

    def handle(pkt):
        stats['total'] += 1
        analyze_packet(pkt, stats)
        captured.append(pkt)
        # somewhere to stop early?
        # (count handling done by sniff if provided)

    print("Starting capture... (press Ctrl-C to stop)\n")
    try:
        sniff(iface=args.iface, prn=handle, filter=args.filter, count=args.count or 0, store=False, promisc=args.promisc)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print("Error during sniffing:", e, file=sys.stderr)

    if args.out and captured:
        try:
            wrpcap(args.out, captured)
            print(f"Wrote {len(captured)} packets to {args.out}")
        except Exception as e:
            print("Failed to write pcap:", e, file=sys.stderr)

    summary_report(stats)

if __name__ == "__main__":
    main()
