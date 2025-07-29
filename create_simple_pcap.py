#!/usr/bin/env python3
"""
Script to create a sample PCAP file for testing FlagSniff
This creates synthetic packets with flags, credentials, and tokens
"""

from scapy.all import *
import random

def create_sample_pcap():
    """Create a sample PCAP file with various test data"""
    packets = []
    
    # Sample 1: HTTP request with CTF flag
    http_flag_payload = """GET /challenge HTTP/1.1
Host: ctf.example.com
User-Agent: Mozilla/5.0
Accept: text/html

<!-- Debug info: flag{h3ll0_w0rld_fr0m_p4ck3t5} -->
"""
    
    pkt1 = IP(src="192.168.1.10", dst="192.168.1.1")/TCP(sport=12345, dport=80)/Raw(load=http_flag_payload.encode())
    packets.append(pkt1)
    
    # Sample 2: HTTP POST with credentials
    login_payload = """POST /login HTTP/1.1
Host: admin.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

username=admin&password=secret123"""
    
    pkt2 = IP(src="192.168.1.20", dst="192.168.1.1")/TCP(sport=12346, dport=80)/Raw(load=login_payload.encode())
    packets.append(pkt2)
    
    # Sample 3: HTTP with JWT token
    jwt_payload = """GET /api/user HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Accept: application/json

"""
    
    pkt3 = IP(src="192.168.1.30", dst="192.168.1.1")/TCP(sport=12347, dport=80)/Raw(load=jwt_payload.encode())
    packets.append(pkt3)
    
    # Sample 4: FTP credentials
    ftp_payload = "USER administrator\r\n"
    pkt4 = IP(src="192.168.1.40", dst="192.168.1.2")/TCP(sport=12348, dport=21)/Raw(load=ftp_payload.encode())
    packets.append(pkt4)
    
    ftp_pass = "PASS SuperSecret2023!\r\n"
    pkt5 = IP(src="192.168.1.40", dst="192.168.1.2")/TCP(sport=12348, dport=21)/Raw(load=ftp_pass.encode())
    packets.append(pkt5)
    
    # Sample 5: DNS query
    dns_pkt = IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=53000, dport=53)/DNS(rd=1, qd=DNSQR(qname="flag.ctf.com"))
    packets.append(dns_pkt)
    
    # Sample 6: HTTP with API key
    api_payload = """GET /api/data?apikey=sk-1234567890abcdef1234567890abcdef HTTP/1.1
Host: secure-api.example.com
User-Agent: Python/requests

"""
    
    pkt6 = IP(src="192.168.1.60", dst="192.168.1.1")/TCP(sport=12349, dport=80)/Raw(load=api_payload.encode())
    packets.append(pkt6)
    
    # Sample 7: Another flag format
    flag2_payload = """HTTP/1.1 200 OK
Content-Type: text/html

<html><body>
<h1>Congratulations!</h1>
<p>You found it: HTB{n3tw0rk_f0r3ns1cs_m4st3r}</p>
</body></html>"""
    
    pkt7 = IP(src="192.168.1.1", dst="192.168.1.10")/TCP(sport=80, dport=12345)/Raw(load=flag2_payload.encode())
    packets.append(pkt7)
    
    # Sample 8: Basic Auth
    basic_auth_payload = """GET /admin HTTP/1.1
Host: secret.example.com
Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
User-Agent: curl/7.68.0

"""
    
    pkt8 = IP(src="192.168.1.70", dst="192.168.1.1")/TCP(sport=12350, dport=80)/Raw(load=basic_auth_payload.encode())
    packets.append(pkt8)
    
    # Add some normal traffic to make it realistic
    for i in range(10):
        normal_payload = f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        normal_pkt = IP(src=f"192.168.1.{100+i}", dst="192.168.1.1")/TCP(sport=12000+i, dport=80)/Raw(load=normal_payload.encode())
        packets.append(normal_pkt)
    
    # Write to PCAP file
    wrpcap("test_data/sample.pcap", packets)
    print("✅ Created sample.pcap with test data")
    print(f"📊 Generated {len(packets)} packets")
    print("🎯 Contains: flags, credentials, tokens, API keys")

if __name__ == "__main__":
    import os
    os.makedirs("test_data", exist_ok=True)
    create_sample_pcap()
