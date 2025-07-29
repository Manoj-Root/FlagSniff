"""
Packet parsing utilities for FlagSniff
"""

from typing import Dict, Optional, Any
from scapy.all import IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import base64

class PacketParser:
    """Handles parsing of different packet types and protocols"""
    
    def extract_data(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant data from packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            packet_info = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': self._get_protocol(packet),
                'data': '',
                'raw_data': b''
            }
            
            # Extract payload data
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                packet_info['raw_data'] = raw_data
                
                # Try to decode as text
                try:
                    packet_info['data'] = raw_data.decode('utf-8', errors='ignore')
                except:
                    packet_info['data'] = str(raw_data)
            
            # HTTP specific parsing
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                packet_info['protocol'] = 'HTTP'
                if packet.haslayer(Raw):
                    http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    packet_info['data'] = http_data
                    
                    # Extract HTTP headers and body
                    if '\r\n\r\n' in http_data:
                        headers, body = http_data.split('\r\n\r\n', 1)
                        packet_info['http_headers'] = headers
                        packet_info['http_body'] = body
            
            # DNS specific parsing
            elif packet.haslayer(DNS):
                packet_info['protocol'] = 'DNS'
                if packet[DNS].qr == 0:  # Query
                    packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                else:  # Response
                    packet_info['dns_response'] = str(packet[DNS].an)
            
            # FTP/Telnet (port-based detection)
            elif packet.haslayer(TCP):
                if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    packet_info['protocol'] = 'FTP'
                elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                    packet_info['protocol'] = 'Telnet'
                else:
                    packet_info['protocol'] = 'TCP'
            
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
            
            return packet_info
            
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None
    
    def _get_protocol(self, packet) -> str:
        """Determine packet protocol"""
        if packet.haslayer(DNS):
            return 'DNS'
        elif packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        else:
            return 'Unknown'
    
    def extract_http_credentials(self, data: str) -> list:
        """Extract HTTP authentication credentials"""
        credentials = []
        
        # Basic Auth
        if 'Authorization: Basic' in data:
            import re
            auth_match = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', data)
            if auth_match:
                try:
                    encoded = auth_match.group(1)
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    credentials.append({
                        'type': 'basic_auth',
                        'data': decoded,
                        'encoded': encoded
                    })
                except:
                    pass
        
        # Form-based login
        form_patterns = [
            r'username=([^&\s]+)',
            r'user=([^&\s]+)',
            r'login=([^&\s]+)',
            r'password=([^&\s]+)',
            r'pass=([^&\s]+)',
            r'pwd=([^&\s]+)'
        ]
        
        for pattern in form_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            for match in matches:
                credentials.append({
                    'type': 'form_data',
                    'field': pattern.split('=')[0].replace('(', ''),
                    'value': match
                })
        
        return credentials
