"""
Pattern matching utilities for FlagSniff
Contains regex patterns and matching logic
"""

import re
from typing import List, Dict, Any

class PatternMatcher:
    """Handles pattern matching for flags, credentials, and sensitive data"""
    
    def __init__(self):
        # Predefined regex patterns
        self.patterns = {
            'flag': [
                r'flag\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'HTB\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'htb\{[^}]+\}',
                r'DUCTF\{[^}]+\}',
                r'PICOCTF\{[^}]+\}',
                r'flag:\s*[a-zA-Z0-9_\-!@#$%^&*()]+',
            ],
            'credentials': [
                r'username[:\s=]+([^\s\r\n&]+)',
                r'user[:\s=]+([^\s\r\n&]+)',
                r'login[:\s=]+([^\s\r\n&]+)',
                r'password[:\s=]+([^\s\r\n&]+)',
                r'pass[:\s=]+([^\s\r\n&]+)',
                r'pwd[:\s=]+([^\s\r\n&]+)',
                r'Authorization: Basic ([A-Za-z0-9+/=]+)',
                r'admin[:\s=]+([^\s\r\n&]+)',
                r'root[:\s=]+([^\s\r\n&]+)',
            ],
            'tokens': [
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',  # JWT
                r'(?i)apikey[\s:=]+[A-Za-z0-9]{16,}',
                r'(?i)api_key[\s:=]+[A-Za-z0-9]{16,}',
                r'(?i)access_token[\s:=]+[A-Za-z0-9]{16,}',
                r'(?i)bearer\s+[A-Za-z0-9\-_]{20,}',
                r'sk-[a-zA-Z0-9]{40,}',  # OpenAI API keys
                r'xox[baprs]-[a-zA-Z0-9-]{10,}',  # Slack tokens
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
            ],
            'emails': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            'ips': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            ],
            'urls': [
                r'https?://[^\s<>"{}|\\^`\[\]]+',
            ],
            'hashes': [
                r'\b[a-fA-F0-9]{32}\b',  # MD5
                r'\b[a-fA-F0-9]{40}\b',  # SHA1
                r'\b[a-fA-F0-9]{64}\b',  # SHA256
            ]
        }
    
    def search_patterns(self, packet_data: Dict[str, Any], search_types: List[str], custom_regex: str = None) -> List[Dict]:
        """Search for patterns in packet data"""
        results = []
        data_to_search = packet_data.get('data', '')
        
        if not data_to_search:
            return results
        
        # Search predefined patterns
        for search_type in search_types:
            if search_type in self.patterns:
                for pattern in self.patterns[search_type]:
                    matches = re.finditer(pattern, data_to_search, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        results.append({
                            'type': search_type,
                            'pattern': pattern,
                            'data': match.group(0),
                            'position': match.span(),
                            'protocol': packet_data.get('protocol', 'Unknown'),
                            'src': packet_data.get('src', ''),
                            'dst': packet_data.get('dst', ''),
                            'context': self._get_context(data_to_search, match.span(), 50)
                        })
        
        # Search custom regex
        if custom_regex:
            try:
                matches = re.finditer(custom_regex, data_to_search, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    results.append({
                        'type': 'custom',
                        'pattern': custom_regex,
                        'data': match.group(0),
                        'position': match.span(),
                        'protocol': packet_data.get('protocol', 'Unknown'),
                        'src': packet_data.get('src', ''),
                        'dst': packet_data.get('dst', ''),
                        'context': self._get_context(data_to_search, match.span(), 50)
                    })
            except re.error as e:
                print(f"❌ Invalid regex pattern: {e}")
        
        return results
    
    def _get_context(self, text: str, span: tuple, context_size: int = 50) -> str:
        """Get context around matched text"""
        start, end = span
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        
        context = text[context_start:context_end]
        
        # Add ellipsis if truncated
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
        
        return context
    
    def add_custom_pattern(self, pattern_type: str, regex: str):
        """Add a custom pattern to the matcher"""
        if pattern_type not in self.patterns:
            self.patterns[pattern_type] = []
        self.patterns[pattern_type].append(regex)
    
    def get_pattern_info(self) -> Dict[str, List[str]]:
        """Get information about all available patterns"""
        return self.patterns.copy()
