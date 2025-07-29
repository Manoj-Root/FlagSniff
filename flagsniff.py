#!/usr/bin/env python3
"""
FlagSniff - CLI Tool for Red Teaming & CTF Practice
Offline packet analysis + flag extraction from .pcap files
"""

import argparse
import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("📦 Install with: pip install scapy rich")
    sys.exit(1)

from utils.parsers import PacketParser
from utils.patterns import PatternMatcher

console = Console()

class FlagSniff:
    """Main FlagSniff CLI tool class"""
    
    def __init__(self):
        self.console = Console()
        self.found_items = []
        self.stats = {
            'total_packets': 0,
            'analyzed_packets': 0,
            'flags_found': 0,
            'credentials_found': 0,
            'tokens_found': 0
        }
    
    def load_pcap(self, filepath: str) -> Optional[List]:
        """Load and return packets from .pcap file"""
        try:
            self.console.print(f"📁 Loading PCAP file: {filepath}", style="cyan")
            packets = rdpcap(filepath)
            self.stats['total_packets'] = len(packets)
            self.console.print(f"✅ Loaded {len(packets)} packets", style="green")
            return packets
        except Exception as e:
            self.console.print(f"❌ Error loading PCAP: {e}", style="red")
            return None
    
    def analyze_packets(self, packets: List, search_patterns: List[str], custom_regex: str = None):
        """Analyze packets for flags, credentials, and sensitive data"""
        parser = PacketParser()
        matcher = PatternMatcher()
        
        with console.status("[bold green]Analyzing packets...") as status:
            for i, packet in enumerate(packets):
                status.update(f"[bold green]Analyzing packet {i+1}/{len(packets)}")
                
                # Parse packet data
                packet_data = parser.extract_data(packet)
                if not packet_data:
                    continue
                
                self.stats['analyzed_packets'] += 1
                
                # Search for patterns
                results = matcher.search_patterns(packet_data, search_patterns, custom_regex)
                
                if results:
                    self.found_items.extend(results)
                    self._update_stats(results)
    
    def _update_stats(self, results: List[Dict]):
        """Update statistics based on found results"""
        for result in results:
            if result['type'] == 'flag':
                self.stats['flags_found'] += 1
            elif result['type'] == 'credential':
                self.stats['credentials_found'] += 1
            elif result['type'] == 'token':
                self.stats['tokens_found'] += 1
    
    def display_results(self):
        """Display found results in a formatted table"""
        if not self.found_items:
            self.console.print("❌ No matches found!", style="yellow")
            return
        
        # Create results table
        table = Table(title="🎯 FlagSniff Results", show_header=True, header_style="bold magenta")
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Protocol", style="green", width=10)
        table.add_column("Source", style="blue", width=15)
        table.add_column("Destination", style="blue", width=15)
        table.add_column("Found Data", style="yellow", width=50)
        
        for item in self.found_items:
            # Highlight sensitive data in red
            found_text = Text(item['data'][:100] + "..." if len(item['data']) > 100 else item['data'])
            found_text.stylize("bold red")
            
            table.add_row(
                item['type'].upper(),
                item['protocol'],
                item['src'],
                item['dst'],
                found_text
            )
        
        self.console.print(table)
        
        # Display statistics
        stats_panel = Panel(
            f"📊 **Analysis Statistics**\n\n"
            f"Total Packets: {self.stats['total_packets']}\n"
            f"Analyzed Packets: {self.stats['analyzed_packets']}\n"
            f"🚩 Flags Found: {self.stats['flags_found']}\n"
            f"🔐 Credentials Found: {self.stats['credentials_found']}\n"
            f"🎫 Tokens Found: {self.stats['tokens_found']}",
            title="Statistics",
            border_style="green"
        )
        self.console.print(stats_panel)
    
    def export_results(self, output_file: str, format_type: str = 'json'):
        """Export results to file"""
        if not self.found_items:
            self.console.print("❌ No results to export!", style="yellow")
            return
        
        try:
            if format_type.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump({
                        'stats': self.stats,
                        'results': self.found_items
                    }, f, indent=2)
            
            self.console.print(f"✅ Results exported to: {output_file}", style="green")
        except Exception as e:
            self.console.print(f"❌ Export failed: {e}", style="red")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="🎯 FlagSniff - CLI Tool for Packet Analysis & Flag Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python flagsniff.py -f capture.pcap --find flag
  python flagsniff.py -f capture.pcap --find all --regex "flag\\{.*?\\}"
  python flagsniff.py -f capture.pcap --find credentials --export results.json
        """
    )
    
    parser.add_argument('-f', '--file', required=True, help='Path to .pcap file')
    parser.add_argument('--find', choices=['flag', 'credentials', 'tokens', 'all'], 
                       default='all', help='What to search for')
    parser.add_argument('--regex', help='Custom regex pattern to search')
    parser.add_argument('--export', help='Export results to file (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate file exists
    if not Path(args.file).exists():
        print(f"❌ File not found: {args.file}")
        sys.exit(1)
    
    # Initialize FlagSniff
    flagsniff = FlagSniff()
    
    # Display banner
    banner = Panel(
        "🎯 **FlagSniff v1.0**\n"
        "CLI Tool for Red Teaming & CTF Practice\n"
        "Packet Analysis + Flag Extraction",
        title="FlagSniff",
        border_style="blue"
    )
    console.print(banner)
    
    # Load packets
    packets = flagsniff.load_pcap(args.file)
    if not packets:
        sys.exit(1)
    
    # Determine search patterns
    search_patterns = []
    if args.find in ['flag', 'all']:
        search_patterns.append('flag')
    if args.find in ['credentials', 'all']:
        search_patterns.append('credentials')
    if args.find in ['tokens', 'all']:
        search_patterns.append('tokens')
    
    # Analyze packets
    flagsniff.analyze_packets(packets, search_patterns, args.regex)
    
    # Display results
    flagsniff.display_results()
    
    # Export if requested
    if args.export:
        flagsniff.export_results(args.export)

if __name__ == "__main__":
    main()
