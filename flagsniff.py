import re
import json
import argparse
from scapy.all import rdpcap
from rich.console import Console
from rich.table import Table

console = Console()

# Auto-expanded credential patterns
USER_KEYS = ["uname", "username", "login", "user", "email", "uemail", "mail", "id"]
PASS_KEYS = ["pass", "password", "pwd", "passwd"]

def build_cred_pattern():
    user_part = f"(?:{'|'.join(USER_KEYS)})=([^&\\s]+)"
    pass_part = f"(?:{'|'.join(PASS_KEYS)})=([^&\\s]+)"
    return f"{user_part}|{pass_part}"

# Default search patterns
PATTERNS = {
    "flag": r"flag{.*?}",
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "jwt": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "http_creds": build_cred_pattern()
}

def extract_payloads(packets):
    payloads = []
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer("Raw"):
            try:
                payload = pkt["Raw"].load.decode(errors="ignore")
                payloads.append((i, payload))
            except Exception:
                continue
    return payloads

def search_patterns(payloads):
    matches = []
    for pkt_num, payload in payloads:
        for label, pattern in PATTERNS.items():
            for match in re.findall(pattern, payload):
                if isinstance(match, tuple):
                    # Remove empty entries
                    filtered = [m for m in match if m]
                    for item in filtered:
                        matches.append({"packet": pkt_num, "match": f"{label}: {item}"})
                else:
                    matches.append({"packet": pkt_num, "match": f"{label}: {match}"})
    return matches

def save_results(results):
    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

def display_results(results):
    if not results:
        console.print("[red]No matches found.[/red]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Packet #")
    table.add_column("Match")

    for result in results:
        table.add_row(str(result["packet"]), result["match"])
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="FlagSniff - Extract secrets from .pcap files")
    parser.add_argument("-f", "--file", required=True, help="Path to .pcap file")
    args = parser.parse_args()

    packets = rdpcap(args.file)
    payloads = extract_payloads(packets)
    results = search_patterns(payloads)

    display_results(results)
    save_results(results)
    if results:
        console.print("[green]Results saved to results.json[/green]")

if __name__ == "__main__":
    main()
