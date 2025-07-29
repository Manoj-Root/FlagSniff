import re
import json
import csv
import argparse
from scapy.all import rdpcap
from rich.console import Console
from rich.table import Table
from rich import print

console = Console()

# Default built-in regex patterns
BUILTIN_PATTERNS = {
    "flag": r"flag{.*?}",
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "jwt": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "credentials": r"(?:uname|username|user)=([^&\s]+)|(?:pass|password)=([^&\s]+)",
    "token": r"(token|apikey|api_key|secret)[\"'=:\s]+([a-zA-Z0-9_\-]{10,})"
}


def extract_payloads(packets):
    payloads = []
    for i, pkt in enumerate(packets, start=1):
        if pkt.haslayer("Raw"):
            try:
                payload = bytes(pkt["Raw"].load).decode(errors="ignore")
                payloads.append((i, payload))
            except Exception:
                continue
    return payloads


def search_patterns(payloads, patterns):
    matches = []
    for pkt_num, payload in payloads:
        for label, pattern in patterns.items():
            for match in re.findall(pattern, payload):
                if isinstance(match, tuple):
                    match = [m for m in match if m]
                    for m in match:
                        matches.append({"packet": pkt_num, "type": label, "match": m})
                else:
                    matches.append({"packet": pkt_num, "type": label, "match": match})
    return matches


def save_json(results, path="results.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=4)


def save_csv(results, path="results.csv"):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["packet", "type", "match"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def display_results(results):
    if not results:
        console.print("[bold red]No matches found.[/bold red]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Packet #", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Match", style="yellow")

    for result in results:
        table.add_row(str(result["packet"]), result["type"], result["match"])
    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="FlagSniff - Extract flags, creds, and tokens from .pcap files")
    parser.add_argument("-f", "--file", required=True, help="Path to .pcap or .pcapng file")
    parser.add_argument("--auto", action="store_true", help="Use built-in patterns automatically")
    parser.add_argument("--regex", help="Custom regex pattern")
    parser.add_argument("--output", default="results.json", help="Output file name")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    args = parser.parse_args()

    packets = rdpcap(args.file)
    payloads = extract_payloads(packets)

    if args.regex:
        patterns = {"custom": args.regex}
    elif args.auto:
        patterns = BUILTIN_PATTERNS
    else:
        console.print("[red]Error: Please use --regex or --auto to scan for data.[/red]")
        return

    results = search_patterns(payloads, patterns)

    display_results(results)

    if args.format == "json":
        save_json(results, args.output)
    elif args.format == "csv":
        save_csv(results, args.output)

    if results:
        console.print(f"[bold green]Results saved to [white]{args.output}[/white][/bold green]")


if __name__ == "__main__":
    main()
