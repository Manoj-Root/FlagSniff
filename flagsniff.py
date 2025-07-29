from scapy.all import rdpcap
from rich.console import Console
from utils.parsers import extract_payloads, search_patterns
import argparse
import json
import sys

console = Console()

# Predefined pattern dictionary
predefined_patterns = {
    "flag": r"flag{.*?}",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "jwt": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
}

def display_matches(matches):
    for index, payload, found in matches:
        for match in found:
            console.print(f"[green]Packet #{index}[/green]: [yellow]{match}[/yellow]")

def save_results(matches, output_file="results.json"):
    output = []
    for index, payload, found in matches:
        for match in found:
            output.append({"packet": index, "match": match})
    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)
    console.print(f"[bold cyan]Results saved to {output_file}[/bold cyan]")

def main():
    parser = argparse.ArgumentParser(description="FlagSniff - Extract flags & secrets from .pcap files")
    parser.add_argument("-f", "--file", help="Path to .pcap file", required=True)
    parser.add_argument("--regex", help="Custom regex pattern to search (overrides --patterns)", default=None)
    parser.add_argument("--patterns", nargs="+", choices=list(predefined_patterns.keys()),
                        help="One or more predefined patterns to search (e.g., flag email jwt)")

    # Show help if no arguments are passed
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    packets = rdpcap(args.file)
    payloads = extract_payloads(packets)

    # Determine which patterns to apply
    if args.regex:
        matches = search_patterns(payloads, args.regex)
    elif args.patterns:
        matches = []
        for pattern_name in args.patterns:
            regex = predefined_patterns[pattern_name]
            found = search_patterns(payloads, regex)
            matches.extend(found)
    else:
        # Default to flag pattern
        matches = search_patterns(payloads, predefined_patterns["flag"])

    if matches:
        display_matches(matches)
        save_results(matches)
    else:
        console.print("[bold red]No matches found.[/bold red]")

if __name__ == "__main__":
    main()
