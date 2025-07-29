from scapy.packet import Raw
from scapy.all import *
from scapy.layers.inet import TCP, UDP
import re

def extract_payloads(packets):
    payloads = []

    for pkt in packets:
        if pkt.haslayer(Raw):
            try:
                raw_data = pkt[Raw].load.decode(errors="ignore")
                payloads.append((pkt.summary(), raw_data))
            except:
                continue
    return payloads

def search_patterns(payloads, regex):
    pattern = re.compile(regex)
    matches = []

    for i, (summary, data) in enumerate(payloads):
        found = pattern.findall(data)  # Correct: use only the string part
        if found:
            matches.append((i, summary, found))
    return matches

