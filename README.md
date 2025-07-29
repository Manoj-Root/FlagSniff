# 🎯 FlagSniff - CLI Tool for Red Teaming & CTF Practice

**FlagSniff** is a powerful command-line tool designed for red teamers and CTF players to quickly analyze `.pcap` files and extract flags, credentials, tokens, and other sensitive information.

## 🚀 Features

### ✅ Core Features (v1.0)
- **📁 PCAP & PCAPNG File Analysis**: Load and parse `.pcap or .pcapng` files using Scapy
- **🔍 Multi-Protocol Support**: HTTP, DNS, FTP, Telnet, TCP, UDP
- **🚩 Flag Detection**: Automatically find CTF flags with patterns like `flag{}`, `CTF{}`, `HTB{}`
- **🔐 Credential Extraction**: Detect Basic Auth, form-based logins, passwords
- **🎫 Token Recognition**: JWT tokens, API keys, Bearer tokens, AWS keys
- **🎨 Colorized Output**: Beautiful terminal output using Rich
- **📊 Statistics**: Detailed analysis statistics
- **💾 Export Results**: Save findings to JSON format
- **🔧 Custom Regex**: Use your own regex patterns for specific searches

### 🛠 Supported Pattern Types
- **Flags**: `flag{}`, `CTF{}`, `HTB{}`, `DUCTF{}`, `PICOCTF{}`
- **Credentials**: usernames, passwords, Basic Auth
- **Tokens**: JWT, API keys, Bearer tokens, Slack tokens, AWS keys
- **Emails**: Standard email format detection
- **Hashes**: MD5, SHA1, SHA256
- **URLs**: HTTP/HTTPS links

## 📦 Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

**Required packages:**
- `scapy` - Packet parsing and analysis
- `rich` - Beautiful terminal output

## 🧪 Usage

### Basic Commands

**1. Find all flags in a PCAP file:**
```bash
python flagsniff.py -f capture.pcap --find flag
```

**2. Search for credentials:**
```bash
python flagsniff.py -f capture.pcap --find credentials
```

**3. Find everything (flags, credentials, tokens):**
```bash
python flagsniff.py -f capture.pcap --find all
```

**4. Use custom regex pattern:**
```bash
python flagsniff.py -f capture.pcap --find all --regex "flag\\{.*?\\}"
```

**5. Export results to JSON:**
```bash
python flagsniff.py -f capture.pcap --find all --export results.json
```

**6. Verbose output:**
```bash
python flagsniff.py -f capture.pcap --find all --verbose
```

### Command Line Arguments

```
usage: flagsniff.py [-h] -f FILE [--find {flag,credentials,tokens,all}] 
                    [--regex REGEX] [--export EXPORT] [--verbose]

🎯 FlagSniff - CLI Tool for Packet Analysis & Flag Extraction

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to .pcap file
  --find {flag,credentials,tokens,all}
                        What to search for (default: all)
  --regex REGEX         Custom regex pattern to search
  --export EXPORT       Export results to file (JSON format)
  --verbose, -v         Verbose output
```

## 📊 Output Example

```
📁 Loading PCAP file: sample.pcap
✅ Loaded 1500 packets

🎯 FlagSniff Results
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type       ┃ Protocol ┃ Source        ┃ Destination   ┃ Found Data                                        ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ FLAG       │ HTTP     │ 192.168.1.10  │ 192.168.1.1   │ flag{h3ll0_w0rld_fr0m_p4ck3t5}                   │
│ CREDENTIAL │ HTTP     │ 192.168.1.20  │ 192.168.1.1   │ username=admin&password=secret123                │
│ TOKEN      │ HTTP     │ 192.168.1.30  │ 192.168.1.1   │ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...         │
└────────────┴──────────┴───────────────┴───────────────┴───────────────────────────────────────────────────┘

┌─ Statistics ─┐
│ 📊 Analysis Statistics │
│                        │
│ Total Packets: 1500    │
│ Analyzed Packets: 847  │
│ 🚩 Flags Found: 3      │
│ 🔐 Credentials Found: 7│
│ 🎫 Tokens Found: 2     │
└────────────────────────┘
```

## 🗂 Project Structure

```
flagsniff/
├── flagsniff.py           # Main CLI tool
├── utils/
│   ├── __init__.py        # Package initialization
│   ├── parsers.py         # Packet parsing utilities
│   └── patterns.py        # Pattern matching & regex
├── test_data/
│   └── sample.pcap        # Sample PCAP for testing
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🧰 Technical Details

### Architecture
- **Scapy**: Handles PCAP file loading and packet parsing
- **Rich**: Provides colorized terminal output and tables
- **Modular Design**: Separate utilities for parsing and pattern matching

### Supported Protocols
- **HTTP**: Web traffic, form data, headers
- **DNS**: Query/response analysis
- **FTP**: File transfer protocol
- **Telnet**: Remote terminal sessions
- **TCP/UDP**: General packet analysis

### Pattern Recognition
The tool uses carefully crafted regex patterns to identify:
- **CTF Flags**: Various flag formats from different competitions
- **Authentication**: Basic Auth, form-based, API keys
- **Tokens**: JWT, Bearer, API keys, cloud service tokens
- **Sensitive Data**: Emails, hashes, URLs

## 🔧 Advanced Usage

### Custom Patterns
You can create custom regex patterns for specific needs:

```bash
# Search for Bitcoin addresses
python flagsniff.py -f capture.pcap --regex "[13][a-km-zA-HJ-NP-Z1-9]{25,34}"

# Find specific flag formats
python flagsniff.py -f capture.pcap --regex "MYCTF\\{[a-zA-Z0-9_]+\\}"
```

### Programmatic Usage
```python
from flagsniff import FlagSniff

# Initialize
fs = FlagSniff()

# Load packets
packets = fs.load_pcap("capture.pcap")

# Analyze
fs.analyze_packets(packets, ['flag', 'credentials'])

# Get results
results = fs.found_items
```

## 🚀 Future Features (v2.0+)

- **🌐 Web Dashboard**: Visual traffic flow and analysis
- **📈 Advanced Statistics**: Detailed protocol breakdowns
- **🔄 Real-time Analysis**: Live packet capture analysis
- **📊 CSV Export**: Multiple export formats
- **🎮 Gaming Mode**: CTF scoring system
- **🔍 Deep Inspection**: SSL/TLS analysis, encrypted content
- **📱 Mobile App**: Companion mobile application

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

**FlagSniff** is designed for educational purposes, authorized penetration testing, and CTF competitions. Always ensure you have proper authorization before analyzing network traffic. The authors are not responsible for any misuse of this tool.

## 🏆 Credits

Created for the red teaming and CTF community. Special thanks to:
- Scapy developers for the powerful packet analysis library
- Rich library for beautiful terminal interfaces
- The CTF community for inspiration and feedback

---

**Happy Flag Hunting! 🚩**
