#  Network Scanner

A simple yet powerful Python-based network scanner that performs **ARP-based host discovery** and **TCP connect port scanning**. Useful for identifying active hosts on a local subnet and determining open ports on those hosts.

---

##  Overview

This script helps network administrators and cybersecurity enthusiasts scan a network for live hosts and discover open TCP ports. It uses ARP requests for host discovery and Python’s socket module for TCP port scanning.

---

##  Requirements

- **Python 3.x** – The script is built for Python 3.
- **Scapy** – For crafting and sending ARP packets.
- **Admin/Root Privileges** – Required for ARP scanning on most systems.
- **Npcap (Windows only)** – Needed for Scapy to work on Windows.

---

##  Features

-  Host Discovery (ARP Scan):
  - Scans a target IP or CIDR subnet (e.g., `192.168.1.0/24`)
  - Displays IP and MAC addresses of active devices

-  Port Scanning (TCP Connect):
  - Scan individual ports (e.g., `80,443`) or port ranges (e.g., `1-1024`)
  - Reports open TCP ports on discovered hosts

-  User-Friendly Interface:
  - Uses `argparse` for clean CLI argument parsing
  - Clear, structured output

-  Robust Error Handling:
  - Validates IP/subnet input format
  - Handles host resolution and socket errors gracefully

---

##  Installation

### 1. Install Python 3
Download and install from [python.org](https://www.python.org/downloads/)

### 2. Install required Python packages
```bash
pip install scapy
````

### 3. Windows Users: Install Npcap

* Download: [nmap.org/npcap/](https://nmap.org/npcap/)
* During installation, optionally enable:

  *  “Support Npcap in WinPcap API Compatibility Mode”
* Restart your system after installation.

### 4. Save the Script

Save the Python script as:

```bash
network_scanner.py
```

---

##  Usage

The script must be run with **administrator/root privileges** for full functionality.

###  General Syntax

```bash
# Linux/macOS
sudo python3 network_scanner.py -t <target> [-p <ports>]

# Windows (Run from Admin PowerShell or Command Prompt)
python network_scanner.py -t <target> [-p <ports>]
```

---

## ⚙ Options

| Option           | Description                                                            |
| ---------------- | ---------------------------------------------------------------------- |
| `-t`, `--target` | **(Required)** Target IP, hostname, or subnet (e.g., `192.168.1.0/24`) |
| `-p`, `--ports`  | **(Optional)** Ports to scan (e.g., `22,80,443` or `1-1024`)           |

>  If `--ports` is not provided, only ARP-based host discovery will be performed.

---

##  Examples

###  Discover all hosts in your subnet

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24
```

###  Discover hosts + Scan specific ports

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -p 22,80,443,3389
```

###  Discover hosts + Scan common ports

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -p 1-1024
```

###  Scan ports on a specific external host

*(Note: ARP discovery won’t work on external IPs/domains)*

```bash
python3 network_scanner.py -t example.com -p 80,443
```

---

##  Contributors

* A. Mohamed yousuf imran (Leader)
* M. Ganeshan
* S. Shyam
