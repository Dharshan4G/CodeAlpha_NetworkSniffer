# CodeAlpha — Task 1: Basic Network Sniffer

A Python packet sniffer that captures live network traffic and decodes it layer by layer
(Ethernet → IP/ARP → TCP/UDP/ICMP → payload).

## Features
- **Two capture backends**
  - `scapy` (default): cross-platform, supports BPF filters like `"tcp port 80"`
  - `socket`: raw sockets with manual header parsing using `struct`, to show how the bytes are laid out
- Shows source/destination IP and port, protocol, service guess (HTTP, DNS, SSH…), TCP flags, sequence/ack numbers, TTL and MAC addresses
- Hex + ASCII payload dump
- Filter by protocol, packet count or BPF expression
- Summary statistics when you stop the capture (protocol breakdown, top talkers)
- `--demo` mode that decodes a hand-built packet with no admin rights needed

## Installation
```bash
pip install -r requirements.txt
```
Windows users also need [Npcap](https://npcap.com) for scapy (tick "WinPcap API-compatible mode").

## Usage
Capturing requires root/Administrator.
```bash
python3 sniffer.py --demo                       # learn the packet structure, no root needed
sudo python3 sniffer.py                         # capture everything (scapy)
sudo python3 sniffer.py -b socket -v            # raw-socket backend, show MACs & TTL
sudo python3 sniffer.py -p tcp -c 20            # only 20 TCP packets
sudo python3 sniffer.py -f "udp port 53"        # DNS traffic only
sudo python3 sniffer.py -i eth0 --payload 128   # choose interface, bigger payload dump
```

| Option | Meaning |
|---|---|
| `-b, --backend` | `scapy` or `socket` |
| `-i, --iface` | network interface |
| `-c, --count` | stop after N packets |
| `-p, --proto` | show only `tcp`, `udp`, `icmp` or `arp` |
| `-f, --filter` | BPF filter (scapy only) |
| `--payload N` | bytes of payload to hexdump (0 hides it) |
| `-v` | show MAC addresses and TTL |

## Sample output
```
[   1] 23:32:17.067  UDP/DNS             192.0.2.2:48894 -> 8.8.8.8:53             len=71
       Payload (29 bytes):
      0000  7c 6b 01 00 00 01 00 00 00 00 00 00 07 65 78 61  |k...........exa
      0010  6d 70 6c 65 03 63 6f 6d 00 00 01 00 01           mple.com.....
[   3] 23:32:17.092  TCP/HTTP            192.0.2.2:41172 -> 104.20.23.154:80       len=74
       Flags=[SYN] Seq=2851001180 Ack=0 Win=65280
[   4] 23:32:17.093  TCP/HTTP           104.20.23.154:80 -> 192.0.2.2:41172        len=74
       Flags=[SYN,ACK] Seq=2157746199 Ack=2851001181 Win=43440
[   5] 23:32:17.093  TCP/HTTP            192.0.2.2:41172 -> 104.20.23.154:80       len=66
       Flags=[ACK] Seq=2851001181 Ack=2157746200 Win=128
```

## What I learned
- **Encapsulation:** every packet is nested headers. Bytes 0–13 are Ethernet, 14–33 IPv4, 34–53 TCP, and the rest is application data.
- **How a web request flows:** the DNS lookup over UDP/53 happens first, then the TCP three-way handshake (SYN → SYN/ACK → ACK), then the HTTP data.
- **TCP reliability:** each ACK number is the other side's sequence number + 1.
- **Encryption matters:** HTTP payloads are readable in plain text. HTTPS payloads are unreadable, but IPs and ports are still visible.

## Ethics
Only capture traffic on networks you own or are explicitly authorised to monitor.
