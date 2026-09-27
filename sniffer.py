#!/usr/bin/env python3
"""
Basic Network Sniffer
=====================
Captures packets on your machine and decodes them layer by layer:

    Ethernet (L2)  ->  IPv4 / ARP (L3)  ->  TCP / UDP / ICMP (L4)  ->  Payload (L7)

Two capture backends are included so you can see both approaches:
  * scapy  : high-level library, cross-platform, supports BPF filters
  * socket : raw sockets + manual header parsing with `struct` (no dependencies),
             the best way to learn what the bytes on the wire actually look like

Usage (capturing requires admin/root privileges):
    sudo python3 sniffer.py                          # scapy backend, all traffic
    sudo python3 sniffer.py -b socket                # raw-socket backend
    sudo python3 sniffer.py -p tcp -c 20             # only 20 TCP packets
    sudo python3 sniffer.py -f "port 53" -i eth0     # BPF filter (scapy only)
    python3 sniffer.py --demo                        # decode a sample packet, no root needed

Only capture traffic on networks you own or are authorised to monitor.
"""

import argparse
import platform
import socket
import struct
import sys
from collections import Counter
from datetime import datetime

# --------------------------------------------------------------------------- #
# Lookup tables
# --------------------------------------------------------------------------- #
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

ETHER_TYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS", 8080: "HTTP-ALT",
}

ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded"}

TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
             (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]

# ANSI colours (disabled automatically if output isn't a terminal)
USE_COLOR = sys.stdout.isatty()
COLORS = {"TCP": "\033[94m", "UDP": "\033[92m", "ICMP": "\033[93m",
          "ARP": "\033[95m", "OTHER": "\033[90m"}
RESET = "\033[0m"


def color(text, proto):
    if not USE_COLOR:
        return text
    return f"{COLORS.get(proto, COLORS['OTHER'])}{text}{RESET}"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def tcp_flag_str(flags: int) -> str:
    return ",".join(name for bit, name in TCP_FLAGS if flags & bit) or "-"


def service_name(sport, dport):
    """Guess the application protocol from the port numbers."""
    for port in (dport, sport):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return None


def hexdump(data: bytes, limit: int) -> str:
    """Classic hex + ASCII view, 16 bytes per row."""
    data = data[:limit]
    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"      {off:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(rows)


# --------------------------------------------------------------------------- #
# Manual header parsers (used by the raw-socket backend)
# Each returns the decoded fields plus the remaining bytes for the next layer.
# --------------------------------------------------------------------------- #
def parse_ethernet(data):
    # 6 bytes dst MAC | 6 bytes src MAC | 2 bytes EtherType
    dst, src, eth_type = struct.unpack("!6s6sH", data[:14])
    return {"dst_mac": mac_str(dst), "src_mac": mac_str(src),
            "eth_type": eth_type}, data[14:]


def parse_ipv4(data):
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4          # header length in bytes
    tos, total_len, ident, frag, ttl, proto, checksum, src, dst = \
        struct.unpack("!xBHHHBBH4s4s", data[:20])
    return {"version": version_ihl >> 4, "ihl": ihl, "ttl": ttl,
            "proto": proto, "total_len": total_len,
            "src": socket.inet_ntoa(src), "dst": socket.inet_ntoa(dst)}, data[ihl:total_len or None]


def parse_tcp(data):
    sport, dport, seq, ack, off_flags, window = struct.unpack("!HHLLHH", data[:16])
    offset = (off_flags >> 12) * 4
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack,
            "flags": off_flags & 0x1FF, "window": window}, data[offset:]


def parse_udp(data):
    sport, dport, length, checksum = struct.unpack("!HHHH", data[:8])
    return {"sport": sport, "dport": dport, "length": length}, data[8:]


def parse_icmp(data):
    icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
    return {"type": icmp_type, "code": code}, data[4:]


def parse_arp(data):
    op = struct.unpack("!H", data[6:8])[0]
    sender_ip = socket.inet_ntoa(data[14:18])
    target_ip = socket.inet_ntoa(data[24:28])
    return {"op": op, "src": sender_ip, "dst": target_ip,
            "sender_mac": mac_str(data[8:14])}


def decode_ip_packet(ip_bytes, record):
    """Decode an IPv4 packet (and its transport layer) into `record`."""
    ip, rest = parse_ipv4(ip_bytes)
    record.update(src=ip["src"], dst=ip["dst"], ttl=ip["ttl"],
                  proto=IP_PROTOCOLS.get(ip["proto"], f"IP-{ip['proto']}"))

    if ip["proto"] == 6 and len(rest) >= 20:
        tcp, payload = parse_tcp(rest)
        record.update(sport=tcp["sport"], dport=tcp["dport"], payload=payload,
                      info=f"Flags=[{tcp_flag_str(tcp['flags'])}] "
                           f"Seq={tcp['seq']} Ack={tcp['ack']} Win={tcp['window']}")
    elif ip["proto"] == 17 and len(rest) >= 8:
        udp, payload = parse_udp(rest)
        record.update(sport=udp["sport"], dport=udp["dport"], payload=payload,
                      info=f"Len={udp['length']}")
    elif ip["proto"] == 1 and len(rest) >= 4:
        icmp, payload = parse_icmp(rest)
        record.update(payload=payload,
                      info=f"{ICMP_TYPES.get(icmp['type'], 'Type ' + str(icmp['type']))}"
                           f" (code {icmp['code']})")
    else:
        record["payload"] = rest
    return record


def decode_raw_frame(frame, has_ethernet=True):
    """Turn raw bytes from a socket into a normalised record dict."""
    record = new_record(len(frame))
    if not has_ethernet:                      # Windows raw sockets start at IP
        return decode_ip_packet(frame, record)

    eth, rest = parse_ethernet(frame)
    record.update(src_mac=eth["src_mac"], dst_mac=eth["dst_mac"])

    if eth["eth_type"] == 0x0800:
        return decode_ip_packet(rest, record)
    if eth["eth_type"] == 0x0806 and len(rest) >= 28:
        arp = parse_arp(rest)
        record.update(proto="ARP", src=arp["src"], dst=arp["dst"],
                      info=("who-has " + arp["dst"] + " tell " + arp["src"])
                      if arp["op"] == 1 else f"{arp['src']} is-at {arp['sender_mac']}")
        return record
    record["proto"] = ETHER_TYPES.get(eth["eth_type"], hex(eth["eth_type"]))
    return record


# --------------------------------------------------------------------------- #
# Record + display
# --------------------------------------------------------------------------- #
def new_record(length):
    return {"time": datetime.now().strftime("%H:%M:%S.%f")[:-3], "length": length,
            "src": "?", "dst": "?", "proto": "OTHER", "sport": None,
            "dport": None, "ttl": None, "info": "", "payload": b"",
            "src_mac": None, "dst_mac": None}


class Sniffer:
    def __init__(self, args):
        self.args = args
        self.count = 0
        self.protocols = Counter()
        self.talkers = Counter()
        self.total_bytes = 0

    def handle(self, rec):
        if self.args.proto and rec["proto"].lower() != self.args.proto:
            return
        self.count += 1
        self.protocols[rec["proto"]] += 1
        self.talkers[rec["src"]] += 1
        self.total_bytes += rec["length"]
        self.display(rec)

    def display(self, r):
        proto = r["proto"]
        src = f"{r['src']}:{r['sport']}" if r["sport"] is not None else r["src"]
        dst = f"{r['dst']}:{r['dport']}" if r["dport"] is not None else r["dst"]
        svc = service_name(r["sport"], r["dport"])
        label = f"{proto}/{svc}" if svc else proto

        print(color(f"[{self.count:>4}] {r['time']}  {label:<12} "
                    f"{src:>22} -> {dst:<22} len={r['length']}", proto))
        if self.args.verbose and r["src_mac"]:
            print(f"       MAC {r['src_mac']} -> {r['dst_mac']}"
                  + (f"   TTL={r['ttl']}" if r["ttl"] else ""))
        if r["info"]:
            print(f"       {r['info']}")
        if r["payload"] and self.args.payload > 0:
            print(f"       Payload ({len(r['payload'])} bytes):")
            print(hexdump(r["payload"], self.args.payload))

    def summary(self):
        print("\n" + "=" * 60)
        print(f" Captured {self.count} packets, {self.total_bytes} bytes")
        print("=" * 60)
        print(" Protocol breakdown:")
        for proto, n in self.protocols.most_common():
            pct = 100 * n / self.count if self.count else 0
            print(f"   {proto:<8} {n:>6}  {'#' * int(pct / 2)} {pct:.1f}%")
        print(" Top sources:")
        for ip, n in self.talkers.most_common(5):
            print(f"   {ip:<18} {n:>6} packets")

    # ---------------- backend 1: scapy ---------------- #
    def run_scapy(self):
        try:
            from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw
        except ImportError:
            sys.exit("scapy is not installed. Run: pip install scapy "
                     "(or use --backend socket)")

        def convert(pkt):
            rec = new_record(len(pkt))
            if Ether in pkt:
                rec.update(src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst)
            if ARP in pkt:
                a = pkt[ARP]
                rec.update(proto="ARP", src=a.psrc, dst=a.pdst,
                           info=f"who-has {a.pdst} tell {a.psrc}" if a.op == 1
                           else f"{a.psrc} is-at {a.hwsrc}")
            elif IP in pkt:
                ip = pkt[IP]
                rec.update(src=ip.src, dst=ip.dst, ttl=ip.ttl,
                           proto=IP_PROTOCOLS.get(ip.proto, f"IP-{ip.proto}"))
                if TCP in pkt:
                    t = pkt[TCP]
                    rec.update(sport=t.sport, dport=t.dport,
                               info=f"Flags=[{tcp_flag_str(int(t.flags))}] "
                                    f"Seq={t.seq} Ack={t.ack} Win={t.window}")
                elif UDP in pkt:
                    rec.update(sport=pkt[UDP].sport, dport=pkt[UDP].dport,
                               info=f"Len={pkt[UDP].len}")
                elif ICMP in pkt:
                    ic = pkt[ICMP]
                    rec["info"] = (f"{ICMP_TYPES.get(ic.type, 'Type ' + str(ic.type))}"
                                   f" (code {ic.code})")
            else:
                rec["proto"] = pkt.lastlayer().name
            if Raw in pkt:
                rec["payload"] = bytes(pkt[Raw].load)
            self.handle(rec)

        sniff(iface=self.args.iface, filter=self.args.filter, prn=convert,
              store=False,
              stop_filter=lambda _: bool(self.args.count) and self.count >= self.args.count)

    # ---------------- backend 2: raw sockets ---------------- #
    def run_socket(self):
        system = platform.system()
        if system == "Linux":
            # AF_PACKET gives full Ethernet frames; ntohs(3) = ETH_P_ALL
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.args.iface:
                sock.bind((self.args.iface, 0))
            has_eth = True
        elif system == "Windows":
            host = socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)   # promiscuous mode
            has_eth = False
        else:
            sys.exit("Raw-socket backend supports Linux and Windows. "
                     "On macOS use --backend scapy.")

        try:
            while not self.args.count or self.count < self.args.count:
                frame, _ = sock.recvfrom(65535)
                try:
                    self.handle(decode_raw_frame(frame, has_eth))
                except (struct.error, OSError, IndexError):
                    continue          # truncated/unusual packet: skip it
        finally:
            if system == "Windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()


# --------------------------------------------------------------------------- #
# Demo: decode a hand-built packet so you can study the structure without root
# --------------------------------------------------------------------------- #
def build_demo_frame():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tcp = struct.pack("!HHLLHHHH", 51514, 80, 1000, 0,
                      (5 << 12) | 0x18, 64240, 0, 0)          # PSH+ACK
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", (4 << 4) | 5, 0, total_len, 1, 0x4000,
                     64, 6, 0, socket.inet_aton("192.168.1.10"),
                     socket.inet_aton("93.184.216.34"))
    eth = struct.pack("!6s6sH", bytes.fromhex("aabbccddeeff"),
                      bytes.fromhex("112233445566"), 0x0800)
    return eth + ip + tcp + payload


def run_demo(sniffer):
    frame = build_demo_frame()
    print("Raw frame as it arrives from the network card:")
    print(hexdump(frame, len(frame)))
    print("\nLayer map: bytes 0-13 Ethernet | 14-33 IPv4 | 34-53 TCP | 54+ HTTP payload\n")
    sniffer.args.verbose = True
    sniffer.handle(decode_raw_frame(frame))


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Basic network packet sniffer")
    ap.add_argument("-b", "--backend", choices=["scapy", "socket"], default="scapy")
    ap.add_argument("-i", "--iface", help="interface to listen on (default: all/auto)")
    ap.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    ap.add_argument("-p", "--proto", choices=["tcp", "udp", "icmp", "arp"],
                    help="show only this protocol")
    ap.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 80" (scapy only)')
    ap.add_argument("--payload", type=int, default=64,
                    help="bytes of payload to hexdump (0 to hide)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show MACs and TTL")
    ap.add_argument("--demo", action="store_true", help="decode a sample packet and exit")
    args = ap.parse_args()

    sniffer = Sniffer(args)
    if args.demo:
        run_demo(sniffer)
        return

    print(f"[*] Sniffing with {args.backend} backend... press Ctrl+C to stop\n")
    try:
        if args.backend == "scapy":
            sniffer.run_scapy()
        else:
            sniffer.run_socket()
    except PermissionError:
        sys.exit("Permission denied: run with sudo (Linux/macOS) or as Administrator (Windows).")
    except KeyboardInterrupt:
        pass
    sniffer.summary()


if __name__ == "__main__":
    main()
