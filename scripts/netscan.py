#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Scan the local network for live hosts and, optionally, open ports.

Usage:
    uv run scripts/netscan.py                    # scan the /24 this machine is on
    uv run scripts/netscan.py 192.168.1.0/24     # scan a specific network
    uv run scripts/netscan.py --ports            # also check common ports
    uv run scripts/netscan.py --ports 22,8000-8100
"""

import argparse
import ipaddress
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    139: "netbios",
    443: "https",
    445: "smb",
    548: "afp",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    3000: "http-dev",
    3389: "rdp",
    5000: "upnp",
    5900: "vnc",
    8080: "http-alt",
    8443: "https-alt",
    9100: "printer",
    32400: "plex",
    62078: "iphone-sync",
}

MAX_HOSTS = 4096

ARP_LINE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)")
NEIGH_LINE = re.compile(r"^(\d+\.\d+\.\d+\.\d+) .*lladdr ([0-9a-fA-F:]+)")


@dataclass
class Host:
    ip: ipaddress.IPv4Address
    mac: str = ""
    hostname: str = ""
    ports: list[int] = field(default_factory=list)


def get_local_ip() -> str:
    # Connecting a UDP socket sends no packets; it only picks the outbound interface.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 80))
        except OSError:
            sys.exit("Could not determine local IP. Are you connected to a network?")
        return s.getsockname()[0]


def ping(ip: str, timeout: float) -> bool:
    match platform.system():
        case "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        case "Darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
        case _:
            cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), ip]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def normalize_mac(mac: str) -> str:
    # macOS drops leading zeros (e.g. "0:1a:2b:..."), so pad each octet.
    return ":".join(part.zfill(2) for part in mac.lower().split(":"))


def read_arp_table() -> dict[ipaddress.IPv4Address, str]:
    """Return IP -> MAC from the OS neighbour cache, which the ping sweep fills.

    Hosts that drop ICMP still answer ARP, so this catches devices ping misses.
    """
    for cmd, pattern in ((["arp", "-an"], ARP_LINE), (["ip", "neigh"], NEIGH_LINE)):
        try:
            output = subprocess.run(cmd, capture_output=True, text=True).stdout
        except FileNotFoundError:
            continue
        table = {}
        for line in output.splitlines():
            if match := pattern.search(line):
                mac = normalize_mac(match.group(2))
                if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
                    continue
                table[ipaddress.IPv4Address(match.group(1))] = mac
        return table
    return {}


def read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; return it and the offset after it."""
    labels = []
    end = None
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:  # pointer to a name earlier in the packet
            end = end or offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
        elif length == 0:
            return ".".join(labels), end or offset + 1
        else:
            labels.append(packet[offset + 1 : offset + 1 + length].decode(errors="replace"))
            offset += 1 + length


def resolve_mdns(ip: ipaddress.IPv4Address, timeout: float) -> str:
    """Ask the host for its own name over mDNS (Bonjour), as `dig -x ip @224.0.0.251 -p 5353` does."""
    query_name = ip.reverse_pointer.encode()
    question = b"".join(bytes([len(label)]) + label for label in query_name.split(b"."))
    packet = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question + b"\x00\x00\x0c\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, ("224.0.0.251", 5353))
            response = s.recv(4096)
            questions, answers = int.from_bytes(response[4:6]), int.from_bytes(response[6:8])
            offset = 12
            for _ in range(questions):
                offset = read_dns_name(response, offset)[1] + 4
            for _ in range(answers):
                offset = read_dns_name(response, offset)[1]
                rtype = int.from_bytes(response[offset : offset + 2])
                rdlength = int.from_bytes(response[offset + 8 : offset + 10])
                offset += 10
                if rtype == 12:  # PTR
                    return read_dns_name(response, offset)[0]
                offset += rdlength
        except (OSError, IndexError):
            pass
    return ""


def resolve(ip: ipaddress.IPv4Address, timeout: float) -> str:
    try:
        name = socket.gethostbyaddr(str(ip))[0]
    except OSError:
        name = ""
    # Some routers answer every reverse lookup with "localhost"; ask the device instead.
    if not name or name.startswith("localhost"):
        name = resolve_mdns(ip, timeout)
    return name


def port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_ports(spec: str) -> list[int]:
    if spec == "common":
        return list(COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    if not all(0 < p < 65536 for p in ports):
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return sorted(ports)


def format_port(port: int) -> str:
    name = COMMON_PORTS.get(port)
    return f"{port}/{name}" if name else str(port)


def print_table(hosts: list[Host], local_ip: str, show_ports: bool) -> None:
    rows = [("IP", "MAC", "HOSTNAME", "PORTS" if show_ports else "")]
    for host in hosts:
        hostname = host.hostname
        if str(host.ip) == local_ip:
            hostname = f"{hostname} (this machine)".strip()
        ports = ", ".join(format_port(p) for p in host.ports) if show_ports else ""
        rows.append((str(host.ip), host.mac or "-", hostname or "-", ports))

    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    for row in rows:
        line = "  ".join(cell.ljust(w) for cell, w in zip(row, widths))
        print(f"{line}  {row[3]}".rstrip())
    print(f"\n{len(hosts)} host{'s' if len(hosts) != 1 else ''} up")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan the local network for live hosts.")
    parser.add_argument(
        "network",
        nargs="?",
        help="network in CIDR form (default: the /24 this machine is on)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        nargs="?",
        const="common",
        type=parse_ports,
        help="check open TCP ports: 'common' (default), or a list like 22,80,8000-8100",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="seconds per probe (default: 1)"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=128, help="parallel probes (default: 128)"
    )
    parser.add_argument(
        "-n", "--no-resolve", action="store_true", help="skip reverse DNS lookups"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    local_ip = get_local_ip()

    try:
        network = ipaddress.ip_network(args.network or f"{local_ip}/24", strict=False)
    except ValueError as e:
        sys.exit(f"Invalid network: {e}")
    if network.version != 4:
        sys.exit("Only IPv4 networks are supported.")
    if network.num_addresses > MAX_HOSTS:
        sys.exit(f"{network} has {network.num_addresses} addresses; the limit is {MAX_HOSTS}.")

    targets = list(network.hosts())
    print(f"Scanning {network} ({len(targets)} addresses)...", file=sys.stderr)

    with ThreadPoolExecutor(args.workers) as pool:
        replies = pool.map(lambda ip: ping(str(ip), args.timeout), targets)
        alive = {ip for ip, up in zip(targets, replies) if up}

        macs = {ip: mac for ip, mac in read_arp_table().items() if ip in network}
        hosts = [Host(ip, macs.get(ip, "")) for ip in sorted(alive | macs.keys())]

        if not args.no_resolve:
            for host, name in zip(hosts, pool.map(lambda h: resolve(h.ip, args.timeout), hosts)):
                host.hostname = name

        if args.ports:
            print(f"Checking {len(args.ports)} ports on {len(hosts)} hosts...", file=sys.stderr)
            jobs = [(host, port) for host in hosts for port in args.ports]
            results = pool.map(lambda j: port_open(str(j[0].ip), j[1], args.timeout), jobs)
            for (host, port), is_open in zip(jobs, results):
                if is_open:
                    host.ports.append(port)

    print(file=sys.stderr)
    print_table(hosts, local_ip, show_ports=bool(args.ports))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
