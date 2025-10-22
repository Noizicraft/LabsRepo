#!/usr/bin/env python3
# win_dns_sniffer_autoiface.py
# Windows: auto-select interface by outbound IP (no psutil required).
# Run as Administrator. pip install scapy

import ctypes
import sys
import time
import socket
import argparse
from scapy.all import AsyncSniffer, sniff, send, IP, UDP, DNS, DNSQR, get_if_list, get_if_addr
from scapy.layers.inet import IP as IP_layer
from scapy.layers.dns import DNS as DNS_layer

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def ensure_admin_or_restart():
    if not is_admin():
        # restart with admin privileges
        params = " ".join(['"' + p + '"' if " " in p else p for p in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit()

def safe_decode(x):
    try:
        if isinstance(x, bytes):
            return x.decode(errors="ignore").rstrip('.')
        return str(x).rstrip('.')
    except Exception:
        return repr(x)

def get_outbound_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def find_iface_by_ip(outbound_ip):
    if not outbound_ip:
        return None
    ifaces = get_if_list()
    for iface in ifaces:
        try:
            addr = get_if_addr(iface)
            if addr == outbound_ip:
                return iface
        except Exception:
            # get_if_addr can raise for interfaces without IPv4 addr or special names
            continue
    return None

def interactive_choose_iface():
    ifs = get_if_list()
    print("Available interfaces:")
    for i, n in enumerate(ifs):
        print(f"  [{i}] {n}")
    choice = input("Enter interface index or exact name (or press Enter for first): ").strip()
    if choice == "":
        return ifs[0] if ifs else None
    try:
        idx = int(choice)
        if 0 <= idx < len(ifs):
            return ifs[idx]
    except Exception:
        pass
    if choice in ifs:
        return choice
    print("Invalid choice; using first interface.")
    return ifs[0] if ifs else None

packet_count = 0

def packet_prn(pkt):
    global packet_count
    packet_count += 1
    # debug: always print a summary of packets seen so we know sniff is active
    print(f"[SEEN={packet_count}] {pkt.summary()}")

    if not pkt.haslayer(DNS_layer):
        return

    ip_src = pkt[IP_layer].src if pkt.haslayer(IP_layer) else "?"
    ip_dst = pkt[IP_layer].dst if pkt.haslayer(IP_layer) else "?"
    dns = pkt[DNS_layer]

    if dns.qr == 0:  # query
        if dns.qd is not None:
            q = getattr(dns.qd, "qname", None)
            qname = safe_decode(q) if q is not None else "(no qname)"
            print(f"QUERY   {ip_src} -> {ip_dst} : {qname}")
    else:
        answers = []
        try:
            ancount = int(dns.ancount)
        except Exception:
            ancount = 0
        for i in range(ancount):
            try:
                a = dns.an[i]
                rrname = safe_decode(getattr(a, "rrname", getattr(a, "rname", "")))
                rdata = getattr(a, "rdata", "")
                answers.append(f"{rrname} -> {safe_decode(rdata)}")
            except Exception:
                continue
        print(f"RESPONSE {ip_src} -> {ip_dst} : " + (" | ".join(answers) if answers else "(no answers)"))

def send_test_queries():
    test_name = "win-one-shot-test.example.com"
    print("Sending test query to 127.0.0.1 (loopback)...")
    pkt1 = IP(dst="127.0.0.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=test_name))
    send(pkt1, verbose=False)
    time.sleep(0.3)

    outbound = get_outbound_ip() or "127.0.0.1"
    print("Sending test query to outbound IP:", outbound)
    pkt2 = IP(dst=outbound)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="win-outbound-test.example.com"))
    send(pkt2, verbose=False)
    time.sleep(0.3)
    print("Test queries sent.")

def main():
    ensure_admin_or_restart()

    parser = argparse.ArgumentParser(description="Windows DNS sniffer - auto interface selection (no psutil)")
    parser.add_argument("--iface", help="Interface to listen on (name). If omitted, auto-detect by outbound IP or ask.")
    parser.add_argument("--test", action="store_true", help="Send test queries after start")
    args = parser.parse_args()

    outbound = get_outbound_ip()
    print("Available outbound IP:", outbound if outbound else "(none)")

    iface = args.iface
    if not iface:
        if outbound:
            print("Trying to find interface matching outbound IP...")
            iface = find_iface_by_ip(outbound)
            if iface:
                print("Auto-selected iface by outbound IP:", iface)
        if not iface:
            print("Auto-selection failed or not applicable. Please choose interface.")
            iface = interactive_choose_iface()

    if not iface:
        print("No interface available, exiting.")
        return

    bpf = "port 53"
    print("Starting AsyncSniffer on iface:", iface, "BPF:", bpf)
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=packet_prn, store=False)
    sniffer.start()
    print("Sniffer started. Press Ctrl+C to stop.")

    if args.test:
        time.sleep(1.0)
        send_test_queries()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        try:
            sniffer.stop()
            print("Stopped.")
        except Exception as e:
            print("Error stopping sniffer:", e)
    finally:
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception:
            pass

if __name__ == "__main__":
    main()
