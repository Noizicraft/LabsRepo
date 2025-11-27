import ctypes
import sys
import time
import socket
import argparse
from scapy.all import AsyncSniffer, sniff, send, IP, UDP, DNS, DNSQR, get_if_list, get_if_addr
from scapy.layers.inet import IP as IP_layer
from scapy.layers.dns import DNS as DNS_layer
from dataclasses import dataclass, field
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import random
import math
import string
import json


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def ensure_admin_or_restart():
    if not is_admin():
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


@dataclass
class DNSRecord:
    ts: datetime
    src_ip: str
    dst_ip: str
    query_name: str
    answers: list = field(default_factory=list)
    ttl: int = None


VOWELS = set("aeiouyAEIOUY")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    ent = 0.0
    for _, cnt in counts.items():
        p = cnt / length
        ent -= p * math.log2(p)
    return ent


def consonant_vowel_ratio(name: str) -> float:
    letters = [c for c in name if c.isalpha()]
    if not letters:
        return 0.0
    vowels = sum(1 for c in letters if c in VOWELS)
    consonants = len(letters) - vowels
    return (consonants / vowels) if vowels > 0 else float('inf')


def digit_ratio(name: str) -> float:
    if not name:
        return 0.0
    digits = sum(1 for c in name if c.isdigit())
    return digits / len(name)


def extract_tld(domain: str) -> str:
    parts = domain.lower().rstrip('.').split('.')
    return parts[-1] if len(parts) > 1 else ''


class DNSAnomalyDetector:
    def __init__(self, log_file="dns_security_log.txt"):
        self.log_file = log_file
        self.records = []
        self.domain_ips = defaultdict(lambda: deque())
        self.domain_times = defaultdict(lambda: deque())

        self.length_threshold = 100
        self.unique_ip_threshold = 20
        self.entropy_threshold = 3.5
        self.cv_ratio_threshold = 4.0
        self.digit_ratio_threshold = 0.3
        self.q_threshold = 100
        self.suspicious_tlds = {"top", "xyz", "tk", "gq", "ws", "pw", "ml", "cf", "gg", "hk"}

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(f"DNS Security Monitor Log - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n")

    def log_alert(self, alert_type, domain, details, timestamp=None):
        if timestamp is None:
            timestamp = datetime.now()
        log_entry = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {alert_type}: {domain} - {details}\n"
        print(f"🚨 ALERT: {log_entry.strip()}")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)

    def detect_tunneling(self, record):
        if len(record.query_name) > self.length_threshold:
            self.log_alert("DNS_TUNNELING", record.query_name,
                           f"Domain name too long ({len(record.query_name)} chars)")
            return True
        return False

    def detect_fastflux(self, record):
        domain = record.query_name.lower()
        dq = self.domain_ips[domain]

        while dq and dq[0][0] < record.ts - timedelta(hours=1):
            dq.popleft()

        for ip in record.answers:
            dq.append((record.ts, ip))

        unique_ips = set(ip for (_, ip) in dq)
        if len(unique_ips) >= self.unique_ip_threshold:
            self.log_alert("FAST_FLUX", domain,
                           f"Too many unique IPs ({len(unique_ips)}) in short time")
            return True
        return False

    def is_dga_like(self, name):
        labels = name.split('.')
        main = labels[-2] if len(labels) >= 2 else labels[0]
        sanitized = ''.join(c for c in main if c.isalnum())
        ent = shannon_entropy(sanitized)
        cv = consonant_vowel_ratio(sanitized)
        dr = digit_ratio(sanitized)

        reasons = []
        if ent >= self.entropy_threshold:
            reasons.append(f"entropy={ent:.2f}")
        if cv >= self.cv_ratio_threshold:
            reasons.append(f"c/v_ratio={cv:.2f}")
        if dr >= self.digit_ratio_threshold:
            reasons.append(f"digit_ratio={dr:.2f}")

        if reasons:
            self.log_alert("DGA_DOMAIN", name, f"DGA characteristics: {', '.join(reasons)}")
            return True
        return False

    def detect_suspicious_tld(self, record):
        tld = extract_tld(record.query_name)
        if tld in self.suspicious_tlds:
            self.log_alert("SUSPICIOUS_TLD", record.query_name, f"Suspicious TLD: .{tld}")
            return True
        return False

    def detect_excessive_queries(self, record):
        domain = record.query_name.lower()
        dq = self.domain_times[domain]

        while dq and dq[0] < record.ts - timedelta(minutes=1):
            dq.popleft()

        dq.append(record.ts)

        if len(dq) >= self.q_threshold:
            self.log_alert("EXCESSIVE_QUERIES", domain,
                           f"High query rate ({len(dq)} queries per minute)")
            return True
        return False

    def analyze_record(self, record):
        self.records.append(record)

        alerts = []
        alerts.append(self.detect_tunneling(record))
        alerts.append(self.detect_fastflux(record))
        alerts.append(self.is_dga_like(record.query_name))
        alerts.append(self.detect_suspicious_tld(record))
        alerts.append(self.detect_excessive_queries(record))

        return any(alerts)


packet_count = 0
detector = DNSAnomalyDetector()


def packet_prn(pkt):
    global packet_count
    packet_count += 1

    if not pkt.haslayer(DNS_layer):
        return

    ip_src = pkt[IP_layer].src if pkt.haslayer(IP_layer) else "?"
    ip_dst = pkt[IP_layer].dst if pkt.haslayer(IP_layer) else "?"
    dns = pkt[DNS_layer]

    current_time = datetime.now()

    if dns.qr == 0:  # query
        if dns.qd is not None:
            q = getattr(dns.qd, "qname", None)
            qname = safe_decode(q) if q is not None else "(no qname)"
            print(f"[{current_time.strftime('%H:%M:%S')}] QUERY   {ip_src} -> {ip_dst} : {qname}")

            record = DNSRecord(ts=current_time, src_ip=ip_src, dst_ip=ip_dst,
                               query_name=qname, answers=[])
            detector.analyze_record(record)

    else:  # response
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
                answers.append(safe_decode(rdata))
            except Exception:
                continue

        if dns.qd is not None:
            q = getattr(dns.qd, "qname", None)
            qname = safe_decode(q) if q is not None else "(no qname)"

            print(
                f"[{current_time.strftime('%H:%M:%S')}] RESPONSE {ip_src} -> {ip_dst} : {qname} -> {', '.join(answers) if answers else 'no answers'}")

            record = DNSRecord(ts=current_time, src_ip=ip_src, dst_ip=ip_dst,
                               query_name=qname, answers=answers)
            detector.analyze_record(record)


def send_test_queries():
    test_name = "win-one-shot-test.example.com"
    print("Sending test query to 127.0.0.1 (loopback)...")
    pkt1 = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=test_name))
    send(pkt1, verbose=False)
    time.sleep(0.3)

    outbound = get_outbound_ip() or "127.0.0.1"
    print("Sending test query to outbound IP:", outbound)
    pkt2 = IP(dst=outbound) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="win-outbound-test.example.com"))
    send(pkt2, verbose=False)
    time.sleep(0.3)
    print("Test queries sent.")


def main():
    ensure_admin_or_restart()

    parser = argparse.ArgumentParser(description="Real-time DNS Security Monitor")
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
    print("Starting DNS Security Monitor on iface:", iface)
    print("Log file:", detector.log_file)
    print("Monitoring DNS traffic in real-time...")
    print("-" * 80)

    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=packet_prn, store=False)
    sniffer.start()

    if args.test:
        time.sleep(1.0)
        send_test_queries()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping DNS Security Monitor...")
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