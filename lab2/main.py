from dataclasses import dataclass, field
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import random
import math
import string
import argparse
import json
import sys
import time
@dataclass
class DNSRecord:
    ts: datetime
    src_ip: str
    dst_ip: str
    query_name: str
    answers: list = field(default_factory=list)
    ttl: int = None

    def to_dict(self):
        return {
            "ts": self.ts.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "query_name": self.query_name,
            "answers": self.answers,
            "ttl": self.ttl
        }
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

def detect_tunneling(records, length_threshold=100):
    alerts = []
    for r in records:
        if len(r.query_name) > length_threshold:
            alerts.append((r, "long_domain_name", len(r.query_name)))
    return alerts

def detect_fastflux(records, window=timedelta(hours=1), unique_ip_threshold=20):
    records_sorted = sorted(records, key=lambda r: r.ts)
    alerts = []
    domain_ips = defaultdict(lambda: deque())  # deque элементов (ts, ip)
    for r in records_sorted:
        domain = r.query_name.lower()
        dq = domain_ips[domain]
        # очистка старых
        while dq and dq[0][0] < r.ts - window:
            dq.popleft()
        # добавляем ответы
        for ip in r.answers:
            dq.append((r.ts, ip))
        unique_ips = set(ip for (_, ip) in dq)
        if len(unique_ips) >= unique_ip_threshold:
            alerts.append((r.ts, domain, len(unique_ips), "fast-flux-candidate"))
    return alerts

def is_dga_like(name, entropy_threshold=3.5, cv_ratio_threshold=4.0, digit_ratio_threshold=0.3):
    """
    Эвристика DGA: берем SLD (второй уровень), считаем энтропию, c/v и долю цифр.
    Возвращает (bool suspicious, reasons_list).
    """
    labels = name.split('.')
    main = labels[-2] if len(labels) >= 2 else labels[0]
    sanitized = ''.join(c for c in main if c.isalnum())
    ent = shannon_entropy(sanitized)
    cv = consonant_vowel_ratio(sanitized)
    dr = digit_ratio(sanitized)
    reasons = []
    if ent >= entropy_threshold:
        reasons.append(("entropy", ent))
    if cv >= cv_ratio_threshold:
        reasons.append(("c/v", cv))
    if dr >= digit_ratio_threshold:
        reasons.append(("digit_ratio", dr))
    return (len(reasons) > 0, reasons)

def detect_dga(records, **kwargs):
    alerts = []
    seen = set()
    for r in records:
        domain = r.query_name.lower().rstrip('.')
        if domain in seen:
            continue
        seen.add(domain)
        suspicious, reasons = is_dga_like(domain, **kwargs)
        if suspicious:
            alerts.append((domain, reasons))
    return alerts

def detect_suspicious_tld(records, suspicious_tlds=None):
    if suspicious_tlds is None:
        suspicious_tlds = {"top","xyz","tk","gq","ws","pw","ml","cf"}
    alerts = []
    for r in records:
        tld = extract_tld(r.query_name)
        if tld in suspicious_tlds:
            alerts.append((r.query_name, tld))
    return alerts


def detect_excessive_queries(records, window=timedelta(minutes=1), q_threshold=100):
    """
    Sliding window count запросов к одному домену.
    Возвращает список (ts, domain, count, tag).
    """
    records_sorted = sorted(records, key=lambda r: r.ts)
    domain_times = defaultdict(lambda: deque())
    alerts = []
    for r in records_sorted:
        domain = r.query_name.lower()
        dq = domain_times[domain]
        while dq and dq[0] < r.ts - window:
            dq.popleft()
        dq.append(r.ts)
        if len(dq) >= q_threshold:
            alerts.append((r.ts, domain, len(dq), "high-query-rate"))
    return alerts

# ---------------------------
# Демонстрация: синтетические сценарии
# ---------------------------

def make_record(base_time, offset_seconds, query_name, answers=None, ttl=300, src_ip="192.0.2.1", dst_ip="198.51.100.1"):
    return DNSRecord(ts=base_time + timedelta(seconds=offset_seconds), src_ip=src_ip, dst_ip=dst_ip, query_name=query_name, answers=answers or [], ttl=ttl)

def simple_dga(seed, length=12):
    rnd = random.Random(seed)
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(rnd.choice(alphabet) for _ in range(length)) + ".com"

def run_demo():
    now = datetime.utcnow()
    records = []
    long_payload = "a" * 128
    for i in range(5):
        records.append(make_record(now, i, f"{long_payload}.exfil.example.com"))

    flux_domain = "badflux.example.com"
    for i in range(60):
        ip = f"203.0.113.{(i % 250) + 1}"
        records.append(make_record(now, i*60, flux_domain, answers=[ip], ttl=30))

    # 3) DGA-подобные домены
    for s in range(10):
        start_time = time.time()
        records.append(make_record(now, 3600 + s*10, simple_dga(start_time, length=12)))


    # 4) Подозрительные TLD
    records.append(make_record(now, 7200, "malicious.top", answers=["198.51.100.5"]))
    records.append(make_record(now, 7210, "cheap-stuff.tk", answers=["198.51.100.9"]))
    records.append(make_record(now, 7220, "normal.example.com", answers=["198.51.100.10"]))

    # 5) Чрезмерные запросы (поток запросов к одному домену)
    target = "ddos.example.com"
    # создаём 300 запросов, сгущая время (i//30 даёт несколько запросов в одну секунду)
    for i in range(300):
        records.append(make_record(now, 8000 + (i // 30), target, answers=["192.0.2.55"]))

    # Бенинные запросы
    records.append(make_record(now, 9000, "calendar.google.com", answers=["172.217.0.46"]))
    records.append(make_record(now, 9010, "api.github.com", answers=["140.82.112.4"]))

    # Запускаем детекторы с дефолтными порогами
    tunneling = detect_tunneling(records, length_threshold=100)
    fastflux = detect_fastflux(records, window=timedelta(hours=1), unique_ip_threshold=20)
    dga = detect_dga(records, entropy_threshold=3.5, cv_ratio_threshold=4.0, digit_ratio_threshold=0.3)
    suspicious_tld = detect_suspicious_tld(records)
    excessive = detect_excessive_queries(records, window=timedelta(minutes=1), q_threshold=100)

    print("=== DNS Anomaly Detector: demo results ===")
    print(f"Total records: {len(records)}\n")

    print("TUNNELING ALERTS:")
    for rec, tag, length in tunneling:
        print(f" - {rec.ts.isoformat()} {rec.query_name} (len={length})")

    print("\nFAST-FLUX ALERTS:")
    ff_by_domain = defaultdict(list)
    for ts, domain, unique, tag in fastflux:
        ff_by_domain[domain].append((ts, unique))
    for dom, items in ff_by_domain.items():
        latest = max(items, key=lambda x: x[0])
        print(f" - {dom} unique_ips={latest[1]} at {latest[0].isoformat()}")

    print("\nDGA-LIKE ALERTS:")
    for domain, reasons in dga:
        print(" -", domain, "reasons:", ", ".join(f"{k}={v:.2f}" for k, v in reasons))

    print("\nSUSPICIOUS TLD ALERTS:")
    for qname, tld in suspicious_tld:
        print(f" - {qname} (tld={tld})")


    print("\nEXCESSIVE QUERIES ALERTS:")
    ex_by_domain = defaultdict(list)
    for ts, domain, count, tag in excessive:
        ex_by_domain[domain].append((ts, count))
    for dom, items in ex_by_domain.items():
        print(f" - {dom} recent_count={max(i[1] for i in items)} at {max(i[0] for i in items).isoformat()}")

    out = {
        "tunneling": [(rec.to_dict(), tag, length) for rec, tag, length in tunneling],
        "fastflux": [{"ts": ts.isoformat(), "domain": d, "unique_ips": u, "tag": t} for ts, d, u, t in fastflux],
        "dga": [{"domain": d, "reasons": [(k, float(v)) for k, v in reasons]} for d, reasons in dga],
        "suspicious_tld": [{"qname": q, "tld": t} for q, t in suspicious_tld],
        "excessive": [{"ts": ts.isoformat(), "domain": d, "count": c, "tag": t} for ts, d, c, t in excessive]
    }
    try:
        with open("dns_anomaly_results.json", "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print("\nStructured results saved to dns_anomaly_results.json")
    except Exception as e:
        print("Failed to save JSON results:", e, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="DNS Anomaly Detector (demo)")
    parser.add_argument("--save", metavar="PATH", help="(demo) save this script source to PATH")
    args = parser.parse_args()

    if args.save:
        try:
            src_path = __file__
            with open(src_path, "r", encoding="utf-8") as rf:
                src = rf.read()
            with open(args.save, "w", encoding="utf-8") as wf:
                wf.write(src)
            print(f"Saved script to: {args.save}")
        except Exception as e:
            print("Failed to save script:", e, file=sys.stderr)
        return

    run_demo()

if __name__ == "__main__":
    main()
