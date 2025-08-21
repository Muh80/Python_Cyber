#!/usr/bin/env python3
import argparse, time, re, math, collections
from collections import defaultdict, deque

try:
    from scapy.all import sniff, PcapReader, IP, TCP, UDP, DNSQR, Raw
    SCAPY_OK = True
except Exception:
    # Allow --pcap-less run to still parse code for teaching
    SCAPY_OK = False

WINDOW = 10                    # seconds for scan window
PORT_SCAN_THRESHOLD = 20       # distinct dports in WINDOW
BEACON_WINDOW = 120            # seconds to evaluate regularity
HTTP_PORTS = {80, 8080, 8000}

sql_xss = re.compile(r"(UNION\s+SELECT|<script|onerror\s*=|or\s+1=1|/etc/passwd|xp_cmdshell|sleep\(\d+\))", re.I)

ports_by_src = defaultdict(lambda: deque())           # src -> deque[(t,dport)]
conn_times = defaultdict(lambda: deque())             # (src,dst) -> deque[t]

def entropy(s: str) -> float:
    if not s: return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

def handle(pkt):
    now = time.time()
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    # 1) SYN scan (distinct dest ports within a short window)
    if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x02):  # SYN
        dq = ports_by_src[src]
        dq.append((now, pkt[TCP].dport))
        while dq and now - dq[0][0] > WINDOW:
            dq.popleft()
        unique_ports = {d for _, d in dq}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            print(f"[ALERT][SCAN] {src} -> {len(unique_ports)} ports in {WINDOW}s")

    # 2) Beaconing (nearly-regular intervals)
    key = (src, dst)
    q = conn_times[key]
    q.append(now)
    while q and now - q[0] > BEACON_WINDOW:
        q.popleft()
    if len(q) >= 4:
        it = [q[i+1]-q[i] for i in range(len(q)-1)]
        if max(it) - min(it) < 1.0:  # ~regular within 1s
            period = sum(it)/len(it)
            print(f"[NOTICE][BEACON] {src} -> {dst} ~{period:.1f}s")

    # 3) Suspicious DNS (long or high-entropy labels)
    if pkt.haslayer(UDP) and pkt[UDP].dport == 53 and pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
        except Exception:
            qname = str(pkt[DNSQR].qname)
        labels = qname.split('.')
        longest = max(labels, key=len) if labels else ""
        H = entropy(longest)
        if len(longest) >= 50 or H > 4.0:
            print(f"[ALERT][DNS] label_len={len(longest)} H={H:.2f} name={qname} from {src}")

    # 4) HTTP payload tokens (very naive)
    if pkt.haslayer(TCP) and pkt[TCP].dport in HTTP_PORTS and pkt.haslayer(Raw):
        payload = pkt[Raw].load[:600].decode('latin-1', errors='ignore')
        if sql_xss.search(payload):
            m = sql_xss.search(payload).group(0)
            print(f"[ALERT][HTTP] {src} -> {dst} token='{m[:30]}'")

def main():
    # ap = argparse.ArgumentParser(description="Mini-IDS (teachable demo)")
    global WINDOW, PORT_SCAN_THRESHOLD
    ap = argparse.ArgumentParser(description="Mini-IDS (teachable demo)")
    ap.add_argument("--iface", help="Interface to sniff (requires sudo)")
    ap.add_argument("--pcap", help="Read from a pcap instead of live sniff")
    ap.add_argument("--bpf", default="tcp or udp", help="BPF filter for sniff()")
    ap.add_argument("--window", type=int, default=WINDOW, help="Scan window seconds")
    ap.add_argument("--scan-threshold", type=int, default=PORT_SCAN_THRESHOLD, help="Distinct ports in window")
    args = ap.parse_args()

    # global WINDOW, PORT_SCAN_THRESHOLD
    WINDOW = args.window
    PORT_SCAN_THRESHOLD = args.scan_threshold

    if args.pcap:
        if not SCAPY_OK:
            print("Scapy not available; install scapy or just show code in class.")
            return
        print(f"[INFO] Reading pcap: {args.pcap}")
        with PcapReader(args.pcap) as pr:
            for pkt in pr:
                handle(pkt)
        return

    if not args.iface:
        print("Provide --iface for live sniff or --pcap for offline mode")
        return

    if not SCAPY_OK:
        print("Scapy not available; install scapy to live sniff (`pip install scapy`)")
        return

    print(f"[INFO] Sniffing on {args.iface} (BPF: {args.bpf}) ... Ctrl+C to stop")
    sniff(iface=args.iface, filter=args.bpf, prn=handle, store=False)

if __name__ == "__main__":
    main()