#!/usr/bin/env python3
import argparse, json, os, random, re, socket, threading, time
from datetime import datetime
from ipaddress import IPv4Address

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/8.0.1", "sqlmap/1.7.10", "Wget/1.21.4",
    "Mozilla/5.0 (X11; Linux x86_64)", "Go-http-client/1.1"
]
METHODS = ["GET","POST","GET","GET","POST","HEAD"]
PATHS = ["/", "/login", "/search", "/admin", "/api/v1/items", "/wp-login.php", "/index.php", "/?id=1"]
STATUS = [200, 200, 200, 404, 403, 500, 302]
EXTS = ["html","php","js","css","png","txt"]
DNS_DOMAINS = ["example.com","corp.local","internal.svc","updates.microsoft.com","github.com","cdn.example.net"]
USERNAMES = ["root","admin","test","ubuntu","oracle","postgres"]
IDS_RULES = ["ET WEB_SERVER Possible Shell Upload","ET ATTACK_RESPONSE id Command Execution","SURICATA STREAM 3way handshake with invalid ack","ET CURRENT_EVENTS Possible CVE Probe"]

SUSPICIOUS_PAYLOADS = [
    "' OR '1'='1", "UNION SELECT 1,2,3--", "<script>alert(1)</script>",
    "../../etc/passwd", "file=http://evil.tld/shell.txt", "onerror=alert(1)", "xp_cmdshell"
]
SUSPICIOUS_UA = ["sqlmap", "nikto", "dirbuster"]

def rand_ip():
    return str(IPv4Address(random.randint(0x01000000, 0xE0000000-1)))

def rand_ts():
    return datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

def maybe_suspicious(p_attack: float) -> bool:
    return random.random() < p_attack

def make_http_log(p_attack: float, json_mode=False):
    ip = rand_ip()
    ua = random.choice(UA)
    method = random.choice(METHODS)
    path = random.choice(PATHS)

    # Inject suspicious payload sometimes
    if maybe_suspicious(p_attack) and method in ("GET","POST"):
        sus = random.choice(SUSPICIOUS_PAYLOADS)
        if "?" in path:
            path += "&q=" + sus
        else:
            path += "?q=" + sus
        if "sqlmap" in ua or random.random() < 0.3:
            ua = "sqlmap/1.7.10"

    status = random.choice(STATUS)
    size = random.randint(120, 4000)
    referer = "-" if random.random()<0.7 else f"https://{random.choice(DNS_DOMAINS)}/{random.choice(PATHS).strip('/')}"
    line = {
        "type":"http_access",
        "client_ip": ip,
        "ts": rand_ts(),
        "request": f"{method} {path} HTTP/1.1",
        "status": status,
        "bytes": size,
        "ua": ua,
        "referer": referer,
        "suspicious": any(k in path for k in ["UNION SELECT","<script>","../","xp_cmdshell"]) or any(s in ua for s in SUSPICIOUS_UA)
    }
    if json_mode:
        return json.dumps(line)
    # Common Log Format-ish
    return f'{ip} - - [{line["ts"]}] "{line["request"]}" {status} {size} "{referer}" "{ua}"'

def make_auth_log(p_attack: float, json_mode=False):
    ip = rand_ip()
    user = random.choice(USERNAMES)
    ok = random.random() < 0.2 and not maybe_suspicious(p_attack)  # mostly failures
    msg = (f"Accepted password for {user} from {ip} port {random.randint(10000,65000)} ssh2"
           if ok else
           f"Failed password for {user} from {ip} port {random.randint(10000,65000)} ssh2")
    line = {"type":"auth","ts": datetime.utcnow().isoformat()+"Z","host":"web01","proc":"sshd","msg":msg,"suspicious":not ok}
    return json.dumps(line) if json_mode else f'Aug {datetime.utcnow().day:02d} {datetime.utcnow().strftime("%H:%M:%S")} web01 sshd[1234]: {msg}'

def make_dns_log(p_attack: float, json_mode=False):
    qname = (f"{''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(random.randint(20,45)))}."
             f"{random.choice(DNS_DOMAINS)}")
    ip = rand_ip()
    msg = f"client {ip}#53: query: {qname} IN A + (127.0.0.1)"
    sus = len(qname.split(".")[0]) > 30 or "base64" in qname
    line = {"type":"dns","ts":datetime.utcnow().isoformat()+"Z","server":"dns01","msg":msg,"suspicious":sus}
    return json.dumps(line) if json_mode else f'{datetime.utcnow().strftime("%b %d %H:%M:%S")} dns01 named[222]: {msg}'

def make_ids_log(p_attack: float, json_mode=False):
    rule = random.choice(IDS_RULES)
    src = rand_ip(); dst = rand_ip()
    sev = random.choice([1,1,2,2,3,4,5])
    msg = f'[{sev}] {rule} SRC={src} DST={dst} SPT={random.randint(1024,65000)} DPT={random.choice([22,80,443,445,3389,3306])}'
    line = {"type":"ids","ts":datetime.utcnow().isoformat()+"Z","engine":"suricata","msg":msg,"severity":sev,"suspicious":sev>=3}
    return json.dumps(line) if json_mode else f'{datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")} suricata: {msg}'

GENS = [make_http_log, make_auth_log, make_dns_log, make_ids_log]

class SocketStreamer:
    def __init__(self, host, port, rate, attack_prob, json_mode):
        self.host, self.port = host, port
        self.rate = rate
        self.attack_prob = attack_prob
        self.json_mode = json_mode
        self.clients = set()
        self.lock = threading.Lock()
        self.keep_running = True

    def start(self):
        t_accept = threading.Thread(target=self._accept_loop, daemon=True)
        t_bcast  = threading.Thread(target=self._broadcast_loop, daemon=True)
        t_accept.start(); t_bcast.start()
        print(f"[+] TCP log server on {self.host}:{self.port} | {self.rate} logs/sec | attack_prob={self.attack_prob} | json={self.json_mode}")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Shutting down...")
            self.keep_running = False

    def _accept_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            while self.keep_running:
                try:
                    conn, addr = s.accept()
                    conn.setblocking(True)
                    with self.lock:
                        self.clients.add(conn)
                    print(f"[+] Client connected: {addr}")
                except OSError:
                    break

    def _broadcast_loop(self):
        period = 1.0 / max(1, self.rate)
        while self.keep_running:
            line = random.choice(GENS)(self.attack_prob, self.json_mode)
            data = (line + "\n").encode()
            rm = []
            with self.lock:
                for c in list(self.clients):
                    try:
                        c.sendall(data)
                    except Exception:
                        rm.append(c)
                for c in rm:
                    self.clients.discard(c)
                    try: c.close()
                    except: pass
            time.sleep(period)

def main():
    ap = argparse.ArgumentParser(description="SOC log streamer over TCP sockets")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5500)
    ap.add_argument("--rate", type=int, default=6, help="logs per second")
    ap.add_argument("--attack-prob", type=float, default=0.15, help="chance a log contains an attack indicator")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args()

    SocketStreamer(args.host, args.port, args.rate, args.attack_prob, args.json).start()

if __name__ == "__main__":
    main()
