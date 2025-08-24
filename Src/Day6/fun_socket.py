import re, socket
pat = re.compile(r"(UNION SELECT|<script>|xp_cmdshell|/etc/passwd|Failed password|SURICATA|ET )", re.I)
s = socket.create_connection(("127.0.0.1", 5500))
with s, s.makefile() as f:
    for line in f:
        line=line.rstrip("\n")
        hit = "  <-- SUSPICIOUS" if pat.search(line) else ""
        print(line+hit)
