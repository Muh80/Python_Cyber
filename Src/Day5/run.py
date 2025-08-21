#import re, socket

#pat = re.compile(r"(UNION SELECT|<script>|xp_cmdshell|/etc/passwd|Failed password|SURICATA|ET )", re.I)
#s = socket.create_connection(("127.0.0.1", 5500))

#with s, s.makefile() as f, open("logs.txt", "a") as logfile:
#    for line in f:
#        line = line.rstrip("\n")
#     hit = "  <-- SUSPICIOUS" if pat.search(line) else ""
/



import re, socket

pat = re.compile(r"(UNION SELECT|<script>|xp_cmdshell|/etc/passwd|Failed password|SURICATA|ET )", re.I)
s = socket.create_connection(("127.0.0.1", 5500))

with s, s.makefile() as f, open("logs.txt", "a") as logfile:
    for line in f:
        line = line.rstrip("\n")
        if pat.search(line):
            log_line = line + "  <-- SUSPICIOUS"
            print(log_line)
            logfile.write(log_line + "\n")

