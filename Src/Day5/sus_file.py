import re

pat1 = re.compile(r"Failed password", re.I)
pat2 = re.compile(r"ET", re.I)

with open("logs.txt", "r") as infile:
    for line1 in infile:
        if pat1.search(line1):
            log_line1 = line1.rstrip("\n") 
            with open("failed_password.txt", "a") as outfile:
                outfile.write(log_line1 + "\n")

    for line2 in infile:
        if pat2.search(line2):
            log_line2 = line2.rstrip("\n")
            with open("other_attack.txt", "a") as o_att:
                o_att.write(log_line2 + "\n")











