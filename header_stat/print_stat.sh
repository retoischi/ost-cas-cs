#!/usr/bin/env python3

# Statistik für HSTS Check
# Eingabeformat: index,URL,True|False|error

import csv
import sys
import time
import datetime

if len(sys.argv) != 2:
    print("usage: stats.py <out.csv>")
    sys.exit(1)

filename = sys.argv[1]

hsts = 0
no_hsts = 0
errors = 0

pos = 0
start = time.time()

with open(filename, newline="") as f:
    reader = csv.reader(f, delimiter=",")
    for row in reader:
        if len(row) < 3:
            continue
        status = row[2].strip()
        pos += 1
        if status == "True":
            hsts += 1
        elif status == "False":
            no_hsts += 1
        else:
            errors += 1

elapsed = time.time() - start
total = hsts + no_hsts + errors
responding = hsts + no_hsts

date_str = datetime.date.today().isoformat()

print(
    "Result on {}: {:.0%} of the responding hosts have set an HSTS header.".format(
        date_str,
        hsts / responding if responding > 0 else 0,
    )
)
print()
print("Absolute values:")
print("{} HSTS set".format(hsts))
print("{} HSTS missing".format(no_hsts))
print("{} No response ({:.0%})".format(errors, errors / total if total > 0 else 0))

