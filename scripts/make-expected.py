#!/usr/bin/env python3
"""Builds lab/expected.tsv: the outcome of every measured cell, from a reference run's measurement rows.

A cell is (suite, switches, placement, variant, test); suite is the config label (c1, c1b, v1). A cell enters the
table only if every run of it gave the same observation and verdict; otherwise the script stops, because an unstable
cell cannot serve as an expectation.

  scripts/make-expected.py results/measurements.tsv c1,c1b,v1 > lab/expected.tsv
"""
import collections
import csv
import sys

src, suites = sys.argv[1], sys.argv[2].split(",")
cells = collections.OrderedDict()
for r in csv.DictReader(open(src), delimiter="\t"):
    suite, _, switches = r["config"].partition("/")
    if suite not in suites:
        continue
    key = (suite, switches or "-", r["placement"], r["variant"], r["test"])
    c = cells.setdefault(key, {"kind": r["kind"], "obs": set(), "verdict": set(), "runs": set()})
    c["obs"].add(r["observed"])
    c["verdict"].add(r["verdict"])
    c["runs"].add(r["run_id"])

unstable = [k for k, c in cells.items() if len(c["obs"]) > 1 or len(c["verdict"]) > 1]
if unstable:
    sys.exit(f"unstable cells, no expectation possible: {unstable[:5]}")
w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
w.writerow(["suite", "switches", "placement", "variant", "test", "kind", "verdict", "observed", "reference_runs"])
for (suite, sw, p, v, t), c in cells.items():
    w.writerow([suite, sw, p, v, t, c["kind"], next(iter(c["verdict"])), next(iter(c["obs"])), len(c["runs"])])
