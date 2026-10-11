#!/usr/bin/env python3
"""Summarises results/measurements.tsv for one config label (default c1): one cell per (test, placement[/switches]
[/variant]) with the verdicts and observations across runs. Every number in the documents comes from here.

  summarize.py [config] [--md]
"""
import collections
import csv
import sys

cfg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "c1"
md = "--md" in sys.argv
rows = [r for r in csv.DictReader(open("results/measurements.tsv"), delimiter="\t")
        if r["config"].split("/")[0] == cfg]
runs = collections.defaultdict(set)
cells = collections.OrderedDict()
for r in rows:
    sw = r["config"].split("/", 1)[1] if "/" in r["config"] else "-"
    sw = ",".join(x for x in sw.split(",") if not x.endswith("=pr")) or "default"
    col = r["placement"] + ("" if sw == "default" else f" [{sw}]") + ("" if r["variant"] == "-" else f" ({r['variant']})")
    runs[r["placement"]].add(r["run_id"])
    key = (r["test"], col)
    c = cells.setdefault(key, {"kind": r["kind"], "verdicts": collections.Counter(), "observed": collections.Counter(),
                               "attr": collections.Counter(), "u": collections.Counter()})
    c["verdicts"][r["verdict"]] += 1
    c["observed"][r["observed"]] += 1
    c["attr"][r["attribution"]] += 1
    c["u"][r["u_control"].split(":")[-1] if r["u_control"] != "-" else "-"] += 1


def fmt(cnt):
    return " ".join(f"{k}×{v}" for k, v in cnt.most_common())


print(f"config {cfg}: " + ", ".join(f"{p} {len(v)} runs" for p, v in sorted(runs.items())))
print(f"rows: {len(rows)}; verdicts: {fmt(collections.Counter(r['verdict'] for r in rows))}")
if md:
    print("\n| Test | Placement | Kind | Verdicts | Observed | Deciding stage | U-control |\n|---|---|---|---|---|---|---|")
for (t, col), c in cells.items():
    if md:
        print(f"| {t} | {col} | {c['kind']} | {fmt(c['verdicts'])} | {fmt(c['observed'])} | {fmt(c['attr'])} | {fmt(c['u'])} |")
    else:
        print(f"{t:22} {col:42} {c['kind']:14} {fmt(c['verdicts']):26} obs={fmt(c['observed']):22} attr={fmt(c['attr'])}")
