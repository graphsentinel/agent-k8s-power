#!/usr/bin/env python3
"""Compares the measurement rows written since a start time with lab/expected.tsv, cell by cell.

  summary.py --since 2026-10-11T10:00:00Z --runs 5 [--runner-failures file] [--incomplete] [--markdown out.md]
             lab/expected.tsv results/measurements.tsv

A cell is (suite, switches, placement, variant, test). Every expected cell must be measured in exactly --runs runs,
each with the expected observation and verdict; a measured cell that is not expected, a 77 (setup failure) or a
DEVIATION, a runner that exited with an error, or a run that did not reach its end is a failure. Exit 0 only when
everything matches.
"""
import argparse
import collections
import csv
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True)
    ap.add_argument("--runs", type=int, required=True)
    ap.add_argument("--runner-failures")
    ap.add_argument("--incomplete", action="store_true")
    ap.add_argument("--markdown")
    ap.add_argument("expected")
    ap.add_argument("measurements")
    a = ap.parse_args()

    exp = {}
    for r in csv.DictReader(open(a.expected), delimiter="\t"):
        exp[(r["suite"], r["switches"], r["placement"], r["variant"], r["test"])] = r
    got = collections.defaultdict(lambda: {"obs": collections.Counter(), "verdict": collections.Counter(), "runs": set()})
    try:
        rows = [r for r in csv.DictReader(open(a.measurements), delimiter="\t") if r["time"] >= a.since]
    except FileNotFoundError:
        rows = []
    for r in rows:
        suite, _, switches = r["config"].partition("/")
        g = got[(suite, switches or "-", r["placement"], r["variant"], r["test"])]
        g["obs"][r["observed"]] += 1
        g["verdict"][r["verdict"]] += 1
        g["runs"].add(r["run_id"])

    problems = []
    if a.incomplete:
        problems.append("the test run did not reach its end (interrupted or aborted)")
    if a.runner_failures:
        try:
            problems += [f"runner failed: {x.strip()}" for x in open(a.runner_failures) if x.strip()]
        except FileNotFoundError:
            pass
    if not rows:
        problems.append(f"no measurements since {a.since}")
    ok = 0
    for key, e in exp.items():
        g = got.get(key)
        name = "/".join(x for x in key if x != "-")
        if not g:
            problems.append(f"{name}: not measured")
            continue
        n = len(g["runs"])
        bad = []
        if n != a.runs:
            bad.append(f"measured in {n} runs, expected {a.runs}")
        if set(g["obs"]) != {e["observed"]}:
            bad.append(f"observed {dict(g['obs'])}, expected '{e['observed']}'")
        if set(g["verdict"]) != {e["verdict"]}:
            bad.append(f"verdict {dict(g['verdict'])}, expected {e['verdict']}")
        if bad:
            problems.append(f"{name}: " + "; ".join(bad))
        else:
            ok += 1
    for key in got:
        if key not in exp:
            problems.append(f"{'/'.join(x for x in key if x != '-')}: measured but not in lab/expected.tsv")
    bad_verdicts = collections.Counter(v for g in got.values() for v, c in g["verdict"].items() for _ in range(c)
                                       if v in ("77", "DEVIATION"))
    for v, c in bad_verdicts.items():
        problems.append(f"{c} rows with verdict {v}")

    suites = collections.Counter(k[0] for k in exp)
    matched = collections.Counter(k[0] for k in exp if k in got and not any(
        p.startswith("/".join(x for x in k if x != "-") + ":") for p in problems))
    lines = ["| suite | expected cells | matching cells |", "|---|---|---|"]
    for s in suites:
        lines.append(f"| {s} | {suites[s]} | {matched[s]} |")
    table = "\n".join(lines)
    verdicts = collections.Counter(v for g in got.values() for v, c in g["verdict"].items() for _ in range(c))
    print(f"\nMeasurements since {a.since}: {len(rows)} rows; runs per cell expected: {a.runs}\n")
    print(table)
    print(f"\nverdicts in the new rows: {dict(verdicts)}")
    print(f"cells matching lab/expected.tsv: {ok} of {len(exp)}")
    if problems:
        print("\nCHECKS FAILED:")
        for p in problems[:60]:
            print("  - " + p)
        if len(problems) > 60:
            print(f"  ... and {len(problems) - 60} more")
    else:
        print("\nALL CHECKS PASSED")
    if a.markdown:
        with open(a.markdown, "w") as f:
            f.write(f"Measurements since {a.since} ({len(rows)} rows), {a.runs} runs per cell\n\n{table}\n\n")
            f.write(f"Cells matching lab/expected.tsv: {ok} of {len(exp)}\n\n")
            f.write("Checks: " + ("all passed\n" if not problems else "FAILED\n" + "".join(f"- {p}\n" for p in problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
