#!/usr/bin/env python3
"""Turns one run's driver output into evidence files and TSV rows (measurement contract §5).

  collect.py <evidence_dir> <tsv>

Reads <evidence_dir>/driver-*.jsonl, webhook.jsonl, audit.jsonl. Control gate: if any control row of the run is not
MATCH, every row of the run is written as 77 with the reason (DEC-01). Adds the derived A1-b propagation row from
the webhook log (two SubjectAccessReviews for one aggregated request = the constraint reached the delegated check).
"""
import glob
import json
import os
import sys

COLS = ["time", "run_id", "config", "placement", "variant", "test", "kind", "verdict", "expected", "observed",
        "attribution", "u_control", "detail"]


def main():
    ev, tsv = sys.argv[1], sys.argv[2]
    rows, reqs, ends = [], [], []
    # webhook.jsonl is appended once per webhook pod (switch changes restart it); count each line once.
    # Evidence is never rewritten (PoC verification 2026-10-08: an earlier in-place de-duplication made one c0 row
    # non-reproducible); de-duplication happens in memory only.
    wp = os.path.join(ev, "webhook.jsonl")
    webhook_lines = []
    if os.path.exists(wp):
        seen = set()
        for line in open(wp):
            if line not in seen:
                seen.add(line)
                webhook_lines.append(line)
    for f in sorted(glob.glob(os.path.join(ev, "driver-*.jsonl"))):
        for line in open(f):
            line = line.strip()
            if not line.startswith("{"):
                continue
            o = json.loads(line)
            {"row": rows, "req": reqs, "end": ends}.get(o.get("type"), []).append(o)
    with open(os.path.join(ev, "requests.jsonl"), "w") as fh:
        for r in reqs:
            fh.write(json.dumps(r) + "\n")

    # derived A1-b row
    a1 = [r for r in rows if r["test"] == "A1-b-team-a"]
    if a1 and os.path.exists(os.path.join(ev, "webhook.jsonl")):
        w = a1[0]["detail"].split()[0].split("=")[1].split("-")
        lo, hi = float(w[0]) - 0.05, float(w[1]) + 0.05
        hits = []
        for line in webhook_lines:
            try:
                o = json.loads(line)
            except Exception:
                continue
            ra = o.get("resourceAttributes") or {}
            if lo <= o.get("ts", 0) <= hi and ra.get("group") == "metrics.k8s.io" and ra.get("namespace") == "team-a":
                hits.append(o)
        carried = sum(1 for o in hits if "s1.lab.example/constraints" in o.get("extra_keys", []))
        rows.append(dict(a1[0], test="A1-b-propagation", kind="design-reading", verdict="OBSERVED", expected="none",
                         observed=f"{len(hits)} SAR", attribution="-", u_control="-",
                         detail=f"webhook saw {len(hits)} SubjectAccessReviews for this metrics request, "
                                f"{carried} carrying the constraint extra (1 = front door only; 2 = also the "
                                f"aggregated server's delegated check)"))

    controls = [r for r in rows if r["kind"] == "control"]
    bad = [r["test"] for r in controls if r["verdict"] != "MATCH"]
    new = not os.path.exists(tsv)
    with open(tsv, "a") as fh:
        if new:
            fh.write("\t".join(COLS) + "\n")
        for r in rows:
            if bad and r["kind"] != "control":
                r = dict(r, verdict="77", detail=f"controls failed in this run: {','.join(bad)} | " + r["detail"])
            fh.write("\t".join(str(r.get(c, "-")).replace("\t", " ") or "-" for c in COLS) + "\n")
    summary = {}
    for r in rows:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    print(json.dumps({"run": os.path.basename(ev), "rows": len(rows), "verdicts": summary, "controls_failed": bad}))


if __name__ == "__main__":
    main()
