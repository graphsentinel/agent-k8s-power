#!/usr/bin/env python3
"""A1-b caller attribution: for each M2 run of a config, find the metrics-server SubjectAccessReview created inside the
lifetime of the front-door A1-b-team-a request (audit log of the whole cluster).  a1b_audit.py <full-audit.jsonl> [config]"""
import datetime, glob, json, sys
A = [json.loads(l) for l in open(sys.argv[1])]
cfg = sys.argv[2] if len(sys.argv) > 2 else "c1"
ts = lambda s: datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
sar = [a for a in A if a.get("user", {}).get("username") == "system:serviceaccount:kube-system:metrics-server"
       and (a.get("objectRef") or {}).get("resource") == "subjectaccessreviews"]
for E in sorted(glob.glob(f"evidence/*-M2-{cfg}")):
    r = [json.loads(l) for l in open(E + "/requests.jsonl") if '"test": "A1-b-team-a"' in l][0]
    a = [x for x in A if x.get("auditID") == r["audit_id"]][0]
    t0, t1 = ts(a["requestReceivedTimestamp"]), ts(a["stageTimestamp"])
    inside = [x for x in sar if t0 <= ts(x["requestReceivedTimestamp"]) <= t1]
    print(json.dumps({"run": E.split("/")[-1], "front_audit_id": a["auditID"], "front_user": a["user"]["username"],
                      "front_window": [a["requestReceivedTimestamp"], a["stageTimestamp"]],
                      "metrics_server_sar_inside": [{"audit_id": x["auditID"], "received": x["requestReceivedTimestamp"],
                                                     "code": x["responseStatus"]["code"]} for x in inside]}))
