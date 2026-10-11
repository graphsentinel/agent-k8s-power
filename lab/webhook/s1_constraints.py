#!/usr/bin/env python3
"""PR-text prototype of KEP-5917's constraint authorizer, as a kube-apiserver authorization webhook.

This is a PROTOTYPE OF A PROPOSED DESIGN (kubernetes/enhancements#5918, head a346858, README as of 2026-09-09).
It is not Kubernetes behaviour. Rules followed (measurement contract R-1..R-10):

  R-1  only Deny or NoOpinion, never Allow
  R-3  constraints are JSON blobs in user extra KEY (lab key, DEC-04), type "Rule"
  R-4  rules are ORed; no rule allows -> Deny
  R-5  resourceNames ignored when the request has no name      (NAMES=pr)   | NAMES=rbac: no name -> no match
  R-6  resourceNamespaces ignored for cluster-scoped requests  (NSEMPTY=pr: empty namespace -> ignored)
                                                                | NSEMPTY=deny: empty namespace -> no match
  R-7  unparsable blobs ignored; no constraints -> NoOpinion   (PARSE=pr)   | PARSE=closed: any unparsable -> Deny
  R-8  impersonation attempts are evaluated like any action    (IMP=pr)     | IMP=hardfail: impersonate* -> Deny

Python standard library only. Logs one JSON line per SubjectAccessReview to stdout.
"""
import json
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ.get("CONSTRAINT_KEY", "s1.lab.example/constraints")
NAMES = os.environ.get("NAMES", "pr")
NSEMPTY = os.environ.get("NSEMPTY", "pr")
PARSE = os.environ.get("PARSE", "pr")
IMP = os.environ.get("IMP", "pr")
REASON = "s1-constraints: no authenticator constraint allowed this action"


def parse_constraints(blobs):
    """Returns (rules, unparsable_count)."""
    rules, bad = [], 0
    for b in blobs:
        try:
            c = json.loads(b)
            if c.get("type") != "Rule" or not isinstance(c.get("rule"), dict):
                raise ValueError("not a Rule")
            rules.append(c["rule"])
        except Exception:
            bad += 1
    return rules, bad


def _in(values, v):
    return "*" in values or v in values


def rule_matches(rule, spec):
    ra, nra = spec.get("resourceAttributes"), spec.get("nonResourceAttributes")
    if nra is not None:
        urls = rule.get("nonResourceURLs") or []
        path, verb = nra.get("path", ""), nra.get("verb", "")
        if not _in(rule.get("verbs") or [], verb):
            return False
        return any(u == path or (u.endswith("*") and path.startswith(u[:-1])) for u in urls)
    if ra is None or rule.get("nonResourceURLs"):
        return False
    group, verb = ra.get("group", ""), ra.get("verb", "")
    res = ra.get("resource", "")
    if ra.get("subresource"):
        res = f"{res}/{ra['subresource']}"
    ns, name = ra.get("namespace", ""), ra.get("name", "")
    if not _in(rule.get("apiGroups") or [], group):
        return False
    if not _in(rule.get("verbs") or [], verb):
        return False
    resources = rule.get("resources") or []
    sub = res.split("/", 1)[1] if "/" in res else None
    if not (_in(resources, res) or (sub and f"*/{sub}" in resources)):
        return False
    namespaces = rule.get("resourceNamespaces") or []
    if namespaces:
        if ns == "":
            if NSEMPTY != "pr":
                return False
        elif ns not in namespaces:
            return False
    names = rule.get("resourceNames") or []
    if names:
        if name == "":
            if NAMES != "pr":
                return False
        elif name not in names:
            return False
    return True


def decide(spec):
    blobs = (spec.get("extra") or {}).get(KEY) or []
    rules, bad = parse_constraints(blobs)
    ra = spec.get("resourceAttributes") or {}
    if IMP == "hardfail" and ra.get("verb", "").startswith("impersonate"):
        return "deny", "s1-constraints: impersonation is not allowed with authenticator constraints (hardfail)", rules, bad
    if bad and PARSE == "closed":
        return "deny", "s1-constraints: unparsable constraint (parse=closed)", rules, bad
    if not rules:
        return "noopinion", "no parsable constraints", rules, bad
    if any(rule_matches(r, spec) for r in rules):
        return "noopinion", "a constraint allows this action", rules, bad
    return "deny", REASON, rules, bad


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        sar = json.loads(self.rfile.read(n) or b"{}")
        spec = sar.get("spec", {})
        decision, reason, rules, bad = decide(spec)
        status = {"allowed": False}
        if decision == "deny":
            status.update({"denied": True, "reason": reason})
        else:
            status["reason"] = reason
        print(json.dumps({
            "ts": time.time(), "user": spec.get("user"), "groups": spec.get("groups"),
            "extra_keys": sorted((spec.get("extra") or {}).keys()),
            "resourceAttributes": spec.get("resourceAttributes"),
            "nonResourceAttributes": spec.get("nonResourceAttributes"),
            "rules": len(rules), "unparsable": bad, "decision": decision, "reason": reason,
            "switches": {"names": NAMES, "nsempty": NSEMPTY, "parse": PARSE, "imp": IMP},
        }), flush=True)
        body = json.dumps({"apiVersion": sar.get("apiVersion", "authorization.k8s.io/v1"),
                           "kind": "SubjectAccessReview", "status": status}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # health
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8443"))), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.environ.get("TLS_CERT", "/tls/tls.crt"), os.environ.get("TLS_KEY", "/tls/tls.key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(json.dumps({"start": True, "key": KEY, "switches": {"names": NAMES, "nsempty": NSEMPTY,
                                                               "parse": PARSE, "imp": IMP}}), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
