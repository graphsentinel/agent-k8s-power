#!/usr/bin/env python3
"""S1 test driver (measurement contract v0.2.x). Python standard library only; runs inside the cluster.

  python3 driver.py --placement M1 --run-id RUN --tests T0,PC,S [--role agent|thief] [--note TEXT]
  (stdin: optional JSON context {"deployer_token": ..., "copied": {...}})

Writes JSON lines to stdout: {"type": "req", ...} for every HTTP request (token shown as sha256 prefix only) and
{"type": "row", ...} for every TSV row. Verdicts: MATCH, DEVIATION, OBSERVED, UNATTRIBUTED, UNREACHABLE, 77.
"""
import argparse
import base64
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://kubernetes.default.svc"
KC = "https://keycloak.s1-idp.svc:8443/realms/s1/protocol/openid-connect/token"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
API_CTX = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
KC_CTX = ssl.create_default_context(cafile="/lab-ca/ca.pem")
ALICE = "oidc:alice"
DEPLOYER = "system:serviceaccount:team-a:deployer"
EXTRA_HDR = "Impersonate-Extra-s1.lab.example%2Fconstraints"
CM_A = "/api/v1/namespaces/team-a/configmaps/app-config"
SECRET = "/api/v1/namespaces/team-a/secrets/db-pass"
WIDE = json.dumps({"apiVersion": "authentication.k8s.io/v1alpha1", "kind": "AuthenticationConstraint",
                   "type": "Rule", "rule": {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}},
                  separators=(",", ":"))

A = None          # parsed args
CTX = {}          # stdin context
OUT = []          # emitted rows (for the control gate)
CONTROLS_OK = True
CONTROL_FAIL = []


def emit(obj):
    print(json.dumps(obj), flush=True)


def h(tok):
    return hashlib.sha256(tok.encode()).hexdigest()[:12] if tok else None


def claims(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        c = json.loads(base64.urlsafe_b64decode(p))
        return {k: c.get(k) for k in ("iss", "sub", "aud", "preferred_username", "exp", "iat", "k8s_constraints")
                if k in c}
    except Exception:
        return None


# ---------------------------------------------------------------- credentials
def sa_token():
    return open(f"{SA_DIR}/token").read().strip()


def jwt(scope="", client="coding-agent"):
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": client, "username": "alice",
                                   "password": "alice-lab-pw", "scope": ("openid " + scope).strip()}).encode()
    with urllib.request.urlopen(urllib.request.Request(KC, data), context=KC_CTX) as r:
        return json.load(r)["access_token"]


class Cred:
    def __init__(self, label, token, imp=None, extra=None):
        self.label, self.token, self.imp, self.extra = label, token, imp, dict(extra or {})

    def with_imp(self, user, extra=None):
        return Cred(f"{self.label}+imp({user})", self.token, user, extra)


def agent_cred(scope="task-read-app-config"):
    """The agent's credential for this placement, as it would send the task request."""
    p = A.placement
    if p == "M0":
        return Cred("agent-sa", sa_token())
    if p in ("M1", "M1-L"):
        return Cred("agent-sa", sa_token(), ALICE)
    if p in ("M2", "M3"):
        return Cred(f"alice-jwt[{scope}]", jwt(scope))
    raise SystemExit(f"unknown placement {p}")


def alice_unconstrained():
    return Cred("alice-jwt[none]", jwt(""))


def deployer():
    return Cred("deployer-sa", CTX["deployer_token"])


# ---------------------------------------------------------------- HTTP
def call(test, cred, method, path, body=None, ctype="application/json", stream_s=None):
    headers = {"User-Agent": f"s1-driver/{A.run_id}/{test}", "Accept": "application/json"}
    if cred and cred.token:
        headers["Authorization"] = f"Bearer {cred.token}"
    if cred and cred.imp:
        headers["Impersonate-User"] = cred.imp
    if cred:
        headers.update(cred.extra)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        # PATCH bodies are merge patches, also when re-sent as a U-control
        headers["Content-Type"] = "application/merge-patch+json" if method == "PATCH" else ctype
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    t0 = time.time()
    status, raw, audit_id = None, b"", None
    try:
        with urllib.request.urlopen(req, context=API_CTX, timeout=stream_s or 15) as r:
            status, audit_id = r.status, r.headers.get("Audit-Id")
            raw = r.read(4096) if stream_s else r.read()
    except urllib.error.HTTPError as e:
        status, audit_id, raw = e.code, e.headers.get("Audit-Id"), e.read()
    except TimeoutError:
        status = status or -1
    except Exception as e:  # network or TLS: not a result
        status, raw = -1, repr(e).encode()
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    msg = parsed.get("message", "") if isinstance(parsed, dict) else raw[:300].decode(errors="replace")
    # never store bearer tokens: TokenRequest responses carry status.token (publication prep, G-7)
    raw_txt = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                     lambda m: f"<jwt sha256:{hashlib.sha256(m.group(0).encode()).hexdigest()[:12]}>",
                     raw[:4096].decode(errors="replace"))
    rec = {"type": "req", "run_id": A.run_id, "placement": A.placement, "test": test, "cred": cred.label if cred else None,
           "token_sha256_12": h(cred.token) if cred else None, "imp": cred.imp if cred else None,
           "extra_hdrs": list(cred.extra) if cred else [], "method": method, "path": path, "status": status,
           "audit_id": audit_id, "latency_ms": round((time.time() - t0) * 1000, 1), "message": msg[:500],
           "body": raw_txt}
    emit(rec)
    return {"status": status, "json": parsed, "msg": msg, "audit_id": audit_id, "method": method, "path": path}


def allowed(r):
    s = r["status"]
    if s and 200 <= s < 300:
        return True
    # contract §4a B-3: pods/exec without an upgrade → 400 "Upgrade request required" means authorization passed
    # (PoC verification 2026-10-08: restricted to the exec subresource and the exact message)
    if s == 400 and (r.get("path") or "").split("?")[0].endswith("/exec") and r["msg"].startswith("Upgrade request required"):
        return True
    return False


def attribution(r):
    m = r["msg"]
    if r["status"] != 403:
        return "-"
    # the webhook's Deny reasons; a NoOpinion reason ("a constraint allows this action") can be appended to an RBAC denial
    if "s1-constraints" in m and ("no authenticator constraint" in m or "hardfail" in m or "unparsable" in m):
        return "webhook"
    if "cannot impersonate" in m:
        return "impersonation-check"
    mu = re.search(r'is forbidden: User "([^"]*)"', m)
    if mu:  # (PoC verification 2026-10-08: no IndexError when the quote is missing)
        return f"rbac({mu.group(1)})"
    return "unknown"


def obs(r):
    return "allowed" if allowed(r) else str(r["status"])


# ---------------------------------------------------------------- rows
def row(test, kind, expected, r, verdict, attr="-", u="-", detail=""):
    global CONTROLS_OK
    if test in ("T0", "T0-B", "PC-1", "PC-2", "PC-3") and verdict not in ("MATCH",):
        CONTROLS_OK = False
        CONTROL_FAIL.append(test)
    rec = {"type": "row", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "run_id": A.run_id,
           "config": A.config, "placement": A.placement, "variant": A.variant or "-", "test": test, "kind": kind,
           "verdict": verdict, "expected": expected, "observed": obs(r) if isinstance(r, dict) else r,
           "attribution": attr, "u_control": u, "detail": detail.replace("\t", " ").replace("\n", " ")}
    OUT.append(rec)
    emit(rec)


def expect_allowed(test, kind, r, detail=""):
    row(test, kind, "allowed", r, "MATCH" if allowed(r) else "DEVIATION", attribution(r), "-", detail or r["msg"][:160])


def expect_status(test, kind, r, code, detail=""):
    row(test, kind, str(code), r, "MATCH" if r["status"] == code else "DEVIATION", attribution(r), "-",
        detail or r["msg"][:160])


def expect_denied(test, kind, r, attrs, u_cred, method, path, body=None, detail=""):
    """Negative test with U-control: the same request with the unconstrained credential of the effective identity."""
    ur = call(test + ":U", u_cred, method, path, body)
    u = f"{u_cred.label}:{obs(ur)}"
    a = attribution(r)
    if not allowed(ur):
        v = "UNREACHABLE"
    elif allowed(r):
        v = "DEVIATION"
    elif a in attrs or any(a.startswith(x) for x in attrs):
        v = "MATCH"
    else:
        v = "UNATTRIBUTED"
    row(test, kind, f"denied[{'|'.join(attrs)}]", r, v, a, u, detail or r["msg"][:160])


def observe(test, kind, r, u_cred=None, method=None, path=None, body=None, detail=""):
    u = "-"
    if u_cred:
        ur = call(test + ":U", u_cred, method, path, body)
        u = f"{u_cred.label}:{obs(ur)}"
    row(test, kind, "none", r, "OBSERVED", attribution(r), u, detail or r["msg"][:160])


# ---------------------------------------------------------------- tests
def neg_attr():
    return {"M1": ["impersonation-check"], "M1-L": ["impersonation-check"], "M2": ["webhook"],
            "M3": ["webhook"]}.get(A.placement, [])


def t_controls():
    c = agent_cred()
    expect_allowed("T0", "control", call("T0", c, "GET", CM_A))
    expect_status("PC-1", "control", call("PC-1", Cred("none", None), "GET", CM_A), 401)
    if A.placement in ("M2", "M3"):
        bad = c.token[:-6] + ("AAAAAA" if not c.token.endswith("AAAAAA") else "BBBBBB")
        expect_status("PC-2", "control", call("PC-2", Cred("jwt-bad-signature", bad), "GET", CM_A), 401)
        r = call("PC-3", c, "GET", SECRET)
        row("PC-3", "control", "denied[webhook]", r, "MATCH" if attribution(r) == "webhook" else "DEVIATION",
            attribution(r), "-", r["msg"][:160])
    else:
        expect_status("PC-2", "control", call("PC-2", Cred("garbage", "garbage.token.value"), "GET", CM_A), 401)
        if A.placement in ("M1", "M1-L"):
            r = call("PC-3", Cred("agent-sa", sa_token()), "GET", CM_A)
            row("PC-3", "control", "denied[rbac(agent)]", r,
                "MATCH" if r["status"] == 403 and attribution(r).startswith("rbac(system:serviceaccount:agents") else "DEVIATION",
                attribution(r), "-", r["msg"][:160])


def scope_tests(c, u, kind="mechanism", names=("S-a", "S-b", "S-c", "S-d", "S-e", "S-f1", "S-f2", "S-g")):
    reqs = {
        "S-a": ("GET", "/api/v1/namespaces/team-a/configmaps/db-config", None),
        "S-b": ("GET", SECRET, None),
        "S-c": ("PATCH", CM_A + "?dryRun=All", {"metadata": {"labels": {"s1-run": A.run_id[:40].lower().replace(":", "")}}}),
        "S-d": ("GET", "/api/v1/namespaces/team-b/configmaps/app-config", None),
        "S-e": ("GET", "/api/v1/namespaces/team-a/configmaps", None),
        "S-f1": ("GET", "/api/v1/namespaces/team-a/configmaps?watch=1&timeoutSeconds=1", None),
        "S-f2": ("GET", "/api/v1/namespaces/team-a/configmaps?watch=1&timeoutSeconds=1&fieldSelector=metadata.name%3Dapp-config", None),
        "S-g": ("GET", "/api/v1/configmaps", None),
    }
    for t in names:
        m, p, b = reqs[t]
        r = call(t, c, m, p, b) if m != "PATCH" else call_patch(t, c, p, b)
        if A.placement in ("M0", "M1-L"):
            observe(t, kind, r)
        else:
            expect_denied(t, kind, r, neg_attr(), u, m, p, b)


def call_patch(test, cred, path, body):
    # merge patch
    headers_ct = "application/merge-patch+json"
    return call(test, cred, "PATCH", path, body, ctype=headers_ct)


def t_scope():
    scope_tests(agent_cred(), alice_unconstrained())


def t_w1_m1():
    # variant w1a or w1b is applied by the runner; the agent impersonates alice
    c = agent_cred()
    lst = "/api/v1/namespaces/team-a/configmaps"
    flt = lst + "?fieldSelector=metadata.name%3Dapp-config"
    if A.variant == "w1a":
        for t, p in (("W1-M1a-list", lst), ("W1-M1a-list-named", flt)):
            expect_denied(t, "mechanism", call(t, c, "GET", p), ["impersonation-check"], alice_unconstrained(), "GET", p)
    elif A.variant == "w1b":
        observe("W1-M1b-imp-list", "configuration", call("W1-M1b-imp-list", c, "GET", lst))
        observe("W1-M1b-direct-list", "configuration", call("W1-M1b-direct-list", Cred("agent-sa", sa_token()), "GET", lst))
        observe("W1-M1b-direct-update", "configuration",
                call_patch("W1-M1b-direct-update", Cred("agent-sa", sa_token()), CM_A + "?dryRun=All",
                           {"metadata": {"labels": {"s1": "w1b"}}}))


def t_g1():
    observe("G1-direct-get", "configuration",
            call("G1-direct-get", Cred("agent-sa", sa_token()), "GET", "/api/v1/namespaces/team-a/configmaps/db-config"))


def t_w1_m2():
    c = agent_cred("task-read-app-config-glw")
    for t, p in (("W1-M2-list", "/api/v1/namespaces/team-a/configmaps"),
                 ("W1-M2-watch-named", "/api/v1/namespaces/team-a/configmaps?watch=1&timeoutSeconds=1&fieldSelector=metadata.name%3Dapp-config"),
                 ("W1-M2-list-allns", "/api/v1/configmaps"),
                 ("W1-M2-get-other", "/api/v1/namespaces/team-a/configmaps/db-config")):
        r = call(t, c, "GET", p)
        body = r["json"] if isinstance(r["json"], dict) else {}
        names = [i["metadata"]["namespace"] + "/" + i["metadata"]["name"] for i in body.get("items", [])][:20]
        observe(t, "design-reading", r, alice_unconstrained(), "GET", p, detail=f"items={names}" if names else "")


def t_i1():
    p = A.placement
    if p in ("M0", "M1", "M1-L"):
        base = Cred("agent-sa", sa_token())
        r = call("I1-a", base.with_imp(DEPLOYER), "GET", SECRET)
        if p == "M1":
            expect_denied("I1-a", "mechanism", r, ["impersonation-check"], deployer(), "GET", SECRET)
        else:
            observe("I1-a", "configuration" if p == "M1-L" else "mechanism", r, deployer(), "GET", SECRET)
        if p != "M0":
            r = call("I1-b", base.with_imp(ALICE), "GET", SECRET)
            if p == "M1":
                expect_denied("I1-b", "mechanism", r, ["impersonation-check"], alice_unconstrained(), "GET", SECRET)
            else:
                observe("I1-b", "configuration", r, alice_unconstrained(), "GET", SECRET)
    elif p == "M3":
        c = agent_cred()
        expect_denied("I1-a", "design-reading", call("I1-a", c.with_imp(DEPLOYER), "GET", SECRET), ["webhook"],
                      deployer(), "GET", SECRET)
        # I1-b needs alice to be allowed to impersonate herself (variant i3alice); otherwise UNREACHABLE is correct
        u = Cred("alice-jwt[none]+imp(alice)", jwt(""), ALICE)
        expect_denied("I1-b", "design-reading", call("I1-b", c.with_imp(ALICE), "GET", SECRET), ["webhook"],
                      u, "GET", SECRET)
        # I1-d: a constraint that allows impersonating SAs
        d = agent_cred("task-allow-impersonate-sa")
        r = call("I1-d", d.with_imp(DEPLOYER), "GET", SECRET)
        observe("I1-d", "design-reading", r, deployer(), "GET", SECRET)


def t_i2():
    p = A.placement
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 600}}
    path = "/api/v1/namespaces/team-a/serviceaccounts/deployer/token"
    c = agent_cred()
    r = call("I2-issue", c, "POST", path, body)
    if p in ("M0", "M1-L"):
        observe("I2-issue", "mechanism" if p == "M0" else "configuration", r, alice_unconstrained(), "POST", path, body)
    else:
        expect_denied("I2-issue", "mechanism", r, neg_attr(), alice_unconstrained(), "POST", path, body)
    minted = (r["json"] or {}).get("status", {}).get("token") if allowed(r) else None
    if minted:
        observe("I2-use", "mechanism", call("I2-use", Cred("minted-deployer", minted), "GET", SECRET),
                detail="minted token used to read team-a/db-pass")
    else:
        row("I2-use", "mechanism", "none", "not-reached", "OBSERVED", "-", "-", "no token was issued")


def t_i3():
    p = A.placement
    hdr = {EXTRA_HDR: WIDE}
    if p == "M1-L":
        base = Cred("agent-sa", sa_token())
        observe("I3-wide", "configuration", call("I3-wide", base.with_imp(ALICE, hdr), "GET", SECRET),
                alice_unconstrained(), "GET", SECRET)
    elif p == "M3":
        c = agent_cred()
        u = Cred("alice-jwt[none]+imp(alice)", jwt(""), ALICE)
        expect_denied("I3-wide", "design-reading", call("I3-wide", c.with_imp(ALICE, hdr), "GET", SECRET), ["webhook"],
                      u, "GET", SECRET)
        expect_denied("I3-omit", "design-reading", call("I3-omit", c.with_imp(ALICE), "GET", SECRET), ["webhook"],
                      u, "GET", SECRET)


def t_i4():
    p = A.placement
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "s1-i4", "namespace": "team-a"},
           "spec": {"serviceAccountName": "deployer",
                    "containers": [{"name": "c", "image": "docker.io/library/python:3.12-slim",
                                    "imagePullPolicy": "Never", "command": ["sleep", "60"]}]}}
    path_a = "/api/v1/namespaces/team-a/pods?dryRun=All"
    path_b = "/api/v1/namespaces/team-a/pods/toolbox/exec?command=id&stdout=true"
    c = agent_cred()
    for t, m, path, body in (("I4-a", "POST", path_a, pod), ("I4-b", "POST", path_b, None)):
        r = call(t, c, m, path, body)
        if p in ("M0", "M1-L"):
            observe(t, "mechanism" if p == "M0" else "configuration", r, alice_unconstrained(), m, path, body)
        else:
            expect_denied(t, "mechanism", r, neg_attr(), alice_unconstrained(), m, path, body)


def t_a1():
    p = A.placement
    pa = "/apis/metrics.k8s.io/v1beta1/namespaces/team-a/pods"
    pb = "/apis/metrics.k8s.io/v1beta1/namespaces/team-b/pods"
    c = agent_cred()
    r = call("A1-a", c, "GET", pa)
    if p in ("M0", "M1-L"):
        observe("A1-a", "mechanism", r, alice_unconstrained(), "GET", pa)
    else:
        expect_denied("A1-a", "mechanism", r, neg_attr(), alice_unconstrained(), "GET", pa)
    if p == "M2":
        m = agent_cred("task-metrics-team-a")
        time.sleep(1)  # isolate the webhook window of this one request (collect.py counts SARs inside it)
        t0 = time.time()
        r = call("A1-b-team-a", m, "GET", pa)
        t1 = time.time()
        time.sleep(1)
        row("A1-b-team-a", "design-reading", "allowed", r, "MATCH" if allowed(r) else "DEVIATION", attribution(r),
            "-", f"window={t0:.3f}-{t1:.3f} {r['msg'][:120]}")
        expect_denied("A1-b-team-b", "design-reading", call("A1-b-team-b", m, "GET", pb), ["webhook"],
                      alice_unconstrained(), "GET", pb)


def t_r1():
    """Runs in the THIEF pod with a copy of the agent's credential (from stdin context)."""
    cp = CTX["copied"]
    own = Cred("thief-sa", sa_token())
    expect_allowed("T0-B", "control", call("T0-B", own, "GET", "/api/v1/namespaces/thief/configmaps/own"))
    c = Cred("copied:" + cp["label"], cp["token"], cp.get("imp"))
    cl = claims(cp["token"]) or {}
    life = (cl.get("exp") or 0) - (cl.get("iat") or 0)
    observe("R1-task", "mechanism", call("R1-task", c, "GET", CM_A), detail=f"exp-iat={life}s")
    observe("R1-secret", "mechanism", call("R1-secret", c, "GET", SECRET), detail=f"exp-iat={life}s")


def t_r1_exp():
    c = Cred("alice-jwt-short[task]", jwt("task-read-app-config", "coding-agent-short"))
    cl = claims(c.token)
    expect_allowed("R1-exp-before", "mechanism", call("R1-exp-before", c, "GET", CM_A),
                   detail=f"exp-iat={cl['exp'] - cl['iat']}s")
    wait = cl["exp"] + 15 - time.time()
    if wait > 0:
        time.sleep(wait)
    expect_status("R1-exp-after", "mechanism", call("R1-exp-after", c, "GET", CM_A), 401,
                  detail=f"sent at exp+{time.time() - cl['exp']:.0f}s")


def t_d1():
    r = call("D1-open", Cred("alice-jwt[none]", jwt("")), "GET", SECRET)
    observe("D1-open", "configuration", r, detail="same client, task scope not requested")
    expect_status("D1-aud", "configuration", call("D1-aud", Cred("alice-jwt[aud-k8s-agents]", jwt("aud-k8s-agents")),
                                                  "GET", CM_A), 401)
    expect_allowed("D1-aud-pos", "control",
                   call("D1-aud-pos", Cred("alice-jwt[aud-k8s-agents+task]", jwt("aud-k8s-agents task-read-app-config")),
                        "GET", CM_A))


def t_x1():
    c = Cred("alice-jwt[task-malformed]", jwt("task-malformed"))
    observe("X1", "design-reading", call("X1", c, "GET", SECRET), alice_unconstrained(), "GET", SECRET)


def ssar(test, cred, ns, verb, resource, name):
    body = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": {"namespace": ns, "verb": verb, "resource": resource, "name": name}}}
    r = call(test, cred, "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", body)
    rep = (r["json"] or {}).get("status", {}).get("allowed") if allowed(r) else None
    return r, rep


def t_c1():
    p = A.placement
    tag = "-x" if A.variant in ("c1x",) or A.scope_override else ""
    creds = [("", agent_cred(A.scope_override or "task-read-app-config"))]
    if p in ("M1", "M1-L"):
        creds = [("-self", Cred("agent-sa", sa_token())), ("-imp", agent_cred())]
    actual_c = agent_cred(A.scope_override or "task-read-app-config")
    act_task = allowed(call("C1-actual-task", actual_c, "GET", CM_A))
    act_sec = allowed(call("C1-actual-secret", actual_c, "GET", SECRET))
    for suffix, c in creds:
        for t, ns, res, name, act in (("C1-a", "team-a", "configmaps", "app-config", act_task),
                                      ("C1-b", "team-a", "secrets", "db-pass", act_sec)):
            test = f"{t}{tag}{suffix}"
            r, rep = ssar(test, c, ns, "get", res, name)
            if rep is None:
                d = "cannot-ask"
            else:
                d = "drift" if rep != act else "consistent"
            row(test, "mechanism", "none", r, "OBSERVED", attribution(r), "-",
                f"{d}: reported={rep} actual={act}")
        test = f"C1-c{tag}{suffix}"
        body = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": "team-a"}}
        r = call(test, c, "POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", body)
        if allowed(r):
            rules = (r["json"] or {}).get("status", {}).get("resourceRules", [])
            sec = any(("secrets" in x.get("resources", []) or "*" in x.get("resources", [])) and
                      ("get" in x.get("verbs", []) or "*" in x.get("verbs", [])) for x in rules)
            d = f"rules-say-secrets-get={sec} actual={act_sec} incomplete={(r['json'] or {}).get('status', {}).get('incomplete')}"
        else:
            d = "cannot-ask"
        row(test, "mechanism", "none", r, "OBSERVED", attribution(r), "-", d)


# ---------------------------------------------------------------- V-tests (contract §4b): after revocation
import threading

WATCH = "/api/v1/namespaces/team-a/configmaps?watch=1&fieldSelector=metadata.name%3Dapp-config&timeoutSeconds="


class Watcher(threading.Thread):
    """Reads one watch stream; records (time, type, label s1v) for every event and when the stream ends."""

    def __init__(self, test, cred, timeout_s):
        super().__init__(daemon=True)
        self.test, self.cred, self.timeout_s = test, cred, timeout_s
        self.events, self.closed_at, self.status, self.error = [], None, None, None

    def run(self):
        headers = {"User-Agent": f"s1-driver/{A.run_id}/{self.test}-watch", "Authorization": f"Bearer {self.cred.token}"}
        if self.cred.imp:
            headers["Impersonate-User"] = self.cred.imp
        req = urllib.request.Request(API + WATCH + str(self.timeout_s), headers=headers)
        try:
            with urllib.request.urlopen(req, context=API_CTX, timeout=self.timeout_s + 30) as r:
                self.status = r.status
                for line in r:
                    try:
                        ev = json.loads(line)
                        lab = ((ev.get("object") or {}).get("metadata") or {}).get("labels") or {}
                        self.events.append((time.time(), ev.get("type"), lab.get("s1v")))
                    except Exception:
                        pass
        except urllib.error.HTTPError as e:
            self.status, self.error = e.code, e.read()[:200].decode(errors="replace")
        except Exception as e:
            self.error = repr(e)[:200]
        self.closed_at = time.time()

    def first(self, mark):
        for t, typ, lab in self.events:
            if typ == "MODIFIED" and lab and lab.startswith(mark):
                return t
        return None


def ready(t0, **extra):
    emit(dict({"type": "ready", "t": t0}, **extra))


def until(t0, offset):
    d = t0 + offset - time.time()
    if d > 0:
        time.sleep(d)


def v_rows(prefix, w, t0, new_req, new_expect, post_mark, end_offset, detail=""):
    pre = w.first("pre")
    row(f"{prefix}-pre", "control", "event", "seen" if pre else "missing", "MATCH" if pre else "DEVIATION", "-", "-",
        f"stream status={w.status} err={w.error}")
    ok = (allowed(new_req) if new_expect == "allowed" else new_req["status"] == new_expect)
    row(f"{prefix}-new-request", "control", str(new_expect), new_req, "MATCH" if ok else "DEVIATION",
        attribution(new_req), "-", new_req["msg"][:140])
    post = w.first(post_mark)
    row(f"{prefix}-post", "mechanism", "none", "seen" if post else "not-seen", "OBSERVED", "-", "-",
        (f"post event at ready+{post - t0:.1f}s; " if post else "") + detail)
    row(f"{prefix}-stream", "mechanism", "none", "open" if w.closed_at is None else "closed", "OBSERVED", "-", "-",
        f"closed at ready+{w.closed_at - t0:.1f}s" if w.closed_at else f"still open at ready+{end_offset}s")


def t_v1():
    c = agent_cred("task-read-app-config-glw")
    w = Watcher("V1", c, 60)
    w.start()
    time.sleep(1.5)
    t0 = time.time()
    ready(t0)
    until(t0, 9)
    r = call("V1-new-request", c, "GET", CM_A)
    until(t0, 20)
    v_rows("V1", w, t0, r, 403, "post", 20, "revocation at ready+6, post patch at ready+11")


def t_v2():
    c = Cred("alice-jwt-short[glw]", jwt("task-read-app-config-glw", "coding-agent-short"))
    cl = claims(c.token)
    w = Watcher("V2", c, 150)
    w.start()
    time.sleep(1.5)
    t0 = time.time()
    ready(t0, exp=cl["exp"])
    until(t0, max(cl["exp"] + 15 - t0, 3))
    r = call("V2-new-request", c, "GET", CM_A)
    until(t0, 95)
    v_rows("V2", w, t0, r, 401, "post", 95, f"token exp at ready+{cl['exp'] - t0:.1f}s, post patch at ready+80")


def t_v3a():
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 600}}
    me = Cred("agent-sa", sa_token())
    r = call("V3a-mint", me, "POST", "/api/v1/namespaces/team-a/serviceaccounts/deployer/token", body)
    minted = (r["json"] or {}).get("status", {}).get("token") if allowed(r) else None
    expect_allowed("V3a-mint", "control", r)
    t0 = time.time()
    ready(t0)
    until(t0, 6)
    own = call("V3a-own-after-revoke", me, "GET", CM_A)
    row("V3a-own-after-revoke", "control", "403", own, "MATCH" if own["status"] == 403 else "DEVIATION",
        attribution(own), "-", own["msg"][:140])
    if minted:
        observe("V3a-minted-use", "mechanism", call("V3a-minted-use", Cred("minted-deployer", minted), "GET", SECRET),
                detail="token minted before the minter's bindings were deleted")


def t_v3b():
    tmp = Cred("tmp-sa-token", CTX["tmp_token"])
    expect_allowed("V3b-before", "control", call("V3b-before", tmp, "GET", CM_A))
    t0 = time.time()
    ready(t0)
    # apiserver caches successful token authentications (TokenSuccessCacheTTL, default 10 s): ask at +3, +12, +27 s
    for off in (6, 15, 30):
        until(t0, off)
        observe(f"V3b-after-delete-{off - 3}s", "mechanism", call(f"V3b-after-delete-{off - 3}s", tmp, "GET", CM_A),
                detail=f"ServiceAccount deleted at ready+3; request at ready+{off}; token exp 600 s")


TESTS = {"CTRL": t_controls, "S": t_scope, "W1M1": t_w1_m1, "G1": t_g1, "W1M2": t_w1_m2, "I1": t_i1, "I2": t_i2,
         "I3": t_i3, "I4": t_i4, "A1": t_a1, "R1": t_r1, "R1EXP": t_r1_exp, "D1": t_d1, "X1": t_x1, "C1": t_c1,
         "V1": t_v1, "V2": t_v2, "V3A": t_v3a, "V3B": t_v3b}


def main():
    global A, CTX
    ap = argparse.ArgumentParser()
    ap.add_argument("--placement", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--config", default="c1")
    ap.add_argument("--tests", required=True)
    ap.add_argument("--variant", default="")
    ap.add_argument("--scope-override", default="")
    ap.add_argument("--print-agent-cred", action="store_true")
    A = ap.parse_args()
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        CTX = json.loads(raw) if raw else {}
    if A.print_agent_cred:
        c = agent_cred()
        emit({"type": "cred", "label": c.label, "token": c.token, "imp": c.imp})
        return
    for t in A.tests.split(","):
        try:
            TESTS[t]()
        except Exception as e:
            emit({"type": "row", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "run_id": A.run_id,
                  "config": A.config, "placement": A.placement, "variant": A.variant or "-", "test": t,
                  "kind": "setup", "verdict": "77", "expected": "-", "observed": "error", "attribution": "-",
                  "u_control": "-", "detail": f"driver exception: {e!r}"[:300]})
    emit({"type": "end", "controls_ok": CONTROLS_OK, "control_fail": CONTROL_FAIL})


if __name__ == "__main__":
    main()
