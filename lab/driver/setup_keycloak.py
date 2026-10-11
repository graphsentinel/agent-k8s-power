#!/usr/bin/env python3
"""Creates the task client scopes of realm s1 through the Keycloak admin REST API (idempotent).

Each task scope adds a hardcoded JSON claim `k8s_constraints` (a list of AuthenticationConstraint blobs in the shape
of the KEP-5917 PR text) and is attached as an OPTIONAL scope to coding-agent and coding-agent-short, so a token
carries a constraint only when the scope is requested (D1-open measures that). Scope `aud-k8s-agents` adds the
audience k8s-agents (D1-aud). Python standard library only; run inside the cluster.
"""
import json
import ssl
import urllib.parse
import urllib.request

KC = "https://keycloak.s1-idp.svc:8443"
CTX = ssl.create_default_context(cafile="/lab-ca/ca.pem")


def rule(**r):
    return json.dumps({"apiVersion": "authentication.k8s.io/v1alpha1", "kind": "AuthenticationConstraint",
                       "type": "Rule", "rule": r}, separators=(",", ":"))


TASK = rule(apiGroups=[""], resources=["configmaps"], verbs=["get"], resourceNamespaces=["team-a"],
            resourceNames=["app-config"])
SCOPES = {
    "task-read-app-config": [TASK],
    # W1-M2, S-f(ii), R1-stream: get/list/watch, still name-restricted
    "task-read-app-config-glw": [rule(apiGroups=[""], resources=["configmaps"], verbs=["get", "list", "watch"],
                                      resourceNamespaces=["team-a"], resourceNames=["app-config"])],
    # A1-b
    "task-metrics-team-a": [TASK, rule(apiGroups=["metrics.k8s.io"], resources=["pods"], verbs=["get", "list"],
                                       resourceNamespaces=["team-a"])],
    # I1-d: a badly designed token that also allows impersonating service accounts in team-a
    "task-allow-impersonate-sa": [TASK, rule(apiGroups=["", "authentication.k8s.io"], resources=["serviceaccounts"],
                                             verbs=["impersonate", "impersonate:serviceaccount"],
                                             resourceNamespaces=["team-a"])],
    # C1-x
    "task-introspect": [TASK, rule(apiGroups=["authorization.k8s.io"],
                                   resources=["selfsubjectaccessreviews", "selfsubjectrulesreviews"],
                                   verbs=["create"])],
    # X1
    "task-malformed": ['{"apiVersion":"authentication.k8s.io/v1alpha1","kind":"AuthenticationConstraint",'
                       '"type":"Rule","rule":{"apiGroups":[""],'],
}


def call(method, path, token=None, data=None, form=False):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(KC + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def main():
    _, tok = call("POST", "/realms/master/protocol/openid-connect/token",
                  data={"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                        "password": "admin-lab-pw"}, form=True)
    at = tok["access_token"]
    _, existing = call("GET", "/admin/realms/s1/client-scopes", at)
    ids = {s["name"]: s["id"] for s in existing}

    def ensure_scope(name, mappers):
        if name not in ids:
            st, _ = call("POST", "/admin/realms/s1/client-scopes", at,
                         {"name": name, "protocol": "openid-connect",
                          "attributes": {"include.in.token.scope": "true"}, "protocolMappers": mappers})
            assert st == 201, (name, st)
        _, all_ = call("GET", "/admin/realms/s1/client-scopes", at)
        ids.update({s["name"]: s["id"] for s in all_})

    for name, blobs in SCOPES.items():
        ensure_scope(name, [{"name": "k8s-constraints", "protocol": "openid-connect",
                             "protocolMapper": "oidc-hardcoded-claim-mapper",
                             "config": {"claim.name": "k8s_constraints", "claim.value": json.dumps(blobs),
                                        "jsonType.label": "JSON", "access.token.claim": "true",
                                        "id.token.claim": "false", "userinfo.token.claim": "false"}}])
    ensure_scope("aud-k8s-agents", [{"name": "aud-k8s-agents", "protocol": "openid-connect",
                                     "protocolMapper": "oidc-audience-mapper",
                                     "config": {"included.custom.audience": "k8s-agents",
                                                "access.token.claim": "true", "id.token.claim": "false"}}])
    _, clients = call("GET", "/admin/realms/s1/clients", at)
    for c in clients:
        if c["clientId"] in ("coding-agent", "coding-agent-short"):
            for name in list(SCOPES) + ["aud-k8s-agents"]:
                st, _ = call("PUT", f"/admin/realms/s1/clients/{c['id']}/optional-client-scopes/{ids[name]}", at)
                assert st in (204, 409), (c["clientId"], name, st)
    print(json.dumps({"scopes": sorted(list(SCOPES) + ["aud-k8s-agents"])}))


if __name__ == "__main__":
    main()
