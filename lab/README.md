# Lab: an agent's Kubernetes power (k3d `s1-agent-power`)

| Path | What |
|---|---|
| `k3s/gen-config.sh` | generates the kube-apiserver files mounted at `/etc/s1`: structured authentication (Keycloak JWT → `oidc:<user>`, extra `s1.lab.example/constraints`), authorization (our webhook first, then Node, RBAC), webhook kubeconfig, audit policy |
| `tls/` | lab-only CA and server certificates (Keycloak, webhook) |
| `webhook/s1_constraints.py` | **PR-text prototype** of the KEP-5917 constraint authorizer (PR #5918 head a346858); switches `NAMES`, `NSEMPTY`, `PARSE`, `IMP` |
| `driver/driver.py` | test driver, Python standard library only; one JSON line per request and per TSV row |
| `driver/setup_keycloak.py` | creates the task client scopes (`k8s_constraints` claim) through the Keycloak admin API |
| `k8s/` | namespaces, objects under test, base RBAC, Keycloak 26.8.0, webhook, placements `30-m0`, `31-m1`, `32-m1l`, variants `40..45` |
| `run-placement.sh` | one run of one placement → `evidence/<run>/`, rows → `results/measurements.tsv` |
| `collect.py` | evidence files, control gate (77), A1-b propagation row |

## Cluster from scratch

```bash
lab/tls/gen.sh            # lab-only CA + server certs (keys are not in the repository)
lab/k3s/gen-config.sh
L=$PWD/lab; mkdir -p $L/.runtime/apiserver-logs
k3d cluster create s1-agent-power --image docker.io/rancher/k3s:v1.37.1-k3s1 --servers 1 --agents 1 \
  --k3s-arg '--disable=traefik@server:0' \
  -v "$L/k3s:/etc/s1@server:0" -v "$L/.runtime/apiserver-logs:/var/log/s1@server:0" \
  --host-alias '10.43.200.10:keycloak.s1-idp.svc' \
  --k3s-arg '--kube-apiserver-arg=authentication-config=/etc/s1/authn.yaml@server:0' \
  --k3s-arg '--kube-apiserver-arg=authorization-config=/etc/s1/authz.yaml@server:0' \
  --k3s-arg '--kube-apiserver-arg=audit-policy-file=/etc/s1/audit-policy.yaml@server:0' \
  --k3s-arg '--kube-apiserver-arg=audit-log-path=/var/log/s1/audit.log@server:0' \
  --k3s-arg '--kube-apiserver-arg=audit-log-maxsize=500@server:0'
# images: podman save → k3d image import (quay.io/keycloak/keycloak:26.8.0, docker.io/library/python:3.12-slim)
K="kubectl --context k3d-s1-agent-power"
$K apply -f lab/k8s/00-namespaces.yaml
$K -n s1-idp create secret tls keycloak-tls --cert=lab/tls/keycloak.pem --key=lab/tls/keycloak.key
$K -n s1-authz create secret tls webhook-tls --cert=lab/tls/webhook.pem --key=lab/tls/webhook.key
$K -n s1-idp create configmap realm-s1 --from-file=s1.json=lab/k8s/realm-s1.json
$K -n s1-authz create configmap s1-authz-code --from-file=lab/webhook/s1_constraints.py
for ns in agents thief; do $K -n $ns create configmap lab-ca --from-file=ca.pem=lab/tls/ca.pem; done
$K apply -f lab/k8s/05-workload.yaml -f lab/k8s/06-rbac-base.yaml -f lab/k8s/10-keycloak.yaml -f lab/k8s/20-webhook.yaml
$K -n agents cp lab/driver/setup_keycloak.py driver:/setup_keycloak.py && $K -n agents exec driver -- python3 /setup_keycloak.py
```

The fixed ClusterIPs (Keycloak 10.43.200.10, webhook 10.43.200.20) and `--host-alias` exist because kube-apiserver in
the k3d server container does not use cluster DNS. k3d runs on the docker engine here; images are built and saved with
podman and imported as tarballs.

## Run

```bash
lab/run-placement.sh M0 c1     # baseline (OBSERVED)
lab/run-placement.sh M1 c1     # constrained impersonation as released + variants w1a, w1b, g1, c1x
lab/run-placement.sh M1-L c1   # M1 + legacy impersonator role + variant i3x
lab/run-placement.sh M2 c1     # PR-text prototype; also names=rbac/nsempty=deny and parse=closed; R1-exp waits ~75 s
lab/run-placement.sh M3 c1     # constrained token × impersonation, imp=pr and imp=hardfail, variant i3alice
W1ONLY=1 lab/run-placement.sh M2 c1   # single-switch isolation of W1-M2 (names=rbac only, nsempty=deny only)
A1ONLY=1 lab/run-placement.sh M2 c1b  # A1 only (with the Request-level audit rule for metrics-server SARs)
```

**Restarting the server container** (`docker restart k3d-s1-agent-power-server-0`, e.g. after changing
`k3s/*.yaml`) regenerates `/etc/hosts` and drops the `--host-alias` entry → re-add it
(`docker exec … sh -c 'echo "10.43.200.10 keycloak.s1-idp.svc" >> /etc/hosts'`), wait until a JWT is accepted, re-apply
`k8s/05-workload.yaml` (bare pods are lost) and re-run `driver/setup_keycloak.py` (Keycloak dev mode loses the task
scopes when its pod is recreated). Runs `c1a` failed exactly this way (controls → 77).

Credentials in `k8s/realm-s1.json`, `k8s/10-keycloak.yaml`, `driver/*.py` and `tls/` are lab-only values.
