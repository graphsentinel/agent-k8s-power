# Shrinking an agent's Kubernetes power

A Kubernetes lab that compares the two mechanisms that can narrow what a coding agent may do with its credential:
**constrained impersonation** (KEP-5284, beta in Kubernetes 1.36) as released, and **authenticator-provided
constraints** (KEP-5917, proposed in PR [kubernetes/enhancements#5918](https://github.com/kubernetes/enhancements/pull/5918))
as a prototype of its proposed shape. Both are run against the same agent task and the same attacks, on a local k3d
cluster that anyone can rebuild from zero with a few commands ([Quickstart](#quickstart)).

- [The problem](#the-problem)
- [What is compared](#what-is-compared)
- [Results](#results)
- [Quickstart](#quickstart)
- [How-to](#how-to)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)

## The problem

A coding agent asked to read one ConfigMap usually holds a credential that can do everything its ServiceAccount, or
the human who delegated to it, can do. KEP-5917's motivation says it directly: *"delegating an action to an agent
today requires that a user trusts the agent (or the MCP server) to have the same level of access to the cluster as
they do."*

Two mechanisms can narrow that power, in different places:

| | KEP-5284 constrained impersonation | KEP-5917 authenticator-provided constraints |
|---|---|---|
| Status | beta since v1.36, on by default | proposed (PR #5918) |
| Where the limit lives | RBAC objects on the impersonator (`impersonate:<mode>`, `impersonate-on:<mode>:<verb>`) | in the token: the authenticator puts constraints into the user's extra fields; a first-in-chain authorizer denies what they do not allow |
| Who sets it | whoever can write RBAC | whoever issues the token (identity provider) |
| Granularity | per impersonator | per token, so per task |

The lab asks, for one agent task: which attacks does each mechanism stop, where does each fall back to the wider
power, and does `kubectl auth can-i` tell the agent the truth?

**Threat model.** The attacker is the agent process acting beyond its task (prompt injection, a bug) with the
credential it legitimately holds, or a second pod that obtained a copy of that credential. Out of scope: cluster
admins, node or control-plane compromise, the identity provider's administrator, network attackers.

**What this is not.** Not a claim that Kubernetes RBAC is insecure (the baseline is wide by configuration), not a
statement about KEP-5917's final behaviour (M2/M3 are our prototype of the proposal's text), and not a vulnerability
report.

## What is compared

The agent's task: `get configmaps/app-config` in namespace `team-a`. Identity: Keycloak user `alice` through the
client `coding-agent`. Everything else is a forbidden action.

| Placement | What limits the agent | Mechanism |
|---|---|---|
| **M0** | nothing extra: the agent's ServiceAccount has `admin` in team-a and `view` cluster-wide | baseline, released Kubernetes |
| **M1** | constrained impersonation: the agent may impersonate `oidc:alice` only for `get` on `app-config` | KEP-5284 as released |
| **M1-L** | M1 plus the legacy `impersonate` role from the Kubernetes docs' impersonator example | KEP-5284, documented fallback |
| **M2** | alice's token from a task scope carries the constraint; a webhook authorizer enforces it first | **our prototype** of KEP-5917 (PR #5918 head `a346858`) |
| **M3** | M2's token plus impersonation headers | **our prototype**, impersonation handling switched (`imp=pr`, `imp=hardfail`) |

The prototype webhook ([lab/webhook/s1_constraints.py](lab/webhook/s1_constraints.py)) has switches for the places
where the PR text allows more than one reading (`NAMES`, `NSEMPTY`, `PARSE`, `IMP`); each reading is measured.

Attacks (each paired with positive controls in the same run, so a denial means the mechanism denied it):

| Test | Question |
|---|---|
| S-a … S-g | other ConfigMap, a Secret, PATCH, another namespace, LIST, WATCH, LIST across namespaces |
| I1, I2, I3, I4 | impersonate another identity, mint another ServiceAccount's token, inject constraints through impersonation extras, create or exec into pods |
| A1 | reach an aggregated API (`metrics.k8s.io`): does the constraint survive the delegated check? |
| W1, G1, X1 | wildcard rules, a later RoleBinding, a malformed constraint |
| R1 | the credential copied to another pod; token lifetime |
| C1 | does SelfSubjectAccessReview / SelfSubjectRulesReview report what the agent can actually do? |
| D1 | a token without the constraint; an audience that requires it |
| V1 … V3 | what an agent still receives after its permission is revoked (open watches, expiry, minted tokens) |

## Results

Reference measurement: 2026-10-07, k3s v1.37.1, Keycloak 26.8.0; config `c1` (6 plan entries × 5 = 30 runs, 179 cells), `c1b`
(5 runs, A1 audit level) and `v1` (6 revocation tests × 5 = 30 runs). **Every cell gave the same outcome in each of
its 5 runs**
(repeatability in one lab setup, not coverage or conformance). Raw evidence of every run:
[evidence/reference](evidence/reference); the expected outcome of each of the 210 cells:
[lab/expected.tsv](lab/expected.tsv).

**1. Both mechanisms deny the forbidden actions in the tested configuration.**

| Forbidden action | M0 | M1 (released) | M2 (prototype) |
|---|---|---|---|
| other ConfigMap, Secret, PATCH, other namespace, LIST, WATCH, LIST all namespaces | allowed | denied (impersonation check) | denied (webhook) |
| impersonate `team-a/deployer` | allowed | denied | denied (M3) |
| mint a token for `deployer` | allowed | denied | denied |
| create a pod as deployer, `pods/exec` | allowed | denied | denied |
| `metrics.k8s.io` pods in team-a | allowed | denied | denied |

**2. Where they differ.**

- **M1 widens through RBAC around it.** With the legacy `impersonate` role also bound (M1-L) every forbidden action is
  allowed. A `verbs: ["*"]` rule in the task Role allows direct LIST and PATCH without impersonation, and a later
  `view` RoleBinding on the agent's ServiceAccount allows direct reads: the M1 limit is not on the credential.
- **M2's outcome depends on how the PR text is read.** With a name-restricted rule, LIST in team-a and **LIST across
  all namespaces** are allowed under one reading and denied when names are enforced by RBAC and an empty namespace
  denies; a malformed constraint gives NoOpinion (the agent's full RBAC) unless parsing fails closed; a constraint that
  allows impersonation lets the impersonated identity read the Secret unless impersonation fails hard.
- **Impersonation extras:** with permission to set `userextras`, an M1-L agent injects a wide constraint and reads the
  Secret; M3 denies both the wide and the omitted constraint.
- **Aggregated API (A1):** the constraint reaches metrics-server's delegated SubjectAccessReview (team-a allowed,
  team-b denied).
- **Tokens:** a token without the task scope is unconstrained; an audience that requires the claim rejects it (401).
  A copied M0/M1 in-pod ServiceAccount token carried a validity of 31,536,000 s (`exp − iat`; kube-apiserver extends
  in-pod tokens) and was accepted when replayed during the run; the M2 JWT carried 300 s.
- **`can-i` drift:** under M1 SelfSubjectAccessReview reported the task as not allowed while it was, and a Secret as
  allowed while it was denied; under M2 SelfSubjectRulesReview reported the Secret as readable while the webhook
  denied it.

**3. Revocation does not reach open watches.** For these tests the agent is first allowed a named watch of
`app-config` (in M1 through `impersonate-on:user-info:watch`, [lab/k8s/46-var-v1w.yaml](lab/k8s/46-var-v1w.yaml)) and
opens it; then that permission is removed (or its 60 s token expires). In M0, M1 and M2 the open watch kept receiving
events, while new requests were refused. A token the
agent minted for another ServiceAccount kept working after the agent lost its own bindings; a deleted ServiceAccount's
token was still accepted for a few seconds (token authentication cache). This is the documented design, not a
vulnerability: authorization happens when a request starts.

**Scope.** These results are for this lab: k3s v1.37.1 with the RBAC objects in [lab/k8s](lab/k8s), Keycloak 26.8.0,
and our prototype of the KEP-5917 text at `a346858`. They say nothing about a future implementation of KEP-5917.

## Quickstart

Requirements: Ubuntu 24.04 or 26.04 (amd64 or arm64), 4+ CPUs, 8 GB RAM, 20 GB disk, sudo, internet access.

```bash
sudo apt-get update && sudo apt-get install -y git   # if git is not there yet
git clone https://github.com/graphsentinel/agent-k8s-power.git && cd agent-k8s-power
scripts/platform.sh install      # Docker, python3, openssl from Ubuntu; kubectl and k3d only if missing
scripts/platform.sh cluster-up   # lab CA and certificates, kube-apiserver configuration, k3d cluster
scripts/lab.sh all               # pull images, install the lab, run the measurement plan, compare with the reference
```

If `install` added you to the `docker` group, the next commands pick the group up by themselves (they re-run under
`sg docker`). `scripts/lab.sh all` ends with the number of cells matching [lab/expected.tsv](lab/expected.tsv) and
either `ALL CHECKS PASSED` or the list of differences (exit status 1). The table is also written to
`lab/.runtime/summary.md`.

To remove the lab and keep the cluster: `scripts/lab.sh uninstall`. To remove the cluster too:
`scripts/platform.sh cluster-down`.

## How-to

### Two layers

| Layer | Script | What it owns |
|---|---|---|
| **platform** | `scripts/platform.sh` | host tools (Docker, python3, openssl, kubectl, k3d) and the lab's k3d cluster |
| **lab** | `scripts/lab.sh` | images, manifests, Keycloak setup, the measurement plan and its comparison |

The cluster is part of the lab: its kube-apiserver runs with the lab's structured authentication and authorization
configuration and audit policy (generated into `lab/k3s` by `cluster-up`), so the lab does not install on an existing
cluster.

### Platform commands

| Command | What it does |
|---|---|
| `scripts/platform.sh install` | installs only what is missing: packages already installed are not reinstalled or upgraded by name. From Ubuntu's packages: Docker (`docker.io`, then its service is enabled and you are added to the `docker` group), python3, git, openssl, curl. Not packaged by Ubuntu: kubectl and k3d at the versions in `scripts/versions.env` (sha256-checked). An existing Docker engine of any kind is not touched; an existing kubectl or k3d is kept unless `UPGRADE_TOOLS=1` |
| `scripts/platform.sh cluster-up` | generates the lab-only CA and the Keycloak and webhook certificates (`lab/tls/gen.sh`) and the kube-apiserver files (`lab/k3s/gen-config.sh`), then creates the k3d cluster `s1-agent-power` with fixed ClusterIPs, a host alias for the issuer, structured authn/authz and audit logging |
| `scripts/platform.sh cluster-down` | deletes the cluster |
| `scripts/platform.sh status` | tool versions and the cluster's nodes |

### Lab commands

| Command | What it does |
|---|---|
| `scripts/lab.sh build` | pulls the runtime images and checks that the manifests use exactly the pinned ones (no image is built: the webhook and the driver run on python) |
| `scripts/lab.sh install` | imports the images into k3d (checked on every node), creates the TLS secrets and config maps, applies the workloads, base RBAC, Keycloak and the webhook, and sets up Keycloak's task scopes |
| `scripts/lab.sh uninstall` | removes placement and variant RBAC, the workloads, Keycloak and the webhook, and the namespaces the lab labelled (`agent-k8s-power/lab=true`), then checks that none is left |
| `scripts/lab.sh reinstall` | uninstall + install |
| `scripts/lab.sh test` | runs the measurement plan `RUNS` times: `run-placement.sh` M0, M1, M1-L, M2, M3 and the W1 isolation (c1), the A1 audit run (c1b), and `run-revocation.sh` V1-M0, V1-M1, V1-M2, V2, V3A, V3B (v1); then `summary` |
| `scripts/lab.sh summary` | compares the last test with [lab/expected.tsv](lab/expected.tsv), cell by cell: every cell measured in `RUNS` runs with the expected observation and verdict, no unexpected cell, no setup failure (77), no runner error, the plan run to its end |
| `scripts/lab.sh status` | pods of the lab |
| `scripts/check-versions.sh` | the host's Docker, k3d, kubectl, and the pinned versions against the latest upstream releases |

Options: `RUNS` (default 5), `ENGINE` (`docker` or `podman`, detected).

### Run one placement or one test

```bash
lab/run-placement.sh M1 c1           # one run of one placement → evidence/<run>/, rows → results/measurements.tsv
W1ONLY=1 lab/run-placement.sh M2 c1  # W1 isolation only
lab/run-revocation.sh V2 v1          # one revocation test
python3 lab/summarize.py c1 --md     # cell table of your own c1 rows
```

Each run writes `evidence/<run>/` (requests, decisions, webhook log, audit events, manifest) and appends rows to
`results/measurements.tsv`; both are ignored by git.

### Change code, configuration or a version

Edit the webhook, the driver or a manifest, or `scripts/versions.env`, then `scripts/lab.sh reinstall` (a change to
`lab/k3s` or `lab/tls` needs a new cluster: `scripts/platform.sh cluster-down && scripts/platform.sh cluster-up`).
If an outcome is meant to change, rebuild the expectation from your own reference run:
`scripts/make-expected.py results/measurements.tsv c1,c1b,v1 > lab/expected.tsv`.

### Versions

| Comes from | Components | Version |
|---|---|---|
| Ubuntu's packages | Docker (`docker.io`), python3, git, openssl, curl | whatever the Ubuntu release ships; an existing Docker of any source is kept |
| upstream, installed only if missing | kubectl, k3d | v1.37.1, v5.9.0 |
| container images, pinned (`scripts/versions.env`) | Kubernetes (k3s) | v1.37.1-k3s1 |
| | Keycloak | 26.8.0 |
| | Python (webhook, driver) | 3.14.8-slim-trixie |

The pinned versions were the latest stable releases on 2026-10-11. The reference measurement used Python 3.12 for the
webhook and the driver (standard library only) and k3d v5.8.3. The pinned versions were then checked from scratch in a
fresh Ubuntu 26.04 VM (`scripts/multipass-e2e.sh`, Docker 29.1.3 from Ubuntu, 5 runs, then reinstall, one more run and
uninstall), and again in a fresh Ubuntu 24.04 VM (Docker 29.1.3, 1 run, reinstall, 1 run, uninstall): all 210 cells
matched `lab/expected.tsv` in every run ([evidence/e2e-multipass](evidence/e2e-multipass)).

Credentials in `lab/k8s/realm-s1.json`, `lab/k8s/10-keycloak.yaml`, `lab/k8s/05-workload.yaml` and `lab/driver/*.py`
are lab-only values. The CA, the server keys and certificates and the kube-apiserver files are generated for each
cluster and never committed.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `permission denied ... docker.sock` | the docker group is not active in this shell: log out and in again (the scripts try `sg docker` first) |
| controls fail, every row of a run is `77` | the server container was restarted: that regenerates its `/etc/hosts` and drops the issuer's host alias, so the apiserver cannot reach Keycloak. Start over with `scripts/platform.sh cluster-down && scripts/platform.sh cluster-up && scripts/lab.sh install` |
| `Keycloak setup failed` | Keycloak takes 1–2 minutes on first start; `scripts/lab.sh install` again (it is idempotent) |
| `missing in <node>: <image>` | the import into k3d failed; `scripts/lab.sh build`, then `scripts/lab.sh install` |
| `lab/tls/... missing` | the certificates are made by `scripts/platform.sh cluster-up` |
| `CERTIFICATE_VERIFY_FAILED ... key usage` | a CA made by an older `lab/tls/gen.sh` lacks the extensions that strict verification (Python 3.13+) requires; recreate the cluster so `cluster-up` generates a new CA |
| a cell differs from `lab/expected.tsv` | the summary names the cell; its evidence is in `evidence/<run>/` |

## Repository layout

```
scripts/                  platform.sh (layer 1), lab.sh (layer 2), versions.env, summary.py, make-expected.py,
                          check-versions.sh, multipass-e2e.sh
lab/webhook/              the KEP-5917 PR-text prototype authorizer (switches NAMES, NSEMPTY, PARSE, IMP)
lab/driver/               test driver and Keycloak setup (python, standard library)
lab/k8s/                  namespaces, workloads, base RBAC, Keycloak, webhook, placements 30–32, variants 40–46
lab/k3s/gen-config.sh     kube-apiserver structured authn/authz, webhook kubeconfig and audit policy (generated)
lab/tls/gen.sh            lab-only CA and server certificates (generated)
lab/run-placement.sh      one run of one placement; lab/run-revocation.sh one revocation test
lab/collect.py, lab/summarize.py, lab/a1b_audit.py, lab/redact.py
lab/expected.tsv          the expected outcome of each measured cell
evidence/reference/       raw evidence of every reference run
results/, evidence/<run>/ written by your own runs (git-ignored)
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
