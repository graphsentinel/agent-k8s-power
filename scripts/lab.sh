#!/usr/bin/env bash
# Layer 2, the lab: images, manifests (lab/k8s), Keycloak setup, the tests and their summary, on the cluster that
# scripts/platform.sh cluster-up created.
#
#   scripts/lab.sh build       pull the runtime images (no image is built: the webhook and the driver run on python)
#   scripts/lab.sh install     import the images into k3d, create the TLS secrets and config maps, apply the
#                              manifests, set up Keycloak's task scopes, wait until ready
#   scripts/lab.sh uninstall   remove the lab's objects (namespaces labelled by the lab, placement/variant RBAC);
#                              the cluster and the platform stay
#   scripts/lab.sh reinstall   uninstall + install
#   scripts/lab.sh test        run the measurement plan RUNS times (c1, c1b, v1), then summary
#   scripts/lab.sh summary     compare the last 'test' with lab/expected.tsv (exit 1 on any difference)
#   scripts/lab.sh status      pods of the lab
#   scripts/lab.sh all         build + install + test
#
# Options (environment):
#   RUNS=5        runs of each plan entry (the reference results use 5)
#   ENGINE=docker image engine (docker or podman); detected when unset
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=versions.env
source "$ROOT/scripts/versions.env"
RUNS=${RUNS:-5}
K="kubectl --context k3d-$CLUSTER"
STATE="$ROOT/lab/.runtime"; mkdir -p "$STATE"
LABEL=agent-k8s-power/lab

log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 not found: run scripts/platform.sh install"; }

# right after 'platform.sh install' the docker group is not active in this shell yet: run again under it
if [ -z "${ENGINE:-}" ] && command -v docker >/dev/null && ! docker info >/dev/null 2>&1 \
   && [ -z "${LAB_SG:-}" ] && getent group docker | grep -qw "$(id -un)" && command -v sg >/dev/null; then
  export LAB_SG=1; exec sg docker -c "$(printf '%q ' "$0" "$@")"
fi
if [ -z "${ENGINE:-}" ]; then
  if command -v docker >/dev/null && docker info >/dev/null 2>&1; then ENGINE=docker
  elif command -v podman >/dev/null; then ENGINE=podman
  else die "no usable container engine: scripts/platform.sh install, then log in again (docker group)"; fi
fi
NODE_RT=docker; command -v docker >/dev/null || NODE_RT=podman
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die "unsupported architecture $(uname -m)" ;; esac
IMAGES=("$KEYCLOAK_IMAGE" "$PYTHON_IMAGE")

# ---------------------------------------------------------------- build
cmd_build() {
  # the manifests must reference exactly the pinned images
  local i used
  used=$(grep -ho 'image: *[^ ,}]*' "$ROOT"/lab/k8s/*.yaml | sed 's/image: *//' | sort -u)
  for i in $used; do printf '%s\n' "${IMAGES[@]}" | grep -qx "$i" || die "lab/k8s uses $i, not pinned in scripts/versions.env"; done
  log "pull ${IMAGES[*]}"
  for i in "${IMAGES[@]}"; do $ENGINE pull -q --platform "linux/$ARCH" "$i" >/dev/null || $ENGINE pull -q "$i" >/dev/null; done
}

# ---------------------------------------------------------------- install
# Images go into the k3d nodes as one single-platform tarball. Docker 29 uses the containerd image store, where
# 'docker save' of a multi-platform image writes an index whose other-platform blobs are missing; k3s's
# 'ctr import' then fails while k3d still reports success. Hence --platform, and the check afterwards.
import_k3d() {
  local tar="$STATE/images.tar"
  if [ "$ENGINE" = podman ]; then podman save -m -o "$tar" "$@"
  elif ! docker save --platform "linux/$ARCH" -o "$tar" "$@" 2>/dev/null; then docker save -o "$tar" "$@"; fi
  k3d image import -c "$CLUSTER" "$tar"
  rm -f "$tar"
  local node img have missing=0
  for node in $(k3d node list -o json | python3 -c 'import sys,json;[print(n["name"]) for n in json.load(sys.stdin) if n["role"] in ("server","agent") and n["runtimeLabels"].get("k3d.cluster")=="'"$CLUSTER"'"]'); do
    have=$($NODE_RT exec "$node" crictl images -o json | python3 -c 'import sys,json;[print(t) for i in json.load(sys.stdin)["images"] for t in i["repoTags"]]')
    for img in "$@"; do grep -qx "$img" <<<"$have" || { echo "missing in $node: $img" >&2; missing=1; }; done
  done
  [ "$missing" = 0 ] || die "image import incomplete (see above)"
  echo "all $# images present on every node"
}

apply_obj() { $K apply -f - >/dev/null; }   # idempotent create of generated objects

cmd_install() {
  need kubectl; need k3d
  $K get --raw /readyz >/dev/null 2>&1 || die "cluster k3d-$CLUSTER not reachable: scripts/platform.sh cluster-up"
  for f in keycloak.pem keycloak.key webhook.pem webhook.key ca.pem; do
    [ -f "$ROOT/lab/tls/$f" ] || die "lab/tls/$f missing: the certificates are made by scripts/platform.sh cluster-up"
  done
  local i; for i in "${IMAGES[@]}"; do $ENGINE image inspect "$i" >/dev/null 2>&1 || die "$i missing: scripts/lab.sh build"; done
  log "images into k3d"
  import_k3d "${IMAGES[@]}"

  log "namespaces, TLS secrets, config maps"
  $K apply -f "$ROOT/lab/k8s/00-namespaces.yaml" >/dev/null
  $K -n s1-idp create secret tls keycloak-tls --cert="$ROOT/lab/tls/keycloak.pem" --key="$ROOT/lab/tls/keycloak.key" --dry-run=client -o yaml | apply_obj
  $K -n s1-authz create secret tls webhook-tls --cert="$ROOT/lab/tls/webhook.pem" --key="$ROOT/lab/tls/webhook.key" --dry-run=client -o yaml | apply_obj
  $K -n s1-idp create configmap realm-s1 --from-file=s1.json="$ROOT/lab/k8s/realm-s1.json" --dry-run=client -o yaml | apply_obj
  $K -n s1-authz create configmap s1-authz-code --from-file="$ROOT/lab/webhook/s1_constraints.py" --dry-run=client -o yaml | apply_obj
  for ns in agents thief; do $K -n $ns create configmap lab-ca --from-file=ca.pem="$ROOT/lab/tls/ca.pem" --dry-run=client -o yaml | apply_obj; done

  log "workloads, base RBAC, Keycloak, webhook"
  $K apply -f "$ROOT/lab/k8s/05-workload.yaml" -f "$ROOT/lab/k8s/06-rbac-base.yaml" \
    -f "$ROOT/lab/k8s/10-keycloak.yaml" -f "$ROOT/lab/k8s/20-webhook.yaml" >/dev/null
  $K -n s1-idp rollout status deploy/keycloak --timeout=300s
  $K -n s1-authz rollout status deploy/s1-authz --timeout=180s
  $K -n agents wait --for=condition=Ready pod/driver --timeout=180s
  $K -n thief wait --for=condition=Ready pod/driver --timeout=180s

  log "Keycloak task scopes (driver/setup_keycloak.py)"
  local ok=0
  for _ in $(seq 1 60); do
    if $K -n agents cp "$ROOT/lab/driver/setup_keycloak.py" driver:/setup_keycloak.py >/dev/null 2>&1 \
       && $K -n agents exec driver -- python3 /setup_keycloak.py > "$STATE/setup-keycloak.log" 2>&1; then ok=1; break; fi
    sleep 5
  done
  [ "$ok" = 1 ] || { tail -5 "$STATE/setup-keycloak.log" >&2; die "Keycloak setup failed (lab/.runtime/setup-keycloak.log)"; }
  echo "ready"
}

cmd_uninstall() {
  need kubectl
  $K get --raw /readyz >/dev/null 2>&1 || die "cluster k3d-$CLUSTER not reachable"
  log "placement and variant RBAC, workloads, Keycloak, webhook, lab namespaces"
  $K delete clusterrole,clusterrolebinding -l s1/placement --ignore-not-found >/dev/null
  $K delete clusterrole,clusterrolebinding -l s1/variant --ignore-not-found >/dev/null
  $K delete role,rolebinding -A -l s1/placement --ignore-not-found >/dev/null
  $K delete role,rolebinding -A -l s1/variant --ignore-not-found >/dev/null
  $K delete --ignore-not-found -f "$ROOT/lab/k8s/20-webhook.yaml" -f "$ROOT/lab/k8s/10-keycloak.yaml" \
    -f "$ROOT/lab/k8s/06-rbac-base.yaml" -f "$ROOT/lab/k8s/05-workload.yaml" >/dev/null
  # only namespaces the lab labelled (lab/k8s/00-namespaces.yaml)
  $K delete ns -l "$LABEL=true" --ignore-not-found --wait=true --timeout=300s
  rm -f "$STATE/test-started" "$STATE/test-plan"
  local left more
  left=$($K get ns -l "$LABEL=true" -o name) || die "could not verify the removal (API error)"
  more=$($K get clusterrole,clusterrolebinding -l 's1/placement' -o name; $K get clusterrole,clusterrolebinding -l 's1/variant' -o name) \
    || die "could not verify the removal (API error)"
  left+=$more
  [ -z "$left" ] || die "still present after uninstall: $(tr '\n' ' ' <<<"$left")"
  echo "removed; the cluster is still there (scripts/platform.sh cluster-down deletes it)"
}

cmd_status() {
  local ns; for ns in s1-idp s1-authz agents thief team-a team-b; do $K -n "$ns" get pods --no-headers 2>/dev/null | sed "s/^/$ns  /"; done
}

# ---------------------------------------------------------------- test
# The plan: every command that produced the reference results (lab/expected.tsv), RUNS times each.
PLAN_C1=("M0 c1" "M1 c1" "M1-L c1" "M2 c1" "M3 c1" "W1ONLY M2 c1")
PLAN_C1B=("A1ONLY M2 c1b")
PLAN_V1=("V1-M0" "V1-M1" "V1-M2" "V2" "V3A" "V3B")

cmd_test() {
  need kubectl
  $K -n s1-authz get deploy s1-authz >/dev/null 2>&1 || die "lab not installed: scripts/lab.sh install"
  rm -f "$STATE/test-plan"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE/test-started"
  : > "$STATE/runner-failures"
  # the plan is written before anything runs; summary fails unless the run reached the end ('complete')
  printf 'runs=%s\ncomplete=0\n' "$RUNS" > "$STATE/test-plan"
  # run <label> <command...>: show the result line, record a non-zero exit of the runner
  run() {
    local label=$1; shift; local rc=0
    "$@" > "$STATE/last-run.log" 2>&1 || rc=$?
    grep -E '^\{"run"|controls_failed|^evidence' "$STATE/last-run.log" | tail -3 || true
    [ "$rc" = 0 ] || { echo "$label: exit $rc" | tee -a "$STATE/runner-failures" >&2; tail -5 "$STATE/last-run.log" >&2; }
  }
  local i e
  for i in $(seq 1 "$RUNS"); do
    log "run $i/$RUNS"
    for e in "${PLAN_C1[@]}" "${PLAN_C1B[@]}"; do
      echo "--- $e"
      case $e in
        W1ONLY*) run "$e #$i" env W1ONLY=1 bash "$ROOT/lab/run-placement.sh" ${e#W1ONLY } ;;
        A1ONLY*) run "$e #$i" env A1ONLY=1 bash "$ROOT/lab/run-placement.sh" ${e#A1ONLY } ;;
        *) run "$e #$i" bash "$ROOT/lab/run-placement.sh" $e ;;
      esac
    done
    for e in "${PLAN_V1[@]}"; do echo "--- revocation $e"; run "$e #$i" bash "$ROOT/lab/run-revocation.sh" "$e" v1; done
  done
  sed -i 's/^complete=0$/complete=1/' "$STATE/test-plan"
  cmd_summary
}

cmd_summary() {
  [ -f "$STATE/test-plan" ] || die "no test plan recorded: run scripts/lab.sh test"
  local runs complete
  # shellcheck disable=SC1091
  . "$STATE/test-plan"
  local extra=(); [ "$complete" = 1 ] || extra+=(--incomplete)
  python3 "$ROOT/scripts/summary.py" --since "$(cat "$STATE/test-started")" --runs "$runs" \
    --runner-failures "$STATE/runner-failures" --markdown "$STATE/summary.md" "${extra[@]}" \
    "$ROOT/lab/expected.tsv" "$ROOT/results/measurements.tsv"
}

case "${1:-}" in
  build) cmd_build ;;
  install) cmd_install ;;
  uninstall) cmd_uninstall ;;
  reinstall) cmd_uninstall; cmd_install ;;
  test) cmd_test ;;
  summary) cmd_summary ;;
  status) cmd_status ;;
  all) cmd_build; cmd_install; cmd_test ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
