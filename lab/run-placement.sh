#!/usr/bin/env bash
# One run of one placement (measurement contract v0.2.x).
#   lab/run-placement.sh M0|M1|M1-L|M2|M3 [config-label]
# Evidence: evidence/<run>/ ; rows appended to results/measurements.tsv (control gate in lab/collect.py).
set -euo pipefail
P=${1:?placement}; CONFIG=${2:-c1}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$ROOT/scripts/versions.env" ] && . "$ROOT/scripts/versions.env"
K="kubectl --context ${KUBE_CONTEXT:-k3d-s1-agent-power}"
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$P-$CONFIG"
EV="$ROOT/evidence/$RUN"; mkdir -p "$EV" "$ROOT/results"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---- placement RBAC: remove every placement/variant object, apply this placement's
$K delete clusterrole,clusterrolebinding -l s1/placement --ignore-not-found >/dev/null
$K delete role,rolebinding -A -l s1/placement --ignore-not-found >/dev/null
reset_variants() {
  $K delete clusterrole,clusterrolebinding -l s1/variant --ignore-not-found >/dev/null
  $K delete role,rolebinding -A -l s1/variant --ignore-not-found >/dev/null
}
reset_variants
case $P in
  M0) $K apply -f "$ROOT/lab/k8s/30-m0.yaml" >/dev/null ;;
  M1) $K apply -f "$ROOT/lab/k8s/31-m1.yaml" >/dev/null ;;
  M1-L) $K apply -f "$ROOT/lab/k8s/31-m1.yaml" -f "$ROOT/lab/k8s/32-m1l.yaml" >/dev/null ;;
  M2|M3) ;;
  *) echo "unknown placement $P" >&2; exit 2 ;;
esac

switches() {  # names nsempty parse imp
  local cur
  cur=$($K -n s1-authz get deploy s1-authz -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.value} {end}')
  if [ "$cur" != "$1 $2 $3 $4 " ]; then
    [ -n "${EV:-}" ] && $K -n s1-authz logs -l app=s1-authz --tail=-1 --max-log-requests=10 --since-time="$START" >> "$EV/webhook.jsonl" 2>/dev/null || true
    $K -n s1-authz set env deploy/s1-authz NAMES="$1" NSEMPTY="$2" PARSE="$3" IMP="$4" >/dev/null
    $K -n s1-authz rollout status deploy/s1-authz --timeout=120s >/dev/null
    sleep 3
  fi
  SW="names=$1,nsempty=$2,parse=$3,imp=$4"
}
switches pr pr pr pr

# ---- run manifest
python3 - "$EV/manifest.json" "$RUN" "$P" "$CONFIG" <<EOF
import json, sys, subprocess, hashlib, glob
out, run, p, cfg = sys.argv[1:5]
k = "kubectl --context k3d-s1-agent-power".split()
def sh(*a): return subprocess.run(list(a), capture_output=True, text=True).stdout.strip()
m = {"run_id": run, "placement": p, "config": cfg,
     "k3s_image": "${K3S_IMAGE:-docker.io/rancher/k3s:v1.37.1-k3s1}",
     "server_version": sh(*k, "version", "-o", "json"),
     "keycloak_image": sh(*k, "-n", "s1-idp", "get", "deploy", "keycloak", "-o", "jsonpath={.spec.template.spec.containers[0].image}"),
     "manifests_sha256_12": {f.split("/")[-1]: hashlib.sha256(open(f, "rb").read()).hexdigest()[:12]
                             for f in sorted(glob.glob("$ROOT/lab/k8s/*") + glob.glob("$ROOT/lab/k3s/*.yaml")
                                             + ["$ROOT/lab/webhook/s1_constraints.py", "$ROOT/lab/driver/driver.py"])}}
json.dump(m, open(out, "w"), indent=1)
EOF

# ---- driver copies (one per run, AI1 lesson)
for ns in agents thief; do $K -n $ns cp "$ROOT/lab/driver/driver.py" "driver:/driver-$RUN.py"; done
DEPLOYER_TOKEN=$($K -n team-a create token deployer --duration=1h)
CTXJSON=$(printf '{"deployer_token":"%s"}' "$DEPLOYER_TOKEN")
N=0
drv() {  # tests [variant] [scope-override]
  N=$((N+1))
  echo "$CTXJSON" | $K -n agents exec -i driver -- python3 "/driver-$RUN.py" --placement "$P" --run-id "$RUN" \
    --config "$CONFIG/$SW" --tests "$1" --variant "${2:-}" --scope-override "${3:-}" > "$EV/driver-$(printf %02d $N)-agent.jsonl"
}
with_variant() {  # variant file tests
  $K apply -f "$ROOT/lab/k8s/$2" >/dev/null; sleep 1
  drv "$3" "$1"
  reset_variants
}
thief() {  # R1: the thief pod gets a copy of the agent's credential
  local cred
  cred=$(echo "$CTXJSON" | $K -n agents exec -i driver -- python3 "/driver-$RUN.py" --placement "$P" --run-id "$RUN" \
    --tests none --print-agent-cred | grep '"type": "cred"')
  N=$((N+1))
  printf '{"deployer_token":"%s","copied":%s}' "$DEPLOYER_TOKEN" "$cred" | $K -n thief exec -i driver -- \
    python3 "/driver-$RUN.py" --placement "$P" --run-id "$RUN" --config "$CONFIG/$SW" --tests R1 \
    > "$EV/driver-$(printf %02d $N)-thief.jsonl"
}

case $P in
  M0)   drv CTRL,S,I1,I2,I4,A1,C1; thief ;;
  M1)   drv CTRL,S,I1,I2,I4,A1,C1; thief
        with_variant w1a 40-var-w1a.yaml W1M1
        with_variant w1b 41-var-w1b.yaml W1M1
        with_variant g1 42-var-g1.yaml G1
        with_variant c1x 43-var-c1x.yaml C1 ;;
  M1-L) drv CTRL,S,I1,I2,I3,I4,A1
        with_variant i3x 44-var-i3x.yaml I3 ;;
  M2)   if [ -n "${A1ONLY:-}" ]; then  # A1-b with the SAR body in the audit log (lab review round 2)
          drv CTRL,A1
        elif [ -n "${W1ONLY:-}" ]; then  # single-switch isolation of W1-M2
          switches rbac pr pr pr; drv CTRL,W1M2
          switches pr deny pr pr; drv CTRL,W1M2
          switches pr pr pr pr
        else
        drv CTRL,S,I2,I4,A1,D1,X1,C1,W1M2; thief
        drv C1 "" task-introspect
        switches rbac deny pr pr;   drv CTRL,W1M2
        switches pr pr closed pr;   drv CTRL,X1
        switches pr pr pr pr
        [ -n "${SKIP_EXP:-}" ] || drv R1EXP
        fi ;;
  M3)   drv CTRL,I1,I3
        with_variant i3alice 45-var-i3alice.yaml CTRL,I1,I3
        switches pr pr pr hardfail
        with_variant i3alice 45-var-i3alice.yaml CTRL,I1,I3
        switches pr pr pr pr ;;
esac

# ---- evidence: webhook decisions and audit events of this run (logs of every webhook pod: after a switch change the
# deployment can briefly have two, and 'logs deploy/…' may pick the terminating one)
$K -n s1-authz logs -l app=s1-authz --tail=-1 --max-log-requests=10 --since-time="$START" >> "$EV/webhook.jsonl" 2>/dev/null || true
docker exec k3d-s1-agent-power-server-0 sh -c "grep -h 's1-driver/$RUN' /var/log/s1/audit*.log" > "$EV/audit.jsonl" 2>/dev/null || true
python3 "$ROOT/lab/collect.py" "$EV" "$ROOT/results/measurements.tsv"
