#!/usr/bin/env bash
# V-tests (measurement contract §4b): what a long-running agent still receives after its permission is removed.
#   lab/run-revocation.sh V1-M0|V1-M1|V1-M2|V2|V3A|V3B [config]
set -euo pipefail
T=${1:?test}; CONFIG=${2:-v1}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
K="kubectl --context ${KUBE_CONTEXT:-k3d-s1-agent-power}"
case $T in V1-M0|V3A) P=M0 ;; V1-M1) P=M1 ;; V1-M2|V2) P=M2 ;; V3B) P=M0 ;; *) echo "unknown $T" >&2; exit 2 ;; esac
RUN="$(date -u +%Y%m%dT%H%M%SZ)-$T-$CONFIG"
EV="$ROOT/evidence/$RUN"; mkdir -p "$EV"
LABEL=$(echo "$RUN" | tr 'A-Z' 'a-z' | cut -c10-15)   # short, label-safe

placement() {
  $K delete clusterrole,clusterrolebinding -l s1/placement --ignore-not-found >/dev/null
  $K delete role,rolebinding -A -l s1/placement --ignore-not-found >/dev/null
  $K delete clusterrole,clusterrolebinding -l s1/variant --ignore-not-found >/dev/null
  $K delete role,rolebinding -A -l s1/variant --ignore-not-found >/dev/null
  $K apply -f "$ROOT/lab/k8s/06-rbac-base.yaml" >/dev/null
  case $P in
    M0) $K apply -f "$ROOT/lab/k8s/30-m0.yaml" >/dev/null ;;
    M1) $K apply -f "$ROOT/lab/k8s/31-m1.yaml" -f "$ROOT/lab/k8s/46-var-v1w.yaml" >/dev/null ;;
  esac
  sleep 1
}
patch() { $K -n team-a patch cm app-config --type merge -p "{\"metadata\":{\"labels\":{\"s1v\":\"$1-$LABEL\"}}}" >/dev/null; echo "$(date +%s.%N) patch $1" >> "$EV/actions.log"; }
revoke() {
  case $P in
    M0) $K -n team-a delete rolebinding s1-agent-admin >/dev/null; $K delete clusterrolebinding s1-agent-view >/dev/null ;;
    M1) $K -n team-a delete rolebinding s1-agent-task s1-var-v1w >/dev/null ;;
    M2) $K -n team-a delete rolebinding alice-admin >/dev/null; $K delete clusterrolebinding s1-alice-view >/dev/null ;;
  esac
  echo "$(date +%s.%N) revoke $P" >> "$EV/actions.log"
}
at() { local d; d=$(python3 -c "import time;print(max(0,$READY+$1-time.time()))"); sleep "$d"; }

placement
$K -n s1-authz get deploy s1-authz -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value} {end}' > "$EV/webhook-switches.txt"
$K -n agents cp "$ROOT/lab/driver/driver.py" "driver:/driver-$RUN.py"
CTXJSON='{}'
if [ "$T" = V3B ]; then
  $K -n team-a create sa s1-v3tmp >/dev/null
  $K -n team-a create role s1-v3tmp --verb=get --resource=configmaps --resource-name=app-config >/dev/null
  $K -n team-a create rolebinding s1-v3tmp --role=s1-v3tmp --serviceaccount=team-a:s1-v3tmp >/dev/null
  sleep 1
  CTXJSON=$(printf '{"tmp_token":"%s"}' "$($K -n team-a create token s1-v3tmp --duration=600s)")
fi
TESTNAME=${T%%-*}; [ "$T" = V3A ] && TESTNAME=V3A; [ "$T" = V3B ] && TESTNAME=V3B
OUT="$EV/driver-01-agent.jsonl"
echo "$CTXJSON" | $K -n agents exec -i driver -- python3 "/driver-$RUN.py" --placement "$P" --run-id "$RUN" \
  --config "$CONFIG" --tests "$TESTNAME" --variant "$T" > "$OUT" &
DPID=$!
for i in $(seq 1 300); do grep -q '"type": "ready"' "$OUT" 2>/dev/null && break; sleep 0.2; done
READY=$(python3 -c "import json;print([json.loads(l) for l in open('$OUT') if '\"ready\"' in l][0]['t'])")
case $T in
  V1-*) at 3; patch pre; at 6; revoke; at 11; patch post ;;
  V2)   at 3; patch pre; at 80; patch post ;;
  V3A)  at 3; revoke ;;
  V3B)  at 3; $K -n team-a delete sa s1-v3tmp >/dev/null; echo "$(date +%s.%N) delete-sa" >> "$EV/actions.log" ;;
esac
wait $DPID
# restore
[ "$T" = V3B ] && $K -n team-a delete role,rolebinding s1-v3tmp --ignore-not-found >/dev/null
placement
docker exec k3d-s1-agent-power-server-0 sh -c "grep -h 's1-driver/$RUN' /var/log/s1/audit*.log" > "$EV/audit.jsonl" 2>/dev/null || true
python3 "$ROOT/lab/collect.py" "$EV" "$ROOT/results/measurements.tsv"
