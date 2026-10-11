#!/usr/bin/env bash
# Generates the kube-apiserver config files mounted at /etc/s1 in the k3d server node.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); T="$D/../tls"
CA_INDENT=$(sed 's/^/      /' "$T/ca.pem")
CA_B64=$(base64 -w0 "$T/ca.pem")

# Structured authentication (KEP-3331, GA v1.34). The extra key is a lab key: kubernetes.io keys are
# rejected by validation (preflight P-3, DEC-04).
cat > "$D/authn.yaml" <<YAML
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
anonymous:
  enabled: false
jwt:
- issuer:
    url: https://keycloak.s1-idp.svc:8443/realms/s1
    certificateAuthority: |
$CA_INDENT
    audiences: [kubernetes, k8s-agents]
    audienceMatchPolicy: MatchAny
  claimValidationRules:
  # D1-aud: a token for the agent audience must carry constraints
  - expression: "!('k8s-agents' in (type(claims.aud) == string ? [claims.aud] : claims.aud)) || has(claims.k8s_constraints)"
    message: "tokens for audience k8s-agents must carry k8s_constraints"
  claimMappings:
    username:
      expression: "'oidc:' + claims.preferred_username"
    extra:
    - key: s1.lab.example/constraints
      valueExpression: "has(claims.k8s_constraints) ? claims.k8s_constraints : []"
YAML

# Structured authorization: our webhook first (M2/M3 prototype), only for constrained tokens; then Node, RBAC.
cat > "$D/authz.yaml" <<YAML
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
- type: Webhook
  name: s1-constraints
  webhook:
    timeout: 3s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: Deny
    cacheAuthorizedRequests: false
    cacheUnauthorizedRequests: false
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/s1/webhook.kubeconfig
    matchConditions:
    - expression: "'s1.lab.example/constraints' in request.extra"
- type: Node
  name: node
- type: RBAC
  name: rbac
YAML

cat > "$D/webhook.kubeconfig" <<YAML
apiVersion: v1
kind: Config
clusters:
- name: s1-authz
  cluster:
    server: https://10.43.200.20:8443/authorize
    certificate-authority-data: $CA_B64
users:
- name: apiserver
  user: {}
contexts:
- name: default
  context: {cluster: s1-authz, user: apiserver}
current-context: default
YAML

cat > "$D/audit-policy.yaml" <<'YAML'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
# A1-b: the delegated SubjectAccessReview body (spec.user, spec.extra) of the aggregated metrics server
- level: Request
  users: [system:serviceaccount:kube-system:metrics-server]
  resources: [{group: authorization.k8s.io, resources: [subjectaccessreviews]}]
- level: Metadata
  users:
  - oidc:alice
  - system:serviceaccount:agents:coding-agent
  - system:serviceaccount:thief:thief
  - system:serviceaccount:team-a:deployer
  - system:serviceaccount:kube-system:metrics-server
- level: Metadata
  namespaces: [team-a, team-b, thief]
- level: None
YAML
echo generated
