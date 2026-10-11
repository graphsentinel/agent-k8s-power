#!/usr/bin/env bash
# Regenerates the lab-only CA and the Keycloak / webhook server certificates (fixed ClusterIPs, see lab/README.md).
set -euo pipefail
cd "$(dirname "$0")"
# The CA carries the extensions that strict X.509 verification requires (Python 3.13+ enables VERIFY_X509_STRICT by
# default): basicConstraints, keyUsage and key identifiers.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 365 -subj "/CN=s1-lab-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null
mk() {
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$1.pem" -days 365 -extfile "$1.ext" 2>/dev/null
  rm "$1.csr" "$1.ext"
}
mk keycloak "DNS:keycloak.s1-idp.svc,DNS:keycloak.s1-idp.svc.cluster.local,IP:10.43.200.10"
mk webhook "DNS:s1-authz.s1-authz.svc,DNS:s1-authz.s1-authz.svc.cluster.local,IP:10.43.200.20"
echo "regenerated; run lab/k3s/gen-config.sh to embed the new CA"
