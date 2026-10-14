#!/usr/bin/env bash
# Generate the test-only lab PKI for the Tencent Cloud resolver-identity lab.
# Runs on the management host (as root). Produces a staging tree under
# /opt/domain-center-install/cloud-928ed0e/lab-pki/ that mirrors the final
# secret-dir layouts; a separate distribution step installs into each host's
# secret tree with the correct ownership. CA and leaf certificates default to
# 30-day validity for the physical lab rotation and remain OU=TEST ONLY.
set -Eeuo pipefail

ROOT=/opt/domain-center-install/cloud-928ed0e
PKI=$ROOT/lab-pki
CA=$PKI/ca
umask 077

VALIDITY_DAYS="${RI_LAB_PKI_VALIDITY_DAYS:-30}"
if ! [[ "$VALIDITY_DAYS" =~ ^[1-9][0-9]*$ ]]; then
  echo "RI_LAB_PKI_VALIDITY_DAYS must be a positive integer" >&2
  exit 2
fi

mkdir -p "$CA"

# ---- 1. Lab CA (RSA 2048, configurable validity, test-only) ----
if [ ! -s "$CA/ca.key" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CA/ca.key"
fi
if [ ! -s "$CA/ca.crt" ]; then
  openssl req -x509 -new -sha256 -days "$VALIDITY_DAYS" -key "$CA/ca.key" \
    -subj "/CN=ri-lab-ca/OU=TEST ONLY" -out "$CA/ca.crt"
fi
chmod 600 "$CA/ca.key"
chmod 644 "$CA/ca.crt"

serial=100
sign() { # sign <csr> <out.crt> <ext-file>
  openssl x509 -req -sha256 -days "$VALIDITY_DAYS" -in "$1" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" \
    -set_serial "$serial" -extfile "$3" -out "$2"
  serial=$((serial + 1))
}

gen_rsa_pair() { # gen_rsa_pair <out.key> <out.crt> <cn> <eku> [sans...]
  local key=$1 crt=$2 cn=$3 eku=$4
  shift 4
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key"
  openssl req -new -sha256 -key "$key" -subj "/CN=$cn/OU=TEST ONLY" -out "$crt.csr"
  { echo "extendedKeyUsage=$eku"
    if [ $# -gt 0 ]; then
      echo "subjectAltName=$(IFS=,; echo "$*")"
    fi
  } > "$crt.ext"
  sign "$crt.csr" "$crt" "$crt.ext"
  rm -f "$crt.csr" "$crt.ext"
}

# ---- 2. Management issuer keys (Ed25519) ----
MGMT=$PKI/management
mkdir -p "$MGMT"
if [ ! -s "$MGMT/identity-issuer-ed25519-private-key" ]; then
  openssl genpkey -algorithm ED25519 -out "$MGMT/identity-issuer-ed25519-private-key"
  openssl pkey -in "$MGMT/identity-issuer-ed25519-private-key" -outform DER | tail -c 32 | base64 > "$MGMT/identity-issuer.key"
fi
if [ ! -s "$MGMT/snapshot-issuer-ed25519-private-key" ]; then
  openssl genpkey -algorithm ED25519 -out "$MGMT/snapshot-issuer-ed25519-private-key"
  openssl pkey -in "$MGMT/snapshot-issuer-ed25519-private-key" -outform DER | tail -c 32 | base64 > "$MGMT/snapshot-issuer.key"
fi
if [ ! -s "$MGMT/publication-ssh-identity" ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'ri-management publication' -f "$MGMT/publication-ssh-identity"
fi
chmod 600 "$MGMT"/*

# ---- 3. Norn server certs (per node) ----
norn_server() { # norn_server <host> <fqdn> <ip>
  local host=$1 fqdn=$2 ip=$3
  local out=$PKI/norn-$host/tls
  mkdir -p "$out"
  gen_rsa_pair "$out/server.key" "$out/server.crt" "$host" serverAuth \
    "DNS:$fqdn" "DNS:$host" "DNS:localhost" "IP:$ip"
  cp "$CA/ca.crt" "$out/ca.crt"
  chmod 600 "$out/server.key"; chmod 644 "$out/server.crt" "$out/ca.crt"
}
norn_server norn-a ri-norn-a.cloud.lab 10.206.16.3
norn_server norn-b ri-norn-b.cloud.lab 10.206.16.5

# ---- 4. Norn-read client certs (management + each resolver) ----
norn_client() { # norn_client <dest-dir> <cn>
  local out=$1 cn=$2
  mkdir -p "$out"
  gen_rsa_pair "$out/client.key" "$out/client.crt" "$cn" clientAuth
  cp "$CA/ca.crt" "$out/ca.crt"
  chmod 600 "$out/client.key"; chmod 644 "$out/client.crt" "$out/ca.crt"
}
norn_client "$PKI/mgmt-norn-tls" management-norn-read
norn_client "$PKI/ri-r1/norn-tls" ri-r1-norn-read
norn_client "$PKI/ri-r2/norn-tls" ri-r2-norn-read
norn_client "$PKI/ri-r3/norn-tls" ri-r3-norn-read
norn_client "$PKI/ri-authdns/norn-tls" ri-authdns-norn-read

# ---- 5. Resolver agent + client certs ----
agent_certs() { # agent_certs <host> <ip> <is-r1>
  local host=$1 ip=$2 is_r1=$3
  local at=$PKI/$host/agent-tls
  local peer_server_id
  case "$host" in
    ri-r1) peer_server_id='operator/L01/r1' ;;
    ri-r2) peer_server_id='operator/L01/r2' ;;
    ri-r3) peer_server_id='operator/L01/r3' ;;
    ri-authdns) peer_server_id='operator/authdns' ;;
    *) echo "unknown Agent host: $host" >&2; exit 1 ;;
  esac
  mkdir -p "$at"
  local csr=$ROOT/work/agents/$host/agent.csr
  [ -s "$csr" ] || { echo "missing agent CSR for $host" >&2; exit 1; }
  { echo "extendedKeyUsage=serverAuth"
    echo "subjectAltName=DNS:agent,DNS:$host,DNS:$host.cloud.lab,IP:$ip"
  } > "$at/agent.ext"
  sign "$csr" "$at/agent.crt" "$at/agent.ext"
  rm -f "$at/agent.ext"
  gen_rsa_pair "$at/agent-client.key" "$at/agent-client.crt" "agent-client-$host" clientAuth \
    "URI:spiffe://ri/$peer_server_id"
  gen_rsa_pair "$at/trace-client.key" "$at/trace-client.crt" "trace-client-$host" clientAuth \
    "URI:spiffe://ri/$peer_server_id"
  if [ "$is_r1" = 1 ]; then
    gen_rsa_pair "$at/wrapper-client.key" "$at/wrapper-client.crt" "wrapper-client-$host" clientAuth \
      'URI:spiffe://ri/wrapper'
  fi
  cp "$CA/ca.crt" "$at/client-ca.crt"
  cp "$CA/ca.crt" "$at/agent-ca.crt"
  chmod 600 "$at"/*.key
  chmod 644 "$at"/*.crt
}
agent_certs ri-r1 10.206.16.14 1
agent_certs ri-r2 10.206.16.17 0
agent_certs ri-r3 10.206.16.7 0

# Auth DNS uses its Agent as a server and the Authority Proxy as a local mTLS client.
agent_certs ri-authdns 10.206.16.13 0
gen_rsa_pair "$PKI/ri-authdns/agent-tls/authority-client.key" \
  "$PKI/ri-authdns/agent-tls/authority-client.crt" \
  authority-client-ri-authdns clientAuth \
  'URI:spiffe://ri/operator/authdns-authority-proxy'
chmod 600 "$PKI/ri-authdns/agent-tls/authority-client.key"
chmod 644 "$PKI/ri-authdns/agent-tls/authority-client.crt"

echo "lab-pki generated under $PKI"
find "$PKI" -type f | sed "s|$PKI/||" | sort
