#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODE=release
PINNED_KEY=
if [ "${1:-}" = "--structural-only" ]; then
  MODE=structural
  shift
fi
[ "$#" -le 1 ] || { echo "usage: $0 [--structural-only] [externally-pinned-public-key.pem]" >&2; exit 2; }
PINNED_KEY=${1:-}
PINNED_FINGERPRINT=${RELEASE_KEY_SHA256:-}
[ -f "$ROOT/SHA256SUMS" ] || { echo "missing SHA256SUMS" >&2; exit 2; }
(
  cd "$ROOT"
  sha256sum --check --strict SHA256SUMS
)
if [ "$MODE" = structural ]; then
  echo "STRUCTURAL ONLY: checksums and bundle structure passed; authenticity not established; NOT RELEASE READY"
  exit 0
fi
[ -f "$ROOT/SHA256SUMS.sig" ] && [ -f "$ROOT/release-public-key.pem" ] || {
  echo "release verification failed: bundle is unsigned or signature material is incomplete" >&2
  echo "use --structural-only only for non-release checksum diagnostics" >&2
  exit 2
}
[ -n "$PINNED_KEY" ] || [ -n "$PINNED_FINGERPRINT" ] || {
  echo "release verification failed: an external public key or RELEASE_KEY_SHA256 fingerprint is required" >&2
  echo "the public key bundled with the release is not a trust anchor" >&2
  exit 2
}
command -v openssl >/dev/null 2>&1 || { echo "openssl is required for signature verification" >&2; exit 2; }
KEY="$ROOT/release-public-key.pem"
TRUST=
if [ -n "$PINNED_KEY" ]; then
  [ -f "$PINNED_KEY" ] || { echo "pinned public key is unavailable" >&2; exit 2; }
  cmp -s "$PINNED_KEY" "$KEY" || { echo "bundle key differs from externally pinned key" >&2; exit 2; }
  KEY="$PINNED_KEY"
  TRUST=trusted_pinned_key
fi
if [ -n "$PINNED_FINGERPRINT" ]; then
  case "$PINNED_FINGERPRINT" in *[!0-9a-f]*) echo "external fingerprint must be 64 lowercase hexadecimal characters" >&2; exit 2;; esac
  [ "${#PINNED_FINGERPRINT}" -eq 64 ] || { echo "external fingerprint must be 64 lowercase hexadecimal characters" >&2; exit 2; }
  ACTUAL=$(sha256sum "$ROOT/release-public-key.pem" | cut -d' ' -f1)
  [ "$ACTUAL" = "$PINNED_FINGERPRINT" ] || { echo "bundle key fingerprint differs from external pin" >&2; exit 2; }
  if [ -n "$TRUST" ]; then TRUST=trusted_pinned_key_and_fingerprint; else TRUST=trusted_pinned_fingerprint; fi
fi
openssl pkeyutl -verify -rawin -pubin -inkey "$KEY" -in "$ROOT/SHA256SUMS" -sigfile "$ROOT/SHA256SUMS.sig" >/dev/null
echo "release authenticity verified: signature=valid trust=$TRUST"
