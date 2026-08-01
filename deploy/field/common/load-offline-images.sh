#!/usr/bin/env bash
set -Eeuo pipefail

ARCHIVE_DIR="${1:?usage: load-offline-images.sh ARCHIVE_DIRECTORY}"
MANIFEST="${ARCHIVE_DIR}/image-archives.json"
[[ -f "${MANIFEST}" ]] || {
  printf 'offline image manifest is missing: %s\n' "${MANIFEST}" >&2
  exit 1
}
command -v jq >/dev/null
command -v docker >/dev/null
while IFS=$'\t' read -r filename expected; do
  archive="${ARCHIVE_DIR}/${filename}"
  [[ -f "${archive}" ]] || {
    printf 'offline image archive is missing: %s\n' "${archive}" >&2
    exit 1
  }
  actual="$(sha256sum "${archive}" | cut -d' ' -f1)"
  [[ "${actual}" == "${expected}" ]] || {
    printf 'offline image archive checksum mismatch: %s\n' "${filename}" >&2
    exit 1
  }
  docker load --input "${archive}"
done < <(jq -r '.archives[] | [.filename,.sha256] | @tsv' "${MANIFEST}")
