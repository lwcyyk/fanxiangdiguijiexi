#!/usr/bin/env sh
set -eu

case "${RI_NORN_NODE_HOSTNAME:?RI_NORN_NODE_HOSTNAME is required}" in
  *[!A-Za-z0-9.-]* | .* | *.)
    printf 'invalid Norn node hostname\n' >&2
    exit 1
    ;;
esac

sed "s/@@NORN_NODE_HOSTNAME@@/${RI_NORN_NODE_HOSTNAME}/g" \
  /field/nginx-readonly.conf >/tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
