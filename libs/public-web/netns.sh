#!/usr/bin/env bash
# Isolated test-owned addresses: never changes the host network.
set -euo pipefail
if [ "${PUBLIC_WEB_NETNS:-}" != 1 ]; then
  exec unshare --user --map-root-user --net env PUBLIC_WEB_NETNS=1 bash "$0" "$@"
fi
ip link set lo up
ip link add d0 type dummy
ip link set d0 up
for addr in 11.0.0.10 11.0.0.20 10.77.0.10 169.254.169.254; do
  ip addr add "$addr/32" dev d0
done
# Hostile proxy environment; tests bind a sentinel to this port.
export HTTP_PROXY=http://11.0.0.20:19099 HTTPS_PROXY=http://11.0.0.20:19099 ALL_PROXY=http://11.0.0.20:19099
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" all_proxy="$ALL_PROXY"
unset NO_PROXY no_proxy
exec "$@"
