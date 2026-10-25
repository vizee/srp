#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PREFIX=srp-v2-example
STATE="$HERE/.state"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for tool in podman curl ssh; do
    command -v "$tool" >/dev/null || fail "missing command: $tool"
done
podman container exists "$PREFIX-relay" || fail 'run ./demo.sh up first'
[[ -f "$STATE/id_ed25519" ]] || fail 'example SSH identity is missing'

http() {
    curl --noproxy '*' --fail --silent --show-error --max-time 3 \
        --http1.0 http://127.0.0.1:18080/
}

ssh_command() {
    ssh -F /dev/null -i "$STATE/id_ed25519" -p 8022 \
        -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=3 \
        -o ConnectionAttempts=1 -o ControlMaster=no -S none \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR demo@127.0.0.1 'cat /etc/srp-example-name'
}

round_robin() {
    local first second
    first=$("$1" 2>/dev/null) || return 1
    second=$("$1" 2>/dev/null) || return 1
    [[ $(printf '%s\n%s\n' "$first" "$second" | sort) == $'srp backend-a\nsrp backend-b' ]]
}

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 30; attempt++)); do
        if "$@"; then return 0; fi
        sleep 1
    done
    fail "timed out: $*; inspect ./demo.sh logs"
}

services_closed() {
    local listeners
    listeners=$(podman exec "$PREFIX-relay" netstat -lnt) || return 1
    ! grep -Eq ':(8022|18080)[[:space:]]' <<<"$listeners"
}

wait_for round_robin http
printf 'PASS: HTTP reaches both private backends in round-robin order\n'
wait_for round_robin ssh_command
printf 'PASS: SSH public-key login reaches both private backends\n'

# Restart on failure as well, so a failed lifecycle check leaves the demo usable.
trap 'podman start "$PREFIX-expose-a" "$PREFIX-expose-b" >/dev/null 2>&1 || true' EXIT
podman stop --time 5 "$PREFIX-expose-a" "$PREFIX-expose-b" >/dev/null
wait_for services_closed
printf 'PASS: removing all exposes closes both relay service listeners\n'
podman start "$PREFIX-expose-a" "$PREFIX-expose-b" >/dev/null
wait_for round_robin http
wait_for round_robin ssh_command
trap - EXIT
printf 'PASS: restarting exposes restores HTTP and SSH forwarding\n'
