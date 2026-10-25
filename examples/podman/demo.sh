#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
STATE="$HERE/.state"
PREFIX=srp-v2-example
LABEL=io.srp.example=podman-v2
SRP_IMAGE=localhost/srp-v2-example:2.0
BACKEND_IMAGE=localhost/srp-v2-example-backend:2.0
CONTAINERS=("$PREFIX-relay" "$PREFIX-expose-a" "$PREFIX-expose-b"
    "$PREFIX-backend-a" "$PREFIX-backend-b")
NETWORKS=("$PREFIX-tunnel" "$PREFIX-private")

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

build() {
    local args=(--file "$HERE/Containerfile" --ignorefile "$HERE/.containerignore"
        --build-arg "GO_IMAGE=${SRP_GO_IMAGE:-docker.io/library/golang:1.24-alpine}"
        --build-arg "ALPINE_IMAGE=${SRP_ALPINE_IMAGE:-docker.io/library/alpine:3.23}")
    if [[ -n "${SRP_BUILD_NETWORK:-}" ]]; then
        args+=(--network "$SRP_BUILD_NETWORK")
    fi
    podman build "${args[@]}" --target srp --tag "$SRP_IMAGE" "$ROOT"
    podman build "${args[@]}" --target backend --tag "$BACKEND_IMAGE" "$ROOT"
}

up() {
    local name suffix
    require ssh-keygen
    require openssl
    for name in "${CONTAINERS[@]}"; do
        if podman container exists "$name"; then
            fail "$name already exists; run ./demo.sh down before starting again"
        fi
    done
    for name in "${NETWORKS[@]}"; do
        if podman network exists "$name"; then
            fail "$name already exists; run ./demo.sh down before starting again"
        fi
    done

    build
    umask 077
    mkdir -p "$STATE"
    chmod 700 "$STATE"
    [[ -f "$STATE/shared.key" ]] || openssl rand -out "$STATE/shared.key" 32
    [[ $(wc -c < "$STATE/shared.key") -eq 32 ]] || fail 'shared.key must contain exactly 32 bytes'
    if [[ ! -f "$STATE/id_ed25519" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C srp-podman-example -f "$STATE/id_ed25519"
    fi
    [[ -f "$STATE/id_ed25519.pub" ]] || fail 'SSH public key is missing'

    podman network create --label "$LABEL" "$PREFIX-tunnel" >/dev/null
    podman network create --internal --label "$LABEL" "$PREFIX-private" >/dev/null
    for suffix in a b; do
        podman run -d --name "$PREFIX-backend-$suffix" --label "$LABEL" \
            --network "$PREFIX-private" --network-alias "backend-$suffix" \
            --hostname "backend-$suffix" --env "BACKEND_NAME=backend-$suffix" \
            --volume "$STATE/id_ed25519.pub:/run/example/id_ed25519.pub:ro,z" \
            "$BACKEND_IMAGE" >/dev/null
    done

    podman run -d --name "$PREFIX-relay" --label "$LABEL" \
        --network "$PREFIX-tunnel" --network-alias relay \
        --publish 127.0.0.1:7770:7770 \
        --publish 127.0.0.1:8022:8022 --publish 127.0.0.1:18080:18080 \
        --volume "$STATE/shared.key:/run/srp/shared.key:ro,z" \
        "$SRP_IMAGE" -v relay -k /run/srp/shared.key -l :7770 \
        -s 'ssh=:8022,myweb=:18080' >/dev/null

    # Podman publishes ports when the container starts; inspect inside the relay
    # to verify that srp itself has no service listeners before registration.
    local attempt listeners ready=false
    for ((attempt = 0; attempt < 30; attempt++)); do
        listeners=$(podman exec "$PREFIX-relay" netstat -lnt)
        if grep -Eq ':7770[[:space:]]' <<<"$listeners"; then
            ready=true
            break
        fi
        sleep 1
    done
    [[ "$ready" == true ]] || fail 'relay tunnel did not start; inspect ./demo.sh logs'
    if grep -Eq ':(8022|18080)[[:space:]]' <<<"$listeners"; then
        fail 'relay has service listeners before any expose registered'
    fi
    printf 'PASS: relay initially listens only on the tunnel port\n'

    for suffix in a b; do
        podman run -d --name "$PREFIX-expose-$suffix" --label "$LABEL" \
            --network "$PREFIX-tunnel" --network "$PREFIX-private" \
            --volume "$STATE/shared.key:/run/srp/shared.key:ro,z" \
            "$SRP_IMAGE" -v expose -k /run/srp/shared.key -r relay:7770 \
            -t "ssh=backend-$suffix:2222,myweb=backend-$suffix:8080" >/dev/null
    done
    printf '\nStarted. Run:\n  %s check\n  curl --noproxy "*" http://127.0.0.1:18080/\n' "$0"
    printf '  %s ssh\n  %s logs\n  %s down\n' "$0" "$0" "$0"
}

down() {
    local name owner
    for name in "${CONTAINERS[@]}"; do
        if podman container exists "$name"; then
            owner=$(podman inspect --format '{{index .Config.Labels "io.srp.example"}}' "$name")
            [[ "$owner" == podman-v2 ]] || fail "refusing to remove unrelated container $name"
            podman rm --force "$name" >/dev/null
        fi
    done
    for name in "${NETWORKS[@]}"; do
        if podman network exists "$name"; then
            owner=$(podman network inspect --format '{{index .Labels "io.srp.example"}}' "$name")
            [[ "$owner" == podman-v2 ]] || fail "refusing to remove unrelated network $name"
            podman network rm "$name" >/dev/null
        fi
    done
    printf 'Removed example containers and networks; keys remain in %s\n' "$STATE"
}

usage() {
    printf 'Usage: %s {up|check|ssh|logs|status|down}\n' "$0"
}

case "${1:-}" in
    up|down) require podman; "$1" ;;
    check) exec bash "$HERE/check.sh" ;;
    ssh)
        require ssh
        exec ssh -F /dev/null -i "$STATE/id_ed25519" -p 8022 \
            -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR demo@127.0.0.1
        ;;
    logs)
        require podman
        for name in "${CONTAINERS[@]}"; do
            printf '\n--- %s ---\n' "$name"
            podman logs --tail 30 "$name"
        done
        ;;
    status)
        require podman
        podman ps --all --filter "label=$LABEL" \
            --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
