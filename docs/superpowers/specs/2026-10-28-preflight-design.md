# Preflight connections

Control registration returns a random 32-byte hex `preflight_key` unique to
that control and `max_preflight_conns`. Relay exposes
`-max-preflight-conns` (default 8, range 1–256). Expose maintains up to that
many idle connections, replacing consumed or failed connections. An empty
pool falls back to the existing direct data handshake.

Preflight hello has type `preflight`, a `preflight_key`, no services and no
data ID. It uses the existing authenticated handshake and independent
session encryption. Relay admits only existing keys and enforces the limit
per control. Preflight heartbeat requests carry the key, run every 5 seconds,
and receive heartbeat responses carrying that same key. Relay closes idle
preflight connections after 10 seconds without a heartbeat.

Expose sends `upgrade` with a pending data ID on a selected idle connection.
Relay atomically checks the key and pending ID owner, consumes the pending
request, releases the preflight slot, sends `ready`, clears idle deadlines,
and starts bridging. No new handshake or encryption reset occurs. The idle
heartbeat and upgrade share one IO owner so heartbeat frames cannot leak
into business traffic. Once an upgrade packet has been sent, that data ID
is not retried.

Control removal deletes its key immediately, without closing its idle
preflight connections. They continue heartbeats until relay rejects the
released key. Expose stops replenishing the old pool. Process shutdown
closes and joins all pool workers, including pools from previous controls.
Established data connections retain the existing control-owned lifetime.

Approach: retain the current protocol Stream and data-claim path, adding
serialized preflight workers. A second handshake on upgrade adds latency
and is unnecessary; reusing the control channel for data changes the
one-TCP-connection-per-client model. The user confirmed configurable relay
capacity with default 8, direct data fallback when empty, and automatic refill.
