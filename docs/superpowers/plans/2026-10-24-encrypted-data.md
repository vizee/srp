# Encrypted data transport implementation plan

**Goal:** Encrypt all business data on the link-agent connection, including pre-read bytes, while preserving streaming and TCP half-closes.

**Architecture:** Wrap only the link-agent connection after the encrypted dial/ack exchange. `io.Copy` then calls the wrapper's encrypting Write/decrypting Read. Use AES-GCM records with direction-specific HMAC-SHA256-derived keys from the existing random session key and a fresh link-generated 16-byte session identifier, authenticated frame lengths, and monotonically increasing nonces. An authenticated empty record signals write-side EOF.

**Constraints:** Go 1.20; standard library only; existing CLI and user/backend TCP interfaces. Existing encrypted handshake/control format remains. Dial and acknowledgement explicitly require `aes-gcm-v1`; both binaries must be upgraded. No plaintext fallback. Do not commit existing user/session changes.

## Task 1: Encrypted connection

Files: `encrypted_conn.go`, `encrypted_conn_test.go`.

- [x] Write tests showing wire bytes hide plaintext; both directions round-trip arbitrary-sized writes and small reads; zero-length writes do not mean EOF.
- [x] Write rejection tests for altered headers/ciphertext, wrong keys/directions, replay/reordering, truncated records, and missing authenticated EOF.
- [x] Observe tests fail before implementation.
- [x] Implement `newEncryptedConn(net.Conn, []byte, []byte, bool) (*encryptedConn, error)`, Read, Write, CloseWrite, 32 KiB plaintext record bounds, sticky errors, independent read/write locks, and complete frame writes. Limit each directional key to 2^32 records, without nonce reuse.
- [x] Verify no-progress writes fail, short writes complete, CloseWrite is idempotent, and reverse traffic survives EOF.

## Task 2: Integrate and verify

Files: `main.go`, `main_test.go`, `README.md`.

- [x] Add tests for encrypted two-hop relays, pre-read ordering, production pairing, and rejecting peers without the transport marker.
- [x] Return the wrapped connection from link pairing; wrap the agent connection on both sides after successful control exchange. Bind dial/ack to the fresh session identifier. Preserve concurrent reverse traffic while sending pre-read bytes.
- [x] Document encrypted tunnel coverage and coordinated upgrade requirement.
- [x] Run the entire suite, race detector, vet, build, and actual CLI requests through a capturing TCP intermediary to verify plaintext does not appear on the tunnel.
- [x] Obtain one independent code review and address important findings.

## Review focus

- No io.Copy optimization may bypass the encrypting/decrypting methods.
- Keys and nonce sequences must be separate by direction; failures must never reuse a nonce.
- No plaintext from a failed authenticated record may be returned.
- Peer FIN without authenticated EOF must report truncation, while authenticated EOF preserves reverse traffic.
- Both production paths and pre-read bytes must use the wrapper; unsupported transport versions must fail closed.

## Progress

- Existing uncommitted protocol/half-close fixes are the baseline and must be preserved.

- Tests observed failing before implementation: missing encrypted connection, unencrypted production pairing, absent transport negotiation, and unsolicited acknowledgement panic.
- Added fresh link-generated session identifier to isolate data keys even if an old agent hello is replayed; ack must echo it. Removed temporary key values from debug logs.
- All protocol validation and TCP half-close regression tests remain green.
- Verification passed: full suite, race detector, vet, build, and whitespace checks.
- Actual CLI verification passed through a capturing loopback intermediary: four concurrent half-closed requests with `preRead=64` returned complete 139537-byte responses. Captured 1118844 tunnel bytes contained no request, pre-read, or response plaintext markers.
- Independent read-only encryption review found no critical or important issues.
