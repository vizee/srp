# Protocol validation and TCP relay repair

**Goal:** Reject malformed control messages without panics and preserve TCP half-close semantics.

**Scope:** The defects identified in the preceding code explanation. Keep the current wire format, CLI, Go 1.20 floor, and standard-library-only dependencies. Business traffic remains transparent TCP.

**Execution:** Implement directly in the existing checkout, with regression tests first. No commits, publication, or dependency changes are needed.

## Task 1: Validate protocol inputs

Files: `main.go`, `main_test.go`.

- [x] Add failing tests for invalid ciphertext lengths, invalid IV lengths, invalid PKCS#7 padding, and truncated/oversized hello payloads.
- [x] Run the tests and confirm malformed inputs fail through the current missing checks.
- [x] Validate lengths before CBC operations and slicing, validate every padding byte, and require the exact hello payload size.
- [x] Check valid messages, empty plaintext, valid hello messages, and invalid signatures for compatibility.
- [x] Run the full test suite.

## Task 2: Preserve TCP half-closes and close completed relays

Files: `main.go`, `main_test.go`.

- [x] Add a TCP regression test where a client sends a request, closes its write side, then reads a delayed response through both relay hops.
- [x] Confirm the current relay truncates the response.
- [x] On clean EOF, close only the destination's write side; on transfer failure, close both connections to unblock the peer copier.
- [x] Wait for both directions, then close both connections. Use the relay helper on both link and agent paths, including pre-read forwarding.
- [x] Test failure cleanup and the fallback for connections without CloseWrite.
- [x] Run the full suite with the race detector, vet, and build; review the complete diff.

## Review focus

- Non-block-aligned or empty ciphertext must not reach CBC operations.
- Padding values zero, above a block, or with inconsistent bytes must be rejected.
- Hello parsing must reject both short and oversized payloads before slicing.
- A write-side FIN must not prevent the sender from receiving a response.
- Both relay goroutines and connections must terminate after completion or copy errors.

## Progress

- Baseline: clean checkout; `go test ./...` succeeds with no existing tests.
- Root causes confirmed in `decrypt`, `recvHello`, and `pipe`.

- Protocol regressions: observed invalid ciphertext, IV, padding, and hello cases fail before implementation; full suite passes after validation.
- Relay regressions: observed half-close response failure and unclosed source connection before implementation; all pass after repair.
- Verification: `go test -v ./...`, `go test -race ./...`, `go vet ./...`, `go build`, and `git diff --check` passed. Loopback socket tests were run outside the socket-restricted sandbox.
- CLI end-to-end: malformed header lengths 0/1/17/>1MiB were rejected without terminating link; four concurrent requests with `preRead=4` and client write-side FIN received complete responses.
- Independent read-only review: no critical or important issues in the scoped changes.
