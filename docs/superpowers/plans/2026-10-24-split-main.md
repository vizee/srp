# Split main.go by responsibility

**Goal:** Make the project easier to navigate through file organization, keeping the same package, declarations, behavior, CLI, and encrypted wire protocol.

## File map

- `main.go`: command dispatch, help, shared argument state, debug logging, fatal errors.
- `crypto.go`: control-message AES-CBC primitives and shared-key loading.
- `protocol.go`: control-message frames, handshake, and JSON messages.
- `relay.go`: bidirectional forwarding and half-close handling.
- `link.go`: link mode, pairing, user handling, and its command options.
- `agent.go`: agent mode, dialing, reconnecting, and its command options.
- `systemd.go`: service unit generation and its command options.
- `encrypted_conn.go`: existing AES-GCM data connection, unchanged.
- `protocol_test.go`, `relay_test.go`: existing tests moved from `main_test.go` into matching groups; cross-file helpers remain in package main.

## Steps

- [x] Capture the original files and verify the current test/build baseline.
- [x] Move declarations verbatim, update imports, and run gofmt. No new abstractions, dependencies, renames, or behavioral changes.
- [x] Compare parsed declarations before/after, run the full suite with race detection, run vet and build, and compare CLI help and generated service output.

## Progress

- Original checkout is clean. Original source and tests are copied to temporary storage for comparison.

- Completed: `main.go` reduced from 649 lines to 57; existing control-protocol and relay tests are grouped into matching files.
- AST declaration comparison: all 39 production declarations and all 37 test declarations are unchanged, excluding imports and file placement.
- CLI comparison: six help/service-generation cases match before and after, with executable paths normalized.
- Verification passed: full suite with `go test -race ./...`, `go vet ./...`, `go build`, and `git diff --check`. No behavior changes or additional tests were introduced.
