# Preflight Implementation Plan

> Implement inline using executing-plans and test-driven-development.

**Goal:** Prepare encrypted connections before data requests and upgrade them.
**Architecture:** Existing Stream encryption, relay key registry and admission,
bounded expose workers that serialize heartbeat and upgrade IO.
**Tech Stack:** Go standard library.
**Spec:** `docs/superpowers/specs/2026-10-28-preflight-design.md`

## Constraints and review focus

- Idle preflight connections outlive their control until heartbeat rejection.
- Upgrade must never claim another control's request or consume an ID twice.
- Heartbeat writes must stop before business bytes, including server-first data.
- Failed attempts and upgrades must release capacity exactly once.
- Shutdown must join workers from previous control sessions.

## Tasks

1. Protocol/config: add Hello.PreflightKey and Message.PreflightKey /
   MaxPreflightConns; validate hello field combinations. Add relay CLI default
   and range checks, pass option through main. Test valid/invalid hellos and CLI.
2. Relay: control key registry, ready metadata, idle slot accounting,
   heartbeat checking and owner-checked upgrade sharing serveData's claim path.
   Test limits, key expiry without proactive close, bad heartbeat, timeout,
   cross-owner and duplicate/expired upgrade, and encrypted bridging.
3. Expose: bounded preflight workers, serialized heartbeats/upgrade, refill,
   pool-empty fallback, and process-owned worker lifetime. Test reuse/refill,
   heartbeat-to-data transition, old-pool lifetime and shutdown.
4. Document protocol/config; run `go test ./...`, `go test -race ./...`,
   `go vet ./...`, inspect diff and fix material findings.

## Progress

- Baseline `go test ./...` passed. Worked in the provided checkout without
  creating a branch or committing changes.
- Tasks 1–3 complete: hello/config validation, relay admission/upgrade/lifetime,
  expose bounded pool/refill/fallback and process-owned cleanup. Each new
  component's tests failed before implementation and passed afterward.
- User confirmed relay configuration with default 8, empty-pool direct data
  fallback and automatic refill.
- Independent read-only review found no Critical/Important issues. Its timeout
  observation was reproduced by `TestPreflightTimeoutStartsAtHeartbeatReceipt`
  (100 ms response delay extended the timeout), then fixed: the deadline is
  based on receipt time. That test now passes.
- Final `env CGO_ENABLED=1 CC=clang go test -race ./...` passed for all six
  packages. CGO defaults to disabled in this environment, so clang was selected
  explicitly. `go vet ./...` and `git diff --check` passed.
- README documents protocol fields, pool behavior, capacity parameter and
  paired expose/relay updates. No deferred review findings remain.
