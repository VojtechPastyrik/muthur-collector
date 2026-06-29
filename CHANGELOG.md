# Changelog

## [0.8.1] — 2026-06-29

### Added

- **Redaction applied beyond log lines.** Alert annotations (Summary,
  Description), label names, label values, and metric descriptions now run
  through the same pattern set as Loki log lines before forwarding. Before
  this, only `RedactedLogs` were sanitized — Prometheus labels routinely
  carry user IDs and emails in annotations, which reached the downstream
  LLM raw. Label *names* are now redacted too, since a custom label like
  `customer_email_alice_at_example_com=true` leaks structure even when the
  value is benign.
- **Size guard for free-text fields.** Annotation, label, and metric
  description strings over 16 KiB are replaced with a fail-closed marker
  `[redacted: string dropped by size guard]`. Mirrors the per-line guard
  on the log path; closes an attacker-controlled-annotation inflation
  vector.
- **IPv6 short forms** (`::1`, `::ffff:127.0.0.1`, `::2001:db8`) are now
  caught by the redactor. The previous pattern required two or more groups
  before the `::`, so leading-compressed forms slipped through.
- **Redaction metrics.** New counter
  `muthur_collector_redact_replacements_total{surface=log_line|string}`
  surfaces both paths so a drop in either (e.g. label-value redactions
  silently falling to zero after a pattern regression) is visible as a
  metric. The fail-closed string drop is tracked alongside line drops as
  `muthur_collector_log_lines_dropped_total{reason=oversize-string}`.
- **Adversarial + fuzz tests** for the redactor. Table-driven cases pin
  known-edge behaviour (compressed IPv6, multi-email lines, plus-tagged
  addresses, etc.); a Go `FuzzRedact_NoEmailLeak` target asserts that no
  surrounding junk lets an embedded email survive the redactor.

## [0.8.0] — 2026-06-28

### Changed

- **Breaking wire format.** The collector now talks to the brain via
  gRPC instead of REST. `forwarder` issues `Brain.Ingest`; bootstrap and
  renew flows issue `Brain.BootstrapCert` and `Brain.SignCSR`. Requires
  `muthur` chart ≥ 0.8.0; deploy the two in lockstep.
- Replay protection (timestamp + nonce) now rides on gRPC outgoing
  metadata (`x-muthur-timestamp`, `x-muthur-nonce`) instead of HTTP
  headers. Same uniqueness semantics.
- `CENTRAL_AGENT_URL` can stay as `https://muthur-api…` (the scheme is
  stripped before dialling) or be set to a bare `host:port`. No `/ingest`
  suffix — the brain endpoint no longer has a path.
- Internal retry classification moved from HTTP status codes to gRPC
  status codes: `Unavailable` / `DeadlineExceeded` retry; everything
  else (`Unauthenticated`, `PermissionDenied`, `InvalidArgument`,
  `FailedPrecondition`, `NotFound`, `Unimplemented`) is permanent.

## [0.7.1] — 2026-06-28

### Fixed

- Add `fsGroup: 65532` to the collector pod's and renew CronJob's
  security contexts. Without it, kubelet kept the mounted Secret files
  at root:root, and the bootstrap init container (uid 65532) failed
  with:

      error: read bootstrap token: open /secrets/bootstrap/token: permission denied

  fsGroup triggers kubelet to chgrp every mounted Secret/ConfigMap
  file to the supplied gid before the container starts, which makes
  the bootstrap token and vendor CA readable to the collector user
  without weakening the mode bits or running as root.

## [0.7.0] — 2026-06-28

Theme: the collector now talks to the brain over mutual TLS. The
shared bearer token (`X-Collector-Token`) is gone.

### Added

- **Three operating modes** in the same binary, dispatched from
  `os.Args[1]`:
  - `serve` — the long-running forwarder (default).
  - `bootstrap` — one-shot. Reads the SOPS-delivered one-time token,
    generates a P-256 keypair, sends a CSR to `/bootstrap-cert`, and
    persists the issued leaf + CA into a Kubernetes Secret.
  - `renew` — one-shot. Loads the current cert, mints a fresh keypair,
    sends a CSR to `/sign-csr` over mTLS, and atomically updates the
    same Secret.
- **`auth.ClientReloader`** wires through `tls.Config.GetClientCertificate`
  on the forwarder's HTTP transport, so renewals take effect on the
  next outbound handshake without restarting the collector.
- **Replay headers** on every outbound POST: `X-Muthur-Timestamp` and
  a 128-bit hex `X-Muthur-Nonce`. The brain's ReplayGuard accepts
  fresh, single-use requests and rejects replays.
- **Helm chart bootstrap init container + renew CronJob.** The cert
  Secret survives pod restarts (so the one-time token is never
  re-burned) and is updated in place by the daily renewal. The chart
  ships a narrow Role for the SA scoped to the specific Secret
  resourceName.
- **Vendor CA bundle** carried in `values.auth.vendorCABundle` so the
  bootstrap call can verify the brain before the collector has its
  own cert. The brain returns the chain on bootstrap, so steady-state
  trust lives in the cert Secret too.
- Optional `TENANT_ID` env / `config.tenantId` value feeds the cert's
  SPIFFE URI SAN (`spiffe://muthur/<tenant>/<cluster>`).

### Changed

- The forwarder now dials HTTPS with a TLS client cert sourced through
  `ClientReloader`. The brain is verified against the vendor root CA
  mounted from the same Secret as the leaf.
- 4xx responses from `/ingest` are now permanent: the brain rejected
  identity, replay, or proto, none of which retries can fix. 5xx
  retries still back off three times.
- Probes still HTTP (the collector's local /healthz is plain).

### Removed (BREAKING)

- `X-Collector-Token` header on `/ingest`. The brain refuses requests
  without a verified client cert.
- `CENTRAL_AGENT_TOKEN` env var. Gone everywhere.
- Chart values `externalSecrets.<*>` that referenced a token; the
  remote-store property pulled in now is `bootstrap-token` instead
  (configurable via `externalSecrets.bootstrapTokenProperty`).
- `devSecrets.centralAgentToken`. Replaced by `devSecrets.bootstrapToken`.

### Migration

See [docs/migration-0.7-mtls.md](docs/migration-0.7-mtls.md). A
coordinated brain (`muthur` chart 0.7.0) + collector (this chart
0.7.0) merge is required. There is no dual-accept mode — collectors
on 0.2.x will be rejected by a 0.7.0 brain, and 0.7.0 collectors will
be rejected by a 0.6.x brain.

## [0.2.0]

- Fail-closed redaction, query bounds, storm protection, proto guard.

(See git history for earlier releases.)
