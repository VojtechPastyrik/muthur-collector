# Changelog

## [0.3.0] — Unreleased

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

See [docs/migration-0.3-mtls.md](docs/migration-0.3-mtls.md). A
coordinated brain (`muthur` chart 0.7.0) + collector (this chart
0.3.0) merge is required. There is no dual-accept mode — collectors
on 0.2.x will be rejected by a 0.7.0 brain, and 0.3.0 collectors will
be rejected by a 0.6.x brain.

## [0.2.0]

- Fail-closed redaction, query bounds, storm protection, proto guard.

(See git history for earlier releases.)
