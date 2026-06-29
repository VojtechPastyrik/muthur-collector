# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability, please report it responsibly.

Email: vojtech@pastyrik.dev

## Security model (summary)

- **PII redaction is the security boundary.** All log lines fetched from
  Loki, plus every free-text field that leaves the cluster (alert
  annotations Summary/Description, label names + values, metric
  descriptions) go through a shared regex pattern set before forwarding.
  Categories: email, phone, SSN, addresses, IPv4 + IPv6 (including
  compressed `::1` / `::ffff:` forms), Bearer tokens, JWT, AWS keys,
  API keys, passwords, credit cards, IBAN, UUID. Custom patterns
  supported via `REDACT_EXTRA_PATTERNS`.
- **Fail closed.** A log line over `REDACT_MAX_LINE_BYTES` (8 KiB) is
  dropped — its content is never forwarded raw. Once cumulative payload
  bytes reach `REDACT_MAX_TOTAL_BYTES` (256 KiB) the remaining lines are
  dropped. A single free-text string over `REDACT_MAX_STRING_BYTES`
  (16 KiB) is replaced with a marker; closes an attacker-controlled-
  annotation inflation vector.
- **Visible drops.** Drops are exposed as
  `muthur_collector_log_lines_dropped_total{reason=oversize|budget|oversize-string}`.
  Replacement counts are exposed as
  `muthur_collector_redact_replacements_total{surface=log_line|string}`,
  so a silent regression on either surface (e.g. label-value redactions
  going to zero after a pattern regression) shows up as a metric.
- **mTLS to the brain.** The collector authenticates with an x509
  client certificate signed by the vendor intermediate CA, hot-reloaded
  from the mounted Secret. The brain enforces
  `payload.cluster_id == cert.cluster_id`.
- **Outbound-only.** No inbound port from the brain to the collector;
  the collector dials the brain. The only inbound port is the
  AlertManager webhook (bounded by `WEBHOOK_MAX_CONCURRENT`).
- **Bootstrap is one-shot.** The bootstrap token is consumed by the
  init container, validated server-side by SHA-256 with a `SetNX` guard
  so the brain refuses any reuse.

## In scope

- PII redaction bypass: novel input that slips a known category
  through the pattern set, regex ReDoS on adversarial input,
  redaction skipped on a code path that forwards untrusted text.
- Fail-closed guard bypass: a line or string that exceeds the cap but
  still gets forwarded raw.
- mTLS auth issues: cert acceptance outside the vendor chain,
  bootstrap token leakage or reuse, key file leaking into logs.
- Webhook abuse: AlertManager-shaped payload that bypasses
  concurrency cap or starves the worker pool.
- K8s RBAC escalation via the collector ServiceAccount.
- Protobuf decoder issues (panic, OOM via unbounded fields).

## Out of scope

- Vulnerabilities in upstream dependencies (report to the respective
  projects).
- Loki / Prometheus / AlertManager misconfiguration that surfaces PII
  in a category the redactor doesn't model (operator responsibility —
  add a custom pattern via `REDACT_EXTRA_PATTERNS`).
- Compromise of the underlying Kubernetes cluster.
