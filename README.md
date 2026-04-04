# muthur-collector

Lightweight Kubernetes alert collector agent. Part of the [muthur](https://github.com/VojtechPastyrik) monitoring system.

Receives AlertManager webhooks, resolves alert targets via the K8s API, fetches logs from Loki and metrics from Prometheus, redacts PII and credentials, and forwards enriched protobuf payloads to [muthur](https://github.com/VojtechPastyrik/muthur).

```
AlertManager
     |
     v
muthur-collector
  - webhook receiver
  - alert target resolver
  - Loki log fetch
  - Prometheus metric fetch
  - PII redaction
  - protobuf encode + forward
     |
     v
  muthur
```

## Prerequisites

- Go 1.26+
- protoc + protoc-gen-go
- Helm 3

## Quick start

```bash
make proto
cp .env.example .env
# Edit .env with cluster ID, muthur server URL, and token
make dev
```

## Deploy via Helm

```bash
helm repo add vojtechpastyrik https://vojtechpastyrik.github.io/charts
helm repo update

helm install muthur-collector vojtechpastyrik/muthur-collector \
  --namespace monitoring \
  --set config.clusterId=my-cluster \
  --set config.lokiUrl=http://loki.monitoring.svc:3100 \
  --set config.prometheusUrl=http://prometheus.monitoring.svc:9090
```

## PII redaction

All log lines are redacted before forwarding. Categories: email, phone, SSN, addresses, IPv4/IPv6, Bearer tokens, JWT, AWS keys, API keys, passwords, credit cards, IBAN, UUID. Custom patterns supported via `REDACT_EXTRA_PATTERNS`.

## License

MIT
