# muthur-collector Helm Chart

Helm chart for deploying `muthur-collector` into Kubernetes.

`muthur-collector` receives Alertmanager webhooks, enriches alerts with Loki/Prometheus context, redacts sensitive data, and forwards payloads to central agent.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.12+

## Install

```bash
helm repo add vojtechpastyrik https://vojtechpastyrik.github.io/charts
helm repo update

helm install muthur-collector vojtechpastyrik/muthur-collector \
  --namespace monitoring \
  --create-namespace
```

## Upgrade

```bash
helm upgrade muthur-collector vojtechpastyrik/muthur-collector \
  --namespace monitoring
```

## Uninstall

```bash
helm uninstall muthur-collector --namespace monitoring
```

## Important values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/vojtechpastyrik/muthur-collector` | Container image repository |
| `image.tag` | `""` | Image tag (defaults to chart appVersion when empty) |
| `service.port` | `8080` | Webhook service port |
| `config.clusterId` | `cluster-a` | Cluster identifier sent with forwarded alerts |
| `config.lokiUrl` | `http://loki.monitoring.svc:3100` | Loki base URL |
| `config.prometheusUrl` | `http://prometheus.monitoring.svc:9090` | Prometheus base URL |
| `config.prometheusEnabled` | `true` | Enables Prometheus metric enrichment |
| `externalSecrets.enabled` | `true` | Creates ExternalSecret for `CENTRAL_AGENT_URL` and `CENTRAL_AGENT_TOKEN` |
| `devSecrets.enabled` | `false` | Creates in-cluster Secret from plain values (dev only) |
| `resources` | requests/limits set | Pod CPU and memory resources |

## Secrets

The chart supports two secret modes:

1. `externalSecrets.enabled=true` (default): uses `ExternalSecret` and `secretStoreRef`.
2. `devSecrets.enabled=true` and `externalSecrets.enabled=false`: creates a native Kubernetes `Secret` from `devSecrets.*` values.

Set only one mode at a time.

## Example

```bash
helm upgrade --install muthur-collector vojtechpastyrik/muthur-collector \
  --namespace monitoring \
  --create-namespace \
  --set config.clusterId=prod-eu-1 \
  --set config.lokiUrl=http://loki.monitoring.svc:3100 \
  --set config.prometheusUrl=http://prometheus.monitoring.svc:9090 \
  --set externalSecrets.enabled=true \
  --set externalSecrets.secretStoreName=vault-backend \
  --set externalSecrets.remoteSecretPath=muthur-collector/prod
```

## Maintainer

- Vojtech Pastyrik (<vojtech@pastyrik.dev>)

