# Migrating to v0.7 — collector mTLS

The collector 0.3 cuts over from the shared `X-Collector-Token` to
mutual TLS. The brain (`muthur` chart) must be on 0.7.0 at the same
time; the protocol is hard-cut, no dual-accept.

This document covers what the chart upgrade does, what the operator has
to provide, and how to validate the migration in production.

## Prerequisites

- The brain (`muthur` chart 0.7.x) is already installed in your central
  cluster. Its root CA is provisioned and you have backed up the root
  Secret to a safe.
- A bootstrap token has been generated for THIS cluster on the brain
  side. The SHA-256 hash is committed to the brain's tenant config; the
  plaintext token reaches you via a secure side channel (Signal,
  1Password Share, …) and is short-lived (24 h by convention).
- Your secrets backend (1Password Connect, Vault, …) can store the
  token under a property the collector chart can pull.
- The vendor root CA PEM (the brain's `muthur-root-ca-tls` Secret's
  `tls.crt`) is available — you will paste it into chart values.

## What the chart now ships

- `Deployment` with an `initContainer` running `collector bootstrap`.
  On first install it generates a keypair, exchanges the bootstrap
  token for a leaf cert, and writes the cert + key + CA into the
  Kubernetes Secret `{release}-tls`. On every subsequent restart it
  detects the existing Secret and exits as a no-op — the token is
  never re-burned.
- `CronJob` `{release}-renew` runs daily, mints a fresh CSR, calls
  `/sign-csr` over mTLS, and updates the same Secret in place. The
  running collector picks up the rotation via mtime watch without a
  restart.
- `Role` + `RoleBinding` for the `ServiceAccount` to get/update/create
  the cert Secret, scoped to that specific Secret resourceName.
- `Secret` `{release}-vendor-ca` carrying the vendor root CA bundle,
  pasted into `values.auth.vendorCABundle`.

## The Secret and ArgoCD

The `{release}-tls` Secret is created by the bootstrap container at
runtime, NOT by the chart. It carries no `app.kubernetes.io/instance`
label and no `argocd.argoproj.io/tracking-id` annotation, so ArgoCD
does not consider it part of the Application and never reports
OutOfSync.

As a belt-and-braces guard against `argocd app sync --prune` or
`helm uninstall` against the namespace, the bootstrap stamps two
annotations onto the Secret when it creates it:

  - `argocd.argoproj.io/sync-options=Prune=false`
  - `helm.sh/resource-policy=keep`

The Secret survives upgrades, downgrades, and accidental syncs. The
only way to lose it is `kubectl delete secret {release}-tls`.

## Per-cluster onboarding

1. **Vendor side**: open a PR against the brain's GitOps repo
   (the `muthur` `values.yaml`) adding a tenant entry for this cluster.
   Share the plaintext token with the cluster operator out of band.

2. **Cluster side**: open a PR against this cluster's GitOps repo:

   a. Add an `ExternalSecret` that pulls `central-agent-url` and
      `bootstrap-token` from your secrets backend into Kubernetes:

      ```yaml
      apiVersion: external-secrets.io/v1
      kind: ExternalSecret
      metadata:
        name: muthur-collector
        namespace: monitoring
      spec:
        refreshInterval: 1h
        secretStoreRef:
          name: onepassword-store
          kind: ClusterSecretStore
        target:
          name: muthur-collector
        data:
          - secretKey: CENTRAL_AGENT_URL
            remoteRef:
              key: muthur-collector
              property: central-agent-url
          - secretKey: bootstrap-token
            remoteRef:
              key: muthur-collector
              property: bootstrap-token
      ```

      (The chart already wires the ExternalSecret in
      `templates/external-secret.yaml` when
      `externalSecrets.enabled: true`. The example above is what the
      chart renders.)

   b. Bump the collector chart to 0.3.0 in your `values.yaml` and add
      the vendor CA PEM:

      ```yaml
      auth:
        vendorCABundle: |
          -----BEGIN CERTIFICATE-----
          MIIB... (paste the brain's muthur-root-ca-tls tls.crt here)
          -----END CERTIFICATE-----
      config:
        clusterId: cluster-acme
        tenantId: acme
      ```

   c. Drop any leftover `CENTRAL_AGENT_TOKEN` references and the old
      `centralAgentToken` value — those are gone.

3. **Merge** both PRs. The brain accepts the registration; the
   collector's init container exchanges the token for a leaf and
   writes the Secret; the main container starts mTLS-only and begins
   forwarding alerts.

4. **Validate** in the collector logs:

   ```
   bootstrap complete — cert installed cluster_id=cluster-acme
   starting muthur-collector (mTLS) cluster_id=cluster-acme
   ```

   And in the brain logs:

   ```
   bootstrap issued cluster_id=cluster-acme tenant_id=acme cert_duration=720h
   received alert cluster_id=cluster-acme ...
   ```

## Renewals

The renew CronJob runs at the schedule defined in
`values.auth.renewCron.schedule` (daily at 03:30 by default). It:

1. Reads the current cert from the `{release}-tls` Secret.
2. Generates a fresh keypair + CSR.
3. POSTs `/sign-csr` over mTLS with the OLD cert.
4. Updates the Secret with the new cert + new key + (optional) CA.
5. kubelet propagates the new Secret content into the main pod's
   mounted volume within ~60 s.
6. The next outbound TLS handshake from the forwarder uses the new
   cert (the in-process ClientReloader detects the mtime change).

There is no operator intervention. If a renewal fails for three days
in a row, the cert will expire and alerts stop flowing — at which
point manual re-onboarding (new bootstrap token, fresh PR) is the
recovery path.

## Manually rotating the cert

Either of these forces a rotation:

- `kubectl create job --from=cronjob/{release}-renew {release}-renew-manual`
- `kubectl delete pod -l app.kubernetes.io/instance={release}` — does
  NOT delete the Secret (Prune=false), so the new pod's init container
  no-ops; the running collector resumes immediately.

To force a fresh enrolment (e.g. after the cert has expired), delete
the Secret and request a new bootstrap token from the vendor:

```sh
kubectl delete secret {release}-tls
# wait for the vendor to publish a new bootstrap token and your
# ExternalSecret to pull it
kubectl rollout restart deployment/{release}
```

## What didn't survive the cut

- `CENTRAL_AGENT_TOKEN` env var and any tooling that injected it.
- Static, never-rotated per-cluster shared secrets in your secrets
  backend. The `central-agent-token` property can be deleted once the
  collector is on mTLS; replace it with `bootstrap-token`.
- The legacy `X-Collector-Token` header on `/ingest`. The brain refuses
  requests without a verified client cert as soon as it rolls to 0.7.0.

If your collector is on this chart version but the brain is still on
0.6.x, alerts will be silently rejected. Roll both, or roll the brain
first and the collectors immediately after (the brain returns 401 with
no body until you do).
