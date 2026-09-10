# Signed transport — auth mode `signed`

Status: implemented in muthur `0.10.0` / muthur-collector `0.11.0`.
mTLS stays the default; `signed` is opt-in per brain listener and per
collector.

## Why

The mTLS transport authenticates the collector in the TLS handshake. That
forces every hop between collector and brain to pass TLS through untouched:
Traefik `IngressRouteTCP`, Gateway API `TLSRoute`, nginx `ssl-passthrough`.
Anything that terminates TLS — Cloudflare proxy or Tunnel, an AWS/GCP/Azure
load balancer, a plain `Ingress` with cert-manager — strips the client
certificate and the brain refuses the call.

For a vendor running the brain that means one public TCP endpoint that no
WAF, bot protection or access policy can front, and a hard requirement on the
customer side that their egress path does not inspect TLS. Cloudflare in
particular does not carry gRPC through a Tunnel public hostname at all.

The fix is not a different network, it is moving authentication out of the
handshake and into the request. Once every request proves who sent it and
carries its payload encrypted end-to-end, the transport in between can be
anything that speaks HTTPS.

## Guarantees compared with mTLS

| Property                          | mTLS                     | signed                                              |
| --------------------------------- | ------------------------ | --------------------------------------------------- |
| Collector authentication          | leaf cert in handshake   | leaf cert key signs every request                   |
| Brain authentication              | server cert (vendor CA)  | edge TLS cert (WebPKI) + vendor-signed HPKE key      |
| Payload integrity                 | TLS                      | signature over method, path, body digest, headers   |
| Replay                            | TLS session + nonce      | timestamp + single-use nonce (same `ReplayGuard`)   |
| Confidentiality against the edge  | edge sees nothing        | edge sees HPKE ciphertext only                      |
| Identity source                   | peer cert SAN/CN         | `X-Muthur-Cert` leaf SAN/CN, chain-verified         |
| Revocation                        | tenants hot-reload       | identical                                           |
| PKI, bootstrap, renew             | unchanged                | unchanged                                           |

What the edge *can* see on the signed transport: that a collector with a
given certificate (the leaf is a header) talks to the brain, when, how big the
payload is, and the HTTP status. It cannot read or alter the payload, cannot
replay it, and cannot forge a request.

What is weaker than mTLS: an edge that terminates TLS can drop or delay
requests (it can do that to passthrough TCP too), and the leaf certificate is
visible to it. The leaf carries `cluster_id`/`tenant_id`, nothing secret.

## Wire protocol (v1)

All endpoints live on the brain's signed listener (`SIGNED_PORT`, default
`8082`, chart `service.signedPort`). Bodies are protobuf messages from
`proto/alert.proto`, unchanged; the contract hash is not affected.

| Method | Path                   | Message                              | Signed | Sealed |
| ------ | ---------------------- | ------------------------------------ | ------ | ------ |
| GET    | `/muthur/v1/keys`      | JSON `KeysDocument`                  | no     | no     |
| POST   | `/muthur/v1/bootstrap` | `BootstrapRequest` → `BootstrapResponse` | no  | yes    |
| POST   | `/muthur/v1/ingest`    | `AlertPayload` → `IngestResponse`    | yes    | yes    |
| POST   | `/muthur/v1/sign-csr`  | `SignCSRRequest` → `SignCSRResponse` | yes    | yes    |

### Headers on every POST

```
Content-Type:        application/vnd.muthur.sealed
Content-Digest:      sha-256=:<base64 SHA-256 of the body>:        (RFC 9530)
X-Muthur-Timestamp:  <unix seconds>
X-Muthur-Nonce:      <≥32 hex chars, crypto/rand>
X-Muthur-Hpke-Kid:   <kid of the brain key the body is sealed to>
```

Authenticated POSTs add:

```
X-Muthur-Cert:       <base64 DER of the collector leaf>
Signature-Input:     sig1=("@method" "@path" "content-digest" "x-muthur-timestamp"
                     "x-muthur-nonce" "x-muthur-cert" "x-muthur-hpke-kid");
                     created=<unix seconds>;alg="ecdsa-p256-sha256";keyid="<hex SHA-256 of leaf DER>"
Signature:           sig1=:<base64 r||s, 64 bytes>:
```

The signature base is built per RFC 9421 §2.5 over exactly that component
list; the brain rejects any other list, so coverage cannot be negotiated
down. `created` must equal `X-Muthur-Timestamp` and `keyid` must equal the
hash of the presented leaf. The key is the leaf's ECDSA P-256 key, the one
`GenerateCSR` already creates; no new key material on the collector.

### Sealed envelope

Ciphersuite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
(RFC 9180). The stdlib `crypto/hpke` implements it; there are no new
dependencies.

```
request body  = 0x01 || enc (32 bytes) || ciphertext
                info = "muthur/v1 " + path
                aad  = timestamp + "\n" + nonce
response body = 0x01 || nonce (12 bytes) || AES-256-GCM ciphertext
                key  = Export("muthur/v1 response", 32) from the request context
```

Binding `path` into `info` and the freshness headers into `aad` means a
captured envelope cannot be re-pointed at another endpoint or re-paired with
different headers even if the signature check were bypassed. The response key
is exported from the same HPKE context, so only the party that sealed the
request can read the reply. Error responses are plaintext JSON
(`{"error": "<code>", "message": "..."}`) and never contain request content.

### Key discovery

`GET /muthur/v1/keys` returns:

```json
{
  "payload":   "<base64 JSON KeysPayload>",
  "signature": "<base64 signature over the raw payload bytes>",
  "signer":    "<base64 DER of the vendor intermediate CA certificate>"
}
```

`KeysPayload` is `{"issued_at": <unix>, "keys": [{"kid", "kem", "kdf",
"aead", "public_key"}]}`, active key first. The collector verifies that
`signer` chains to its `vendorCABundle` and that `signature` verifies with
`signer`'s key before trusting any key in the payload. The payload is signed
as opaque bytes, so there is no JSON canonicalisation to get wrong. Keys are
cached for 24h; a `400 hpke_key_unknown` from the brain triggers one refetch
and retry.

### Error codes

| HTTP | `error`            | Meaning                                              | Retry |
| ---- | ------------------ | ---------------------------------------------------- | ----- |
| 400  | `bad_request`      | malformed body / headers (also gRPC `InvalidArgument`) | no  |
| 400  | `bad_digest`       | `Content-Digest` does not match body                 | no    |
| 400  | `sealed_malformed` | envelope cannot be opened                            | no    |
| 400  | `hpke_key_unknown` | brain no longer holds that `kid`                     | after refetch |
| 401  | `bad_cert`         | leaf missing, unparsable, or not chained to vendor CA | no   |
| 401  | `bad_signature`    | signature invalid or params inconsistent             | no    |
| 401  | `replay`           | timestamp outside window or nonce reused             | no    |
| 401  | `unauthenticated`  | handler-level `Unauthenticated`                      | no    |
| 403  | `unknown_tenant`, `revoked`, `forbidden` | tenant policy / cluster mismatch | no  |
| 415  | `bad_request`      | wrong `Content-Type`                                 | no    |
| 5xx  | `internal`         | brain-side failure                                   | yes   |

## Brain

Configuration:

| Env             | Chart                       | Default | Notes                                        |
| --------------- | --------------------------- | ------- | -------------------------------------------- |
| `AUTH_MODES`    | `auth.modes`                | `mtls`  | comma list of `mtls`, `signed`; both allowed |
| `SIGNED_PORT`   | `service.signedPort`        | `8082`  |                                              |
| `HPKE_KEY_FILE` | `signed.hpkeKeySecretName`  | —       | required when `signed` is on                 |

`TLS_SERVER_CERT_FILE`/`TLS_SERVER_KEY_FILE` are only required when `mtls`
is enabled. The trust root and intermediate CA files are always required:
the signed transport verifies collector leaves against them and signs the
keys document with the intermediate key.

Generate the HPKE key once per brain and keep it in a Secret (key
`hpke.pem`):

```sh
docker run --rm ghcr.io/vojtechpastyrik/muthur:<tag> hpke-keygen > hpke.pem
kubectl -n muthur create secret generic muthur-hpke --from-file=hpke.pem
```

Rotation: generate a new key, *prepend* it to the PEM file, roll the brain.
The new key is advertised, the old one keeps decrypting until you remove it.
Collectors pick the new key up within 24h or on the first
`hpke_key_unknown`.

The signed listener reuses the gRPC handlers (`grpcsrv.Server`) and the same
`ReplayGuard`, `TenantsProvider` and `Signer`; `internal/signedsrv` is the
HTTP shim the way `internal/grpcsrv` is the gRPC one. Pipeline order matches
the interceptor chain: digest → signature/identity → revocation → replay →
unseal → handler → seal.

## Collector

| Env                  | Chart          | Default | Notes                                    |
| -------------------- | -------------- | ------- | ---------------------------------------- |
| `AUTH_MODE`          | `auth.mode`    | `mtls`  | `mtls` or `signed`                       |
| `CENTRAL_AGENT_URL`  | remote secret  | —       | `host:port` for mtls, `https://host` for signed (no path prefix) |
| `SIGNED_TLS_CA_FILE` | —              | —       | pin a private edge CA; empty = system roots |

Bootstrap, renew and the forwarder all switch on `AUTH_MODE`. The bootstrap
call is sealed but unsigned (there is no key yet); the token inside the
envelope authenticates it exactly as on gRPC. Renew signs with the current
leaf and installs the new one through the existing `Persister`.

## Rollout

The transport is additive. A brain with `auth.modes: [mtls, signed]` serves
both; collectors migrate one at a time by flipping `auth.mode` and pointing
`central-agent-url` at the signed hostname. No cert re-enrolment, no proto
change, no coordinated cut.

Reference deployment: the brain sits behind a Cloudflare Tunnel on the signed
hostname; the in-cluster collector keeps mTLS on the ClusterIP; the remote
collector uses `signed`. The mTLS passthrough ingress and its public load
balancer go away.

## Non-goals

- Replacing mTLS. Passthrough deployments keep the simpler stack.
- gRPC through the edge. The signed transport is plain HTTP by design so it
  works where gRPC does not (Cloudflare Tunnel public hostnames, gRPC-hostile
  proxies).
- Hiding the leaf certificate from the edge. It identifies the cluster, it
  contains no secret, and sending it saves the brain a lookup.
- Key types other than ECDSA P-256 for request signatures. That is what the
  collector generates; supporting more adds surface for no user.
