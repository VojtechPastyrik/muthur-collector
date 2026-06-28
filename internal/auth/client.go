package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// bootstrapRequest mirrors the brain's BootstrapRequest shape. Kept private
// because callers feed it through Bootstrap(), which assembles the JSON.
type bootstrapRequest struct {
	ClusterID      string `json:"clusterId"`
	BootstrapToken string `json:"bootstrapToken"`
	CSR            string `json:"csr"`
}

// renewRequest mirrors the brain's RenewRequest.
type renewRequest struct {
	CSR string `json:"csr"`
}

// signResponse covers both bootstrap and renew responses (the shapes are
// identical — leaf + CA chain).
type signResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// BrainClient talks to the brain's CA endpoints. It carries its own HTTP
// client because the TLS configuration differs from the forwarder's: the
// bootstrap call has no client cert yet but still needs the vendor root CA
// to verify the brain.
type BrainClient struct {
	baseURL string
	caPool  *x509.CertPool
}

// NewBrainClient returns a client that trusts the supplied vendor root CA
// when verifying the brain. caRootFile MUST be a PEM bundle containing the
// brain's trust root — this is what cert-manager wrote into the collector's
// chart as ca.crt at install time (preseeded with the chart) or from a
// previous successful bootstrap.
func NewBrainClient(baseURL, caRootFile string) (*BrainClient, error) {
	pem, err := os.ReadFile(caRootFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("auth: CA bundle has no usable PEM certificates")
	}
	return &BrainClient{baseURL: baseURL, caPool: pool}, nil
}

// Bootstrap exchanges a one-time token + CSR for the collector's first leaf
// cert. The call deliberately presents NO client cert: the bootstrap path
// authenticates by hashed token, and the listener is configured with
// VerifyClientCertIfGiven so a cert-less handshake is accepted on that route.
//
// The returned certificate and CA bundle are PEM-encoded and ready to be
// passed to WriteMaterial.
func (c *BrainClient) Bootstrap(ctx context.Context, clusterID, token string, csrPEM []byte) (cert, ca []byte, err error) {
	if clusterID == "" || token == "" || len(csrPEM) == 0 {
		return nil, nil, errors.New("auth: clusterID, token, and CSR are required")
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: c.caPool},
		},
	}
	body, _ := json.Marshal(bootstrapRequest{
		ClusterID:      clusterID,
		BootstrapToken: token,
		CSR:            string(csrPEM),
	})
	return c.postSign(ctx, client, "/bootstrap-cert", body)
}

// Renew exchanges a CSR for a fresh leaf using the collector's existing
// client cert (passed via clientCert). The CSR carries a new public key; the
// brain re-uses the identity from the verified peer cert.
func (c *BrainClient) Renew(ctx context.Context, clientCert tls.Certificate, csrPEM []byte) (cert, ca []byte, err error) {
	if len(csrPEM) == 0 {
		return nil, nil, errors.New("auth: CSR required")
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      c.caPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}
	body, _ := json.Marshal(renewRequest{CSR: string(csrPEM)})
	return c.postSign(ctx, client, "/sign-csr", body)
}

// postSign POSTs the encoded body to path and parses the standard
// {certificate, ca} response. Used by both Bootstrap and Renew because the
// only thing that varies between them is the TLS client configuration.
//
// Replay headers (X-Muthur-Timestamp, X-Muthur-Nonce) are attached here so
// /sign-csr (which the brain replay-protects) is satisfied. /bootstrap-cert
// ignores them, but emitting them unconditionally keeps the two paths
// symmetric.
func (c *BrainClient) postSign(ctx context.Context, client *http.Client, path string, body []byte) ([]byte, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	stampReplayHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read a tail of the body for diagnostics — the brain returns a plain
		// text message on errors. Cap so a hostile/big response can't bloat
		// the collector log.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, nil, fmt.Errorf("%s: status %d: %s", path, resp.StatusCode, bytes.TrimSpace(snippet))
	}

	var out signResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Certificate == "" {
		return nil, nil, errors.New("brain returned empty certificate")
	}
	return []byte(out.Certificate), []byte(out.CA), nil
}
