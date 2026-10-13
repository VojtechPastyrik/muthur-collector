package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// Signed-transport endpoints on the brain. Mirrors signedsrv in muthur.
const (
	SignedPathKeys      = "/muthur/v1/keys"
	SignedPathBootstrap = "/muthur/v1/bootstrap"
	SignedPathIngest    = "/muthur/v1/ingest"
	SignedPathSignCSR   = "/muthur/v1/sign-csr"
	SignedPathHeartbeat = "/muthur/v1/heartbeat"

	// Error code the brain returns when it no longer holds the HPKE key a
	// request was sealed to; the client refetches keys and retries once.
	codeHPKEKeyUnknown = "hpke_key_unknown"

	signedKeysTTL     = 24 * time.Hour
	signedCallTimeout = 30 * time.Second
	maxSignedResponse = 4 << 20
)

// HTTPError is a non-2xx reply from the brain's signed transport.
type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("brain replied %d %s: %s", e.Status, e.Code, e.Message)
}

// Permanent reports whether a retry without operator intervention could
// change the answer. Mirrors forwarder.isPermanent for gRPC codes.
func (e *HTTPError) Permanent() bool {
	switch e.Status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusPreconditionFailed,
		http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return true
	}
	return false
}

// SignedClient talks to the brain over the signed HTTP transport: every
// request is HPKE-sealed to the brain's advertised key and, once the
// collector holds a leaf cert, signed with that cert's key. TLS to the edge is
// ordinary WebPKI (or a private edge CA); the vendor CA only vouches for the
// brain's HPKE keys and, through the leaf, for the collector.
type SignedClient struct {
	base   string
	http   *http.Client
	vendor *x509.CertPool
	now    func() time.Time

	mu      sync.Mutex
	keys    []HPKEPublicKey
	fetched time.Time
}

// NewSignedClient builds a client for baseURL (scheme + host, no path).
// vendorCAFile is the brain's trust root bundle; edgeCAFile optionally pins
// the CA that signed the edge's TLS certificate (empty = system roots).
func NewSignedClient(baseURL, vendorCAFile, edgeCAFile string) (*SignedClient, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("auth: parse brain URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("auth: brain URL must be http(s)://host, got %q", baseURL)
	}
	if p := strings.Trim(u.Path, "/"); p != "" || u.RawQuery != "" {
		// The endpoint path is part of the signature base; a prefix the edge
		// strips would make every signature fail on the brain.
		return nil, fmt.Errorf("auth: brain URL must not carry a path prefix, got %q", baseURL)
	}

	vendorPEM, err := os.ReadFile(vendorCAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	vendor := x509.NewCertPool()
	if !vendor.AppendCertsFromPEM(vendorPEM) {
		return nil, errors.New("auth: CA bundle has no usable PEM certificates")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if edgeCAFile != "" {
		edgePEM, err := os.ReadFile(edgeCAFile)
		if err != nil {
			return nil, fmt.Errorf("read edge CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(edgePEM) {
			return nil, errors.New("auth: edge CA bundle has no usable PEM certificates")
		}
		tlsCfg.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	transport.ForceAttemptHTTP2 = true

	return &SignedClient{
		base:   u.Scheme + "://" + u.Host,
		http:   &http.Client{Transport: transport, Timeout: signedCallTimeout},
		vendor: vendor,
		now:    time.Now,
	}, nil
}

// Bootstrap exchanges the one-time token + CSR for the first leaf. The
// request is sealed but unsigned — there is no key to sign with yet.
func (c *SignedClient) Bootstrap(ctx context.Context, clusterID, token string, csrPEM []byte) (cert, ca []byte, err error) {
	if clusterID == "" || token == "" || len(csrPEM) == 0 {
		return nil, nil, errors.New("auth: clusterID, token, and CSR are required")
	}
	var resp pb.BootstrapResponse
	if err := c.call(ctx, SignedPathBootstrap, &pb.BootstrapRequest{
		ClusterId:      clusterID,
		BootstrapToken: token,
		Csr:            string(csrPEM),
	}, &resp, nil); err != nil {
		return nil, nil, fmt.Errorf("bootstrap call: %w", err)
	}
	if resp.GetCertificate() == "" {
		return nil, nil, errors.New("brain returned empty certificate")
	}
	return []byte(resp.GetCertificate()), []byte(resp.GetCa()), nil
}

// Renew exchanges a CSR for a fresh leaf, signing the request with the
// current cert.
func (c *SignedClient) Renew(ctx context.Context, clientCert tls.Certificate, csrPEM []byte) (cert, ca []byte, err error) {
	if len(csrPEM) == 0 {
		return nil, nil, errors.New("auth: CSR required")
	}
	var resp pb.SignCSRResponse
	if err := c.call(ctx, SignedPathSignCSR, &pb.SignCSRRequest{Csr: string(csrPEM)}, &resp, &clientCert); err != nil {
		return nil, nil, fmt.Errorf("renew call: %w", err)
	}
	if resp.GetCertificate() == "" {
		return nil, nil, errors.New("brain returned empty certificate")
	}
	return []byte(resp.GetCertificate()), []byte(resp.GetCa()), nil
}

// Ingest ships one AlertPayload, signed with clientCert.
func (c *SignedClient) Ingest(ctx context.Context, payload *pb.AlertPayload, clientCert *tls.Certificate) error {
	if clientCert == nil {
		return errors.New("auth: client cert required for ingest")
	}
	var resp pb.IngestResponse
	return c.call(ctx, SignedPathIngest, payload, &resp, clientCert)
}

// Heartbeat reports collector liveness over the signed transport.
func (c *SignedClient) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest, clientCert *tls.Certificate) error {
	if clientCert == nil {
		return errors.New("auth: client cert required for heartbeat")
	}
	var resp pb.HeartbeatResponse
	return c.call(ctx, SignedPathHeartbeat, req, &resp, clientCert)
}

func (c *SignedClient) call(ctx context.Context, path string, req, resp proto.Message, cred *tls.Certificate) error {
	raw, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("auth: encode request: %w", err)
	}
	err = c.once(ctx, path, raw, resp, cred, false)
	var he *HTTPError
	if errors.As(err, &he) && he.Code == codeHPKEKeyUnknown {
		err = c.once(ctx, path, raw, resp, cred, true)
	}
	return err
}

func (c *SignedClient) once(ctx context.Context, path string, raw []byte, resp proto.Message, cred *tls.Certificate, refreshKeys bool) error {
	key, err := c.activeKey(ctx, refreshKeys)
	if err != nil {
		return err
	}
	created := c.now().Unix()
	timestamp := strconv.FormatInt(created, 10)
	nonce := FreshNonce()

	body, opener, err := SealRequest(key.Key, path, timestamp, nonce, raw)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	h := httpReq.Header
	h.Set("Content-Type", SealedContentType)
	h.Set("Accept", SealedContentType)
	h.Set(HeaderContentDigest, ContentDigest(body))
	h.Set(HeaderTimestamp, timestamp)
	h.Set(HeaderNonce, nonce)
	h.Set(HeaderHPKEKid, key.KID)
	if cred != nil {
		if len(cred.Certificate) == 0 {
			return errors.New("auth: client cert has no certificate")
		}
		priv, ok := cred.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return ErrSignatureKeyType
		}
		h.Set(HeaderCert, base64.StdEncoding.EncodeToString(cred.Certificate[0]))
		if err := SignRequest(h, http.MethodPost, path, priv, cred.Certificate[0], created); err != nil {
			return err
		}
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("auth: %s: %w", path, err)
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, maxSignedResponse))
	if err != nil {
		return fmt.Errorf("auth: read response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return decodeHTTPError(httpResp.StatusCode, data)
	}
	pt, err := opener.Open(data)
	if err != nil {
		return fmt.Errorf("auth: open response: %w", err)
	}
	if err := proto.Unmarshal(pt, resp); err != nil {
		return fmt.Errorf("auth: decode response: %w", err)
	}
	return nil
}

func decodeHTTPError(status int, data []byte) error {
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &body); err != nil || body.Error == "" {
		return &HTTPError{Status: status, Code: "http_" + strconv.Itoa(status), Message: strings.TrimSpace(string(data))}
	}
	return &HTTPError{Status: status, Code: body.Error, Message: body.Message}
}

// activeKey returns the brain's advertised HPKE key, fetching the key list
// when it is missing, stale, or explicitly refreshed.
func (c *SignedClient) activeKey(ctx context.Context, refresh bool) (HPKEPublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if refresh || len(c.keys) == 0 || c.now().Sub(c.fetched) > signedKeysTTL {
		if err := c.fetchKeysLocked(ctx); err != nil {
			return HPKEPublicKey{}, err
		}
	}
	return c.keys[0], nil
}

// keysDocument mirrors signedsrv.KeysDocument / KeysPayload on the brain.
type keysDocument struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
}

type keysPayload struct {
	IssuedAt int64 `json:"issued_at"`
	Keys     []struct {
		KID       string `json:"kid"`
		KEM       string `json:"kem"`
		KDF       string `json:"kdf"`
		AEAD      string `json:"aead"`
		PublicKey string `json:"public_key"`
	} `json:"keys"`
}

// fetchKeysLocked downloads and verifies the brain's HPKE keys. The payload
// is signed by the vendor intermediate, so an edge that could rewrite the
// document cannot substitute its own key.
func (c *SignedClient) fetchKeysLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+SignedPathKeys, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("auth: fetch brain keys: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSignedResponse))
	if err != nil {
		return fmt.Errorf("auth: read brain keys: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return decodeHTTPError(resp.StatusCode, data)
	}

	var doc keysDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("auth: decode brain keys: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(doc.Payload)
	if err != nil {
		return errors.New("auth: brain keys: malformed payload")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return errors.New("auth: brain keys: malformed signature")
	}
	signerDER, err := base64.StdEncoding.DecodeString(doc.Signer)
	if err != nil {
		return errors.New("auth: brain keys: malformed signer")
	}
	signer, err := x509.ParseCertificate(signerDER)
	if err != nil {
		return fmt.Errorf("auth: brain keys: parse signer: %w", err)
	}
	if _, err := signer.Verify(x509.VerifyOptions{
		Roots:       c.vendor,
		CurrentTime: c.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("auth: brain keys: signer not trusted by vendor CA: %w", err)
	}
	if err := VerifyPayload(signer, payload, sig); err != nil {
		return fmt.Errorf("auth: brain keys: bad signature: %w", err)
	}

	var kp keysPayload
	if err := json.Unmarshal(payload, &kp); err != nil {
		return fmt.Errorf("auth: brain keys: decode payload: %w", err)
	}
	var keys []HPKEPublicKey
	for _, k := range kp.Keys {
		if k.KEM != HPKEKEMName || k.KDF != HPKEKDFName || k.AEAD != HPKEAEADName {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			continue
		}
		pub, err := ParseHPKEPublicKey(raw)
		if err != nil || HPKEKeyID(pub) != k.KID {
			continue
		}
		keys = append(keys, HPKEPublicKey{KID: k.KID, Key: pub})
	}
	if len(keys) == 0 {
		return errors.New("auth: brain advertises no usable HPKE key")
	}
	c.keys = keys
	c.fetched = c.now()
	return nil
}
