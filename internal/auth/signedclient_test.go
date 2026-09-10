package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// fakeSignedBrain is a minimal brain speaking the signed transport, built
// from the same primitives the real brain uses. It verifies signatures with
// the leaf it is handed and unseals with its HPKE key set.
type fakeSignedBrain struct {
	t        *testing.T
	keys     *HPKEKeySet
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	keysHits atomic.Int32

	// rotateOnce makes the first authenticated call answer hpke_key_unknown
	// after swapping keys, to exercise the client's refetch path.
	rotateOnce atomic.Bool

	lastIngest    *pb.AlertPayload
	lastBootstrap *pb.BootstrapRequest
	lastSigned    bool
}

func newFakeSignedBrain(t *testing.T) (*fakeSignedBrain, *httptest.Server, string) {
	t.Helper()
	caCert, caKey, caPEM := makeCA(t)
	keyPEM, err := GenerateHPKEKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseHPKEKeys(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeSignedBrain{t: t, keys: keys, caCert: caCert, caKey: caKey}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+SignedPathKeys, fb.serveKeys)
	mux.HandleFunc("POST "+SignedPathBootstrap, fb.handle(SignedPathBootstrap, false))
	mux.HandleFunc("POST "+SignedPathIngest, fb.handle(SignedPathIngest, true))
	mux.HandleFunc("POST "+SignedPathSignCSR, fb.handle(SignedPathSignCSR, true))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return fb, srv, caPath
}

func (fb *fakeSignedBrain) serveKeys(w http.ResponseWriter, _ *http.Request) {
	fb.keysHits.Add(1)
	var payload struct {
		IssuedAt int64 `json:"issued_at"`
		Keys     []struct {
			KID       string `json:"kid"`
			KEM       string `json:"kem"`
			KDF       string `json:"kdf"`
			AEAD      string `json:"aead"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	payload.IssuedAt = time.Now().Unix()
	for _, k := range fb.keys.Public() {
		payload.Keys = append(payload.Keys, struct {
			KID       string `json:"kid"`
			KEM       string `json:"kem"`
			KDF       string `json:"kdf"`
			AEAD      string `json:"aead"`
			PublicKey string `json:"public_key"`
		}{k.KID, HPKEKEMName, HPKEKDFName, HPKEAEADName, base64.StdEncoding.EncodeToString(k.Key.Bytes())})
	}
	raw, _ := json.Marshal(payload)
	sig, err := SignPayload(fb.caKey, raw)
	if err != nil {
		fb.t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"payload":   base64.StdEncoding.EncodeToString(raw),
		"signature": base64.StdEncoding.EncodeToString(sig),
		"signer":    base64.StdEncoding.EncodeToString(fb.caCert.Raw),
	})
}

func (fb *fakeSignedBrain) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": code})
}

func (fb *fakeSignedBrain) handle(path string, authenticated bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := VerifyContentDigest(r.Header, body); err != nil {
			fb.fail(w, http.StatusBadRequest, "bad_digest")
			return
		}
		ts := r.Header.Get(HeaderTimestamp)
		nonce := r.Header.Get(HeaderNonce)
		fb.lastSigned = false
		if authenticated {
			der, err := base64.StdEncoding.DecodeString(r.Header.Get(HeaderCert))
			if err != nil {
				fb.fail(w, http.StatusUnauthorized, "bad_cert")
				return
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				fb.fail(w, http.StatusUnauthorized, "bad_cert")
				return
			}
			if _, err := VerifyRequest(r.Method, path, r.Header, leaf.PublicKey.(*ecdsa.PublicKey)); err != nil {
				fb.fail(w, http.StatusUnauthorized, "bad_signature")
				return
			}
			fb.lastSigned = true
			if fb.rotateOnce.CompareAndSwap(true, false) {
				keyPEM, _ := GenerateHPKEKeyPEM()
				fb.keys, _ = ParseHPKEKeys(keyPEM)
				fb.fail(w, http.StatusBadRequest, codeHPKEKeyUnknown)
				return
			}
		}
		pt, sealer, err := fb.keys.OpenRequest(r.Header.Get(HeaderHPKEKid), path, ts, nonce, body)
		if errors.Is(err, ErrUnknownHPKEKey) {
			fb.fail(w, http.StatusBadRequest, codeHPKEKeyUnknown)
			return
		}
		if err != nil {
			fb.fail(w, http.StatusBadRequest, "sealed_malformed")
			return
		}
		var resp proto.Message
		switch path {
		case SignedPathBootstrap:
			var req pb.BootstrapRequest
			_ = proto.Unmarshal(pt, &req)
			fb.lastBootstrap = &req
			resp = &pb.BootstrapResponse{Certificate: "LEAF-" + req.GetClusterId(), Ca: "CA"}
		case SignedPathIngest:
			var req pb.AlertPayload
			_ = proto.Unmarshal(pt, &req)
			fb.lastIngest = &req
			resp = &pb.IngestResponse{}
		case SignedPathSignCSR:
			resp = &pb.SignCSRResponse{Certificate: "NEWLEAF", Ca: "CA"}
		}
		out, _ := proto.Marshal(resp)
		sealed, err := sealer.Seal(out)
		if err != nil {
			fb.t.Fatal(err)
		}
		w.Header().Set("Content-Type", SealedContentType)
		_, _ = w.Write(sealed)
	}
}

func TestSignedClient_RejectsPathPrefix(t *testing.T) {
	_, _, caPath := newFakeSignedBrain(t)
	if _, err := NewSignedClient("https://brain.example/api", caPath, ""); err == nil {
		t.Fatal("expected error for path prefix")
	}
	if _, err := NewSignedClient("grpc://brain.example", caPath, ""); err == nil {
		t.Fatal("expected error for non-http scheme")
	}
}

func TestSignedClient_Bootstrap(t *testing.T) {
	fb, srv, caPath := newFakeSignedBrain(t)
	c, err := NewSignedClient(srv.URL, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	cert, ca, err := c.Bootstrap(context.Background(), "cluster-a", "tok", []byte("csr"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cert) != "LEAF-cluster-a" || string(ca) != "CA" {
		t.Fatalf("cert %q ca %q", cert, ca)
	}
	if fb.lastBootstrap.GetBootstrapToken() != "tok" || fb.lastSigned {
		t.Fatalf("bootstrap %+v signed=%v", fb.lastBootstrap, fb.lastSigned)
	}
}

func TestSignedClient_IngestSignsWithLeaf(t *testing.T) {
	fb, srv, caPath := newFakeSignedBrain(t)
	c, err := NewSignedClient(srv.URL, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeLeaf(t, fb.caCert, fb.caKey, "cluster-a")
	if err := c.Ingest(context.Background(), &pb.AlertPayload{ClusterId: "cluster-a", AlertName: "Down"}, &leaf); err != nil {
		t.Fatal(err)
	}
	if !fb.lastSigned || fb.lastIngest.GetAlertName() != "Down" {
		t.Fatalf("signed=%v payload=%+v", fb.lastSigned, fb.lastIngest)
	}
	// Second call reuses the cached key list.
	if err := c.Ingest(context.Background(), &pb.AlertPayload{ClusterId: "cluster-a"}, &leaf); err != nil {
		t.Fatal(err)
	}
	if hits := fb.keysHits.Load(); hits != 1 {
		t.Fatalf("keys fetched %d times, want 1", hits)
	}
}

func TestSignedClient_RefetchesKeysOnRotation(t *testing.T) {
	fb, srv, caPath := newFakeSignedBrain(t)
	c, err := NewSignedClient(srv.URL, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeLeaf(t, fb.caCert, fb.caKey, "cluster-a")
	fb.rotateOnce.Store(true)
	if err := c.Ingest(context.Background(), &pb.AlertPayload{ClusterId: "cluster-a"}, &leaf); err != nil {
		t.Fatal(err)
	}
	if hits := fb.keysHits.Load(); hits != 2 {
		t.Fatalf("keys fetched %d times, want 2", hits)
	}
}

func TestSignedClient_Renew(t *testing.T) {
	fb, srv, caPath := newFakeSignedBrain(t)
	c, err := NewSignedClient(srv.URL, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	leaf := makeLeaf(t, fb.caCert, fb.caKey, "cluster-a")
	cert, _, err := c.Renew(context.Background(), leaf, []byte("csr"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cert) != "NEWLEAF" || !fb.lastSigned {
		t.Fatalf("cert %q signed=%v", cert, fb.lastSigned)
	}
}

func TestSignedClient_SurfacesHTTPErrors(t *testing.T) {
	fb, srv, caPath := newFakeSignedBrain(t)
	c, err := NewSignedClient(srv.URL, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	// A leaf from a foreign CA still signs correctly, so drive the failure
	// through a key the fake brain never issued: sign with a mismatched key.
	leaf := makeLeaf(t, fb.caCert, fb.caKey, "cluster-a")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf.PrivateKey = other
	err = c.Ingest(context.Background(), &pb.AlertPayload{ClusterId: "cluster-a"}, &leaf)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusUnauthorized || he.Code != "bad_signature" || !he.Permanent() {
		t.Fatalf("got %v", err)
	}
}

func TestSignedClient_RejectsKeysFromForeignSigner(t *testing.T) {
	_, srv, _ := newFakeSignedBrain(t)
	// Point the client at a different vendor CA than the one signing /keys.
	_, _, otherPEM := makeCA(t)
	otherPath := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(otherPath, otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewSignedClient(srv.URL, otherPath, "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Bootstrap(context.Background(), "cluster-a", "tok", []byte("csr"))
	if err == nil || !strings.Contains(err.Error(), "not trusted by vendor CA") {
		t.Fatalf("got %v", err)
	}
}

func TestSignedClient_PinsEdgeCA(t *testing.T) {
	fb, _, caPath := newFakeSignedBrain(t)
	// A TLS server whose cert is signed by the vendor CA stands in for a
	// private edge; pinning that CA must work, system roots must not.
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+SignedPathKeys, fb.serveKeys)
	tlsSrv := httptest.NewUnstartedServer(mux)
	serverCert := makeServerCert(t, fb.caCert, fb.caKey)
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)

	pinned, err := NewSignedClient(tlsSrv.URL, caPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.activeKey(context.Background(), true); err != nil {
		t.Fatalf("pinned edge CA: %v", err)
	}
	unpinned, err := NewSignedClient(tlsSrv.URL, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unpinned.activeKey(context.Background(), true); err == nil {
		t.Fatal("expected TLS failure without edge CA pin")
	}
}
