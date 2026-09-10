package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

// Signed-transport header names. Shared byte-for-byte with muthur-collector;
// keep the two copies identical.
const (
	HeaderTimestamp      = "X-Muthur-Timestamp"
	HeaderNonce          = "X-Muthur-Nonce"
	HeaderCert           = "X-Muthur-Cert"
	HeaderHPKEKid        = "X-Muthur-Hpke-Kid"
	HeaderContentDigest  = "Content-Digest"
	HeaderSignatureInput = "Signature-Input"
	HeaderSignature      = "Signature"

	SignatureLabel = "sig1"
	SignatureAlg   = "ecdsa-p256-sha256"

	SealedContentType = "application/vnd.muthur.sealed"
)

// signedComponents is the fixed component list of every signed request
// (RFC 9421 §2). The order is part of the signature base; both peers must
// agree on it, so it is not negotiable per request.
var signedComponents = []string{
	"@method",
	"@path",
	"content-digest",
	"x-muthur-timestamp",
	"x-muthur-nonce",
	"x-muthur-cert",
	"x-muthur-hpke-kid",
}

var (
	ErrSignatureMissing   = errors.New("auth: request is not signed")
	ErrSignatureMalformed = errors.New("auth: malformed signature headers")
	ErrSignatureInvalid   = errors.New("auth: signature verification failed")
	ErrSignatureKeyType   = errors.New("auth: signing key must be ECDSA P-256")
	ErrDigestMismatch     = errors.New("auth: content-digest does not match body")
)

// ContentDigest renders the RFC 9530 sha-256 digest field for body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// VerifyContentDigest checks the Content-Digest header against body.
func VerifyContentDigest(h http.Header, body []byte) error {
	want := ContentDigest(body)
	got := strings.TrimSpace(h.Get(HeaderContentDigest))
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return ErrDigestMismatch
	}
	return nil
}

// CertKeyID is the keyid carried in Signature-Input: the hex SHA-256 of the
// leaf certificate's DER encoding.
func CertKeyID(leafDER []byte) string {
	sum := sha256.Sum256(leafDER)
	return hex.EncodeToString(sum[:])
}

func signatureParams(created int64, keyID string) string {
	var b strings.Builder
	b.WriteString("(")
	for i, c := range signedComponents {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%q", c)
	}
	fmt.Fprintf(&b, ");created=%d;alg=%q;keyid=%q", created, SignatureAlg, keyID)
	return b.String()
}

// SignatureBase builds the RFC 9421 §2.5 signature base for the fixed
// component set. Header values are read from h; derived components from
// method and path.
func SignatureBase(method, path string, h http.Header, params string) string {
	var b strings.Builder
	for _, c := range signedComponents {
		var v string
		switch c {
		case "@method":
			v = strings.ToUpper(method)
		case "@path":
			v = path
		default:
			v = strings.TrimSpace(h.Get(c))
		}
		fmt.Fprintf(&b, "%q: %s\n", c, v)
	}
	fmt.Fprintf(&b, "%q: %s", "@signature-params", params)
	return b.String()
}

// SignRequest computes Signature-Input and Signature over the headers already
// present in h. The caller must have set Content-Digest, X-Muthur-Timestamp,
// X-Muthur-Nonce, X-Muthur-Cert and X-Muthur-Hpke-Kid beforehand.
func SignRequest(h http.Header, method, path string, key *ecdsa.PrivateKey, leafDER []byte, created int64) error {
	if key == nil || key.Curve != elliptic.P256() {
		return ErrSignatureKeyType
	}
	params := signatureParams(created, CertKeyID(leafDER))
	digest := sha256.Sum256([]byte(SignatureBase(method, path, h, params)))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return fmt.Errorf("auth: sign request: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	h.Set(HeaderSignatureInput, SignatureLabel+"="+params)
	h.Set(HeaderSignature, SignatureLabel+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// SignatureInfo is what VerifyRequest learned from a valid signature.
type SignatureInfo struct {
	Created int64
	KeyID   string
}

// VerifyRequest checks the Signature headers of an incoming request against
// pub. It verifies the signature bytes only; the caller is responsible for
// validating the certificate the key came from and for the freshness of
// Created.
func VerifyRequest(method, path string, h http.Header, pub *ecdsa.PublicKey) (*SignatureInfo, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, ErrSignatureKeyType
	}
	inputRaw := strings.TrimSpace(h.Get(HeaderSignatureInput))
	sigRaw := strings.TrimSpace(h.Get(HeaderSignature))
	if inputRaw == "" || sigRaw == "" {
		return nil, ErrSignatureMissing
	}

	params, ok := strings.CutPrefix(inputRaw, SignatureLabel+"=")
	if !ok {
		return nil, ErrSignatureMalformed
	}
	info, err := parseSignatureParams(params)
	if err != nil {
		return nil, err
	}

	sigB64, ok := strings.CutPrefix(sigRaw, SignatureLabel+"=:")
	if !ok || !strings.HasSuffix(sigB64, ":") {
		return nil, ErrSignatureMalformed
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(sigB64, ":"))
	if err != nil || len(sig) != 64 {
		return nil, ErrSignatureMalformed
	}

	digest := sha256.Sum256([]byte(SignatureBase(method, path, h, params)))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrSignatureInvalid
	}
	return info, nil
}

// parseSignatureParams accepts only the exact component list this package
// signs, so a peer cannot downgrade coverage by omitting components.
func parseSignatureParams(params string) (*SignatureInfo, error) {
	closing := strings.Index(params, ")")
	if !strings.HasPrefix(params, "(") || closing < 0 {
		return nil, ErrSignatureMalformed
	}
	wantList := signatureParams(0, "")
	wantList = wantList[:strings.Index(wantList, ")")+1]
	if params[:closing+1] != wantList {
		return nil, fmt.Errorf("%w: unexpected covered components", ErrSignatureMalformed)
	}

	info := &SignatureInfo{}
	seen := map[string]bool{}
	for _, kv := range strings.Split(params[closing+1:], ";") {
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || seen[k] {
			return nil, ErrSignatureMalformed
		}
		seen[k] = true
		switch k {
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, ErrSignatureMalformed
			}
			info.Created = n
		case "alg":
			if v != strconv.Quote(SignatureAlg) {
				return nil, fmt.Errorf("%w: alg %s", ErrSignatureMalformed, v)
			}
		case "keyid":
			id, err := strconv.Unquote(v)
			if err != nil {
				return nil, ErrSignatureMalformed
			}
			info.KeyID = id
		default:
			return nil, fmt.Errorf("%w: unknown parameter %q", ErrSignatureMalformed, k)
		}
	}
	if !seen["created"] || !seen["alg"] || !seen["keyid"] {
		return nil, ErrSignatureMalformed
	}
	return info, nil
}
