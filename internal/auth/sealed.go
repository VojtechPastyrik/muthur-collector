package auth

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Sealed envelope, version 1:
//
//	request  body = 0x01 || enc (32 bytes, X25519) || HPKE ciphertext
//	response body = 0x01 || nonce (12 bytes)       || AES-256-GCM ciphertext
//
// Ciphersuite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. The
// response key is exported from the request's HPKE context, so a response can
// only be read by whoever sealed the matching request. The stdlib has no
// ChaCha20-Poly1305 outside HPKE, which is why AES-256-GCM is used on both
// sides.
const (
	SealedVersion = 0x01

	hpkeEncSize    = 32
	responseKeyLen = 32
	gcmNonceLen    = 12

	hpkeInfoPrefix        = "muthur/v1 "
	responseExportContext = "muthur/v1 response"

	HPKEKEMName  = "dhkem-x25519-hkdf-sha256"
	HPKEKDFName  = "hkdf-sha256"
	HPKEAEADName = "aes-256-gcm"
)

var (
	ErrSealedMalformed = errors.New("auth: malformed sealed envelope")
	ErrUnknownHPKEKey  = errors.New("auth: unknown HPKE key id")
)

var (
	hpkeKEM  = hpke.DHKEM(ecdh.X25519())
	hpkeKDF  = hpke.HKDFSHA256()
	hpkeAEAD = hpke.AES256GCM()
)

func hpkeInfo(path string) []byte { return []byte(hpkeInfoPrefix + path) }

// sealAAD binds the ciphertext to the freshness headers so the envelope
// cannot be re-paired with a different timestamp/nonce.
func sealAAD(timestamp, nonce string) []byte { return []byte(timestamp + "\n" + nonce) }

// HPKEKeyID identifies a public key: the first 8 bytes of its SHA-256, hex.
func HPKEKeyID(pub hpke.PublicKey) string {
	sum := sha256.Sum256(pub.Bytes())
	return hex.EncodeToString(sum[:8])
}

// ParseHPKEPublicKey deserialises a raw X25519 public key.
func ParseHPKEPublicKey(raw []byte) (hpke.PublicKey, error) {
	return hpkeKEM.NewPublicKey(raw)
}

// ResponseOpener decrypts the response to a request sealed with SealRequest.
type ResponseOpener struct{ key []byte }

// SealRequest encrypts plaintext to pub for the given endpoint path and
// freshness headers. It returns the envelope body and the opener for the
// matching response.
func SealRequest(pub hpke.PublicKey, path, timestamp, nonce string, plaintext []byte) ([]byte, *ResponseOpener, error) {
	enc, sender, err := hpke.NewSender(pub, hpkeKDF, hpkeAEAD, hpkeInfo(path))
	if err != nil {
		return nil, nil, fmt.Errorf("auth: hpke sender: %w", err)
	}
	ct, err := sender.Seal(sealAAD(timestamp, nonce), plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: hpke seal: %w", err)
	}
	rk, err := sender.Export(responseExportContext, responseKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: hpke export: %w", err)
	}
	body := make([]byte, 0, 1+len(enc)+len(ct))
	body = append(body, SealedVersion)
	body = append(body, enc...)
	body = append(body, ct...)
	return body, &ResponseOpener{key: rk}, nil
}

// Open decrypts a sealed response body.
func (o *ResponseOpener) Open(body []byte) ([]byte, error) {
	if len(body) < 1+gcmNonceLen || body[0] != SealedVersion {
		return nil, ErrSealedMalformed
	}
	aead, err := newGCM(o.key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, body[1:1+gcmNonceLen], body[1+gcmNonceLen:], nil)
	if err != nil {
		return nil, ErrSealedMalformed
	}
	return pt, nil
}

// ResponseSealer encrypts the response to a request opened by HPKEKeySet.
type ResponseSealer struct{ key []byte }

// Seal encrypts a response body.
func (s *ResponseSealer) Seal(plaintext []byte) ([]byte, error) {
	aead, err := newGCM(s.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("auth: response nonce: %w", err)
	}
	body := make([]byte, 0, 1+gcmNonceLen+len(plaintext)+16)
	body = append(body, SealedVersion)
	body = append(body, nonce...)
	return aead.Seal(body, nonce, plaintext, nil), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: response cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// HPKEKeySet holds the brain's decapsulation keys. The first key in the file
// is the one advertised to collectors; older keys stay accepted so a rotation
// does not cut off collectors that cached the previous public key.
type HPKEKeySet struct {
	order []string
	keys  map[string]hpke.PrivateKey
}

// GenerateHPKEKeyPEM creates a fresh X25519 key encoded as PKCS#8 PEM, the
// format LoadHPKEKeys reads.
func GenerateHPKEKeyPEM() ([]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadHPKEKeys reads one or more PKCS#8 X25519 private keys from a PEM file.
func LoadHPKEKeys(path string) (*HPKEKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read HPKE key file: %w", err)
	}
	return ParseHPKEKeys(data)
}

// ParseHPKEKeys is LoadHPKEKeys for in-memory PEM.
func ParseHPKEKeys(pemData []byte) (*HPKEKeySet, error) {
	ks := &HPKEKeySet{keys: map[string]hpke.PrivateKey{}}
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" {
			continue
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse HPKE key: %w", err)
		}
		priv, ok := parsed.(*ecdh.PrivateKey)
		if !ok || priv.Curve() != ecdh.X25519() {
			return nil, errors.New("auth: HPKE key must be X25519")
		}
		key, err := hpke.NewDHKEMPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("wrap HPKE key: %w", err)
		}
		kid := HPKEKeyID(key.PublicKey())
		if _, dup := ks.keys[kid]; dup {
			continue
		}
		ks.order = append(ks.order, kid)
		ks.keys[kid] = key
	}
	if len(ks.order) == 0 {
		return nil, errors.New("auth: no X25519 private key found in HPKE key file")
	}
	return ks, nil
}

// HPKEPublicKey is one advertised encapsulation key.
type HPKEPublicKey struct {
	KID string
	Key hpke.PublicKey
}

// Public lists the public keys, active key first.
func (ks *HPKEKeySet) Public() []HPKEPublicKey {
	out := make([]HPKEPublicKey, 0, len(ks.order))
	for _, kid := range ks.order {
		out = append(out, HPKEPublicKey{KID: kid, Key: ks.keys[kid].PublicKey()})
	}
	return out
}

// OpenRequest decrypts a sealed request body addressed to key kid and returns
// the plaintext plus the sealer for the response.
func (ks *HPKEKeySet) OpenRequest(kid, path, timestamp, nonce string, body []byte) ([]byte, *ResponseSealer, error) {
	key, ok := ks.keys[kid]
	if !ok {
		return nil, nil, ErrUnknownHPKEKey
	}
	if len(body) < 1+hpkeEncSize || body[0] != SealedVersion {
		return nil, nil, ErrSealedMalformed
	}
	enc := body[1 : 1+hpkeEncSize]
	ct := body[1+hpkeEncSize:]
	recipient, err := hpke.NewRecipient(enc, key, hpkeKDF, hpkeAEAD, hpkeInfo(path))
	if err != nil {
		return nil, nil, ErrSealedMalformed
	}
	pt, err := recipient.Open(sealAAD(timestamp, nonce), ct)
	if err != nil {
		return nil, nil, ErrSealedMalformed
	}
	rk, err := recipient.Export(responseExportContext, responseKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: hpke export: %w", err)
	}
	return pt, &ResponseSealer{key: rk}, nil
}

// SignPayload signs payload with the key behind signer using the algorithm
// implied by the key type. VerifyPayload is the inverse.
func SignPayload(signer crypto.Signer, payload []byte) ([]byte, error) {
	switch signer.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		digest := sha256.Sum256(payload)
		return signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	case ed25519.PublicKey:
		return signer.Sign(rand.Reader, payload, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("auth: unsupported signer key %T", signer.Public())
	}
}

// VerifyPayload checks a SignPayload signature against cert's public key.
func VerifyPayload(cert *x509.Certificate, payload, sig []byte) error {
	var algo x509.SignatureAlgorithm
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		algo = x509.ECDSAWithSHA256
	case *rsa.PublicKey:
		algo = x509.SHA256WithRSA
	case ed25519.PublicKey:
		algo = x509.PureEd25519
	default:
		return fmt.Errorf("auth: unsupported signer key %T", cert.PublicKey)
	}
	return cert.CheckSignature(algo, payload, sig)
}
