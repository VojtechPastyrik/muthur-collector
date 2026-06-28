package auth

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCSR_HasSpiffeURI(t *testing.T) {
	csrPEM, keyPEM, err := GenerateCSR("acme", "cluster-prod")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if len(csrPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("CSR or key PEM is empty")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR PEM does not decode")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "cluster-prod" {
		t.Errorf("CN = %q, want cluster-prod", csr.Subject.CommonName)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://muthur/acme/cluster-prod" {
		t.Errorf("URIs = %v, want [spiffe://muthur/acme/cluster-prod]", csr.URIs)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR self-signature invalid: %v", err)
	}
}

func TestGenerateCSR_NoTenantOmitsURI(t *testing.T) {
	// CN-only setups (no tenant) must still produce a verifiable CSR; the URI
	// SAN is simply omitted so the brain falls back to CN extraction.
	csrPEM, _, err := GenerateCSR("", "cluster-x")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if len(csr.URIs) != 0 {
		t.Errorf("URIs = %v, want empty (no tenant)", csr.URIs)
	}
	if csr.Subject.CommonName != "cluster-x" {
		t.Errorf("CN = %q, want cluster-x", csr.Subject.CommonName)
	}
}

func TestGenerateCSR_RejectsEmptyCluster(t *testing.T) {
	if _, _, err := GenerateCSR("acme", ""); err == nil {
		t.Error("GenerateCSR accepted empty clusterID")
	}
}

func TestWriteMaterial_Atomicity(t *testing.T) {
	dir := t.TempDir()
	m := NewMaterial(dir)
	if err := WriteMaterial(m, []byte("cert"), []byte("key"), []byte("ca")); err != nil {
		t.Fatalf("WriteMaterial: %v", err)
	}
	for _, p := range []string{m.CertFile, m.KeyFile, m.CAFile} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("read %s: %v", p, err)
		}
		if len(data) == 0 {
			t.Errorf("%s is empty", p)
		}
	}
	// No leftover *.tmp.* files should remain after a successful write.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestWriteMaterial_RotatesInPlace(t *testing.T) {
	// A subsequent WriteMaterial call must replace the previous contents
	// without leaving the files in a partial state.
	dir := t.TempDir()
	m := NewMaterial(dir)
	if err := WriteMaterial(m, []byte("v1"), []byte("v1"), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := WriteMaterial(m, []byte("v2"), []byte("v2"), []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(m.CertFile)
	if string(got) != "v2" {
		t.Errorf("cert = %q, want v2 (rotation failed)", got)
	}
}

func TestWriteMaterial_OmitsCAWhenEmpty(t *testing.T) {
	// Renewals reuse the existing CA. Empty caPEM must NOT delete or zero out
	// the previously written ca.crt — leave it alone.
	dir := t.TempDir()
	m := NewMaterial(dir)
	if err := WriteMaterial(m, []byte("c1"), []byte("k1"), []byte("ca")); err != nil {
		t.Fatal(err)
	}
	if err := WriteMaterial(m, []byte("c2"), []byte("k2"), nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(m.CAFile)
	if err != nil {
		t.Fatalf("CA file missing after empty-CA renewal: %v", err)
	}
	if string(got) != "ca" {
		t.Errorf("CA = %q, want untouched original 'ca'", got)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	m := NewMaterial(dir)
	if m.Exists() {
		t.Error("Exists = true for empty dir")
	}
	if err := WriteMaterial(m, []byte("c"), []byte("k"), nil); err != nil {
		t.Fatal(err)
	}
	if !m.Exists() {
		t.Error("Exists = false after WriteMaterial")
	}
}

func TestWriteMaterial_RejectsEmptyCertOrKey(t *testing.T) {
	dir := t.TempDir()
	m := NewMaterial(dir)
	if err := WriteMaterial(m, nil, []byte("k"), nil); err == nil {
		t.Error("WriteMaterial accepted empty cert")
	}
	if err := WriteMaterial(m, []byte("c"), nil, nil); err == nil {
		t.Error("WriteMaterial accepted empty key")
	}
}
