//go:build !nomldsa

package tls

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
)

func TestX509KeyPairAcceptsMLDSASeedAndExpandedPKCS8(t *testing.T) {
	requireGoMLDSASupported(t)

	tests := []struct {
		name         string
		certPEM      string
		keyPEM       string
		expandedSize int
	}{
		{"MLDSA44", testMLDSA44CertPEM, testMLDSA44KeyPEM, mldsa44ExpandedPrivateKeySize},
		{"MLDSA65", testMLDSA65CertPEM, testMLDSA65KeyPEM, mldsa65ExpandedPrivateKeySize},
		{"MLDSA87", testMLDSA87CertPEM, testMLDSA87KeyPEM, mldsa87ExpandedPrivateKeySize},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyPEM := testingCombinedMLDSAPrivateKeyPEM(t, test.keyPEM, test.expandedSize)
			cert, err := X509KeyPair([]byte(test.certPEM), keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cert.PrivateKey.(*mldsa.PrivateKey); !ok {
				t.Fatalf("PrivateKey = %T, want *mldsa.PrivateKey", cert.PrivateKey)
			}
		})
	}
}

func TestX509KeyPairRejectsMLDSASeedAndExpandedPKCS8WithWrongSize(t *testing.T) {
	requireGoMLDSASupported(t)

	keyPEM := testingCombinedMLDSAPrivateKeyPEM(t, testMLDSA44KeyPEM, mldsa44ExpandedPrivateKeySize-1)
	if _, err := X509KeyPair([]byte(testMLDSA44CertPEM), keyPEM); err == nil {
		t.Fatal("X509KeyPair accepted an ML-DSA key with the wrong expanded-key size")
	}
}

func testingCombinedMLDSAPrivateKeyPEM(t *testing.T, keyPEM string, expandedSize int) []byte {
	t.Helper()

	block, _ := pem.Decode([]byte(testingKeyToPrivateKeyPEM(keyPEM)))
	if block == nil {
		t.Fatal("failed to decode private key PEM")
	}

	var key struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if rest, err := asn1.Unmarshal(block.Bytes, &key); err != nil || len(rest) != 0 {
		t.Fatalf("failed to parse PKCS#8 key: rest=%d err=%v", len(rest), err)
	}

	var seed asn1.RawValue
	if rest, err := asn1.Unmarshal(key.PrivateKey, &seed); err != nil || len(rest) != 0 {
		t.Fatalf("failed to parse ML-DSA seed: rest=%d err=%v", len(rest), err)
	}
	if seed.Class != asn1.ClassContextSpecific || seed.Tag != 0 || len(seed.Bytes) != mldsa.PrivateKeySize {
		t.Fatalf("unexpected ML-DSA seed encoding: class=%d tag=%d size=%d", seed.Class, seed.Tag, len(seed.Bytes))
	}

	combined, err := asn1.Marshal(struct {
		Seed     []byte
		Expanded []byte
	}{seed.Bytes, make([]byte, expandedSize)})
	if err != nil {
		t.Fatal(err)
	}
	key.PrivateKey = combined

	der, err := asn1.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParseCertificateUsesStandardLibraryMLDSAKeys(t *testing.T) {
	requireGoMLDSASupported(t)

	tests := []struct {
		name    string
		certPEM string
		keyPEM  string
		sigAlg  SignatureScheme
	}{
		{"MLDSA44", testMLDSA44CertPEM, testMLDSA44KeyPEM, MLDSA44},
		{"MLDSA65", testMLDSA65CertPEM, testMLDSA65KeyPEM, MLDSA65},
		{"MLDSA87", testMLDSA87CertPEM, testMLDSA87KeyPEM, MLDSA87},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := X509KeyPair([]byte(test.certPEM), []byte(testingKeyToPrivateKeyPEM(test.keyPEM)))
			if err != nil {
				t.Fatal(err)
			}
			if cert.Leaf == nil {
				t.Fatal("X509KeyPair did not set Leaf")
			}
			expectMLDSAPublicKey(t, cert.Leaf.PublicKey, test.sigAlg)
			if _, ok := cert.Leaf.PublicKey.(*mldsa.PublicKey); !ok {
				t.Fatalf("PublicKey = %T, want *mldsa.PublicKey", cert.Leaf.PublicKey)
			}
			if _, ok := cert.PrivateKey.(*mldsa.PrivateKey); !ok {
				t.Fatalf("PrivateKey = %T, want ML-DSA", cert.PrivateKey)
			}
			if !publicKeyMatchesMLDSAPrivateKey(cert.Leaf.PublicKey, cert.PrivateKey) {
				t.Fatal("ML-DSA public/private key mismatch")
			}
		})
	}
}

func expectMLDSAPublicKey(t *testing.T, pub crypto.PublicKey, want SignatureScheme) {
	t.Helper()

	got, ok := mldsaSignatureSchemeForPublicKey(pub)
	if !ok {
		t.Fatalf("PublicKey = %T, want ML-DSA", pub)
	}
	if got != want {
		t.Fatalf("ML-DSA signature scheme = %v, want %v", got, want)
	}
}

func testingKeyToPrivateKeyPEM(keyPEM string) string {
	keyPEM = strings.ReplaceAll(keyPEM, "BEGIN TESTING KEY", "BEGIN PRIVATE KEY")
	return strings.ReplaceAll(keyPEM, "END TESTING KEY", "END PRIVATE KEY")
}
