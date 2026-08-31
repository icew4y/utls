package tls

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestX509KeyPairUsesStandardLibraryMLDSAKeys(t *testing.T) {
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
			if cert.Leaf != nil {
				t.Fatal("X509KeyPair populated Leaf; uTLS compatibility requires it to remain nil")
			}

			block, _ := pem.Decode([]byte(test.certPEM))
			if block == nil {
				t.Fatal("failed to decode certificate PEM")
			}
			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			expectMLDSAPublicKey(t, x509Cert.PublicKey, test.sigAlg)

			priv, ok := cert.PrivateKey.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("PrivateKey = %T, want *mldsa.PrivateKey", cert.PrivateKey)
			}
			pub := x509Cert.PublicKey.(*mldsa.PublicKey)
			if !priv.PublicKey().Equal(pub) {
				t.Fatal("ML-DSA public/private key mismatch")
			}
		})
	}
}

func expectMLDSAPublicKey(t *testing.T, pub crypto.PublicKey, want SignatureScheme) {
	t.Helper()

	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey = %T, want *mldsa.PublicKey", pub)
	}
	var got SignatureScheme
	switch key.Parameters() {
	case mldsa.MLDSA44():
		got = MLDSA44
	case mldsa.MLDSA65():
		got = MLDSA65
	case mldsa.MLDSA87():
		got = MLDSA87
	default:
		t.Fatalf("unknown ML-DSA parameters %v", key.Parameters())
	}
	if got != want {
		t.Fatalf("ML-DSA signature scheme = %v, want %v", got, want)
	}
}

func testingKeyToPrivateKeyPEM(keyPEM string) string {
	keyPEM = strings.ReplaceAll(keyPEM, "BEGIN TESTING KEY", "BEGIN PRIVATE KEY")
	return strings.ReplaceAll(keyPEM, "END TESTING KEY", "END PRIVATE KEY")
}
