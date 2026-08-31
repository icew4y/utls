package tls

import (
	"crypto"
	"crypto/fips140"
	"crypto/mldsa"
	"testing"
)

func TestGoMLDSASupportedMatchesFIPSModule(t *testing.T) {
	want := fips140.Version() != "v1.0.0"
	if got := goMLDSASupported(); got != want {
		t.Fatalf("goMLDSASupported() = %v, want %v for FIPS module %s", got, want, fips140.Version())
	}
}

func TestLegacyTypeAndHashRejectsMLDSA(t *testing.T) {
	requireGoMLDSASupported(t)

	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := legacyTypeAndHashFromPublicKey(priv.PublicKey()); err == nil {
		t.Fatal("legacy signature path accepted ML-DSA")
	}
}

func TestMLDSAStandardLibraryVerifyHandshakeSignature(t *testing.T) {
	requireGoMLDSASupported(t)

	tests := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"mldsa44", mldsa.MLDSA44()},
		{"mldsa65", mldsa.MLDSA65()},
		{"mldsa87", mldsa.MLDSA87()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(test.params)
			if err != nil {
				t.Fatal(err)
			}
			pub := priv.PublicKey()
			msg := []byte("uTLS ML-DSA CertificateVerify input")
			sig, err := priv.Sign(nil, msg, crypto.Hash(0))
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, msg, sig); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			sig[0] ^= 0x80
			if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, msg, sig); err == nil {
				t.Fatal("invalid signature accepted")
			}
		})
	}
}

func TestVerifyHandshakeSignatureMLDSARequiresDirectSigning(t *testing.T) {
	requireGoMLDSASupported(t)

	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	msg := []byte("uTLS ML-DSA CertificateVerify input")
	sig, err := priv.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHandshakeSignature(signatureMLDSA, pub, crypto.SHA256, msg, sig); err == nil {
		t.Fatal("ML-DSA signature accepted with a pre-hash function")
	}
}

func TestSelectSignatureSchemeMLDSARequiresTLS13(t *testing.T) {
	requireGoMLDSASupported(t)

	cert, err := X509KeyPair([]byte(testMLDSA44CertPEM), []byte(testingKeyToPrivateKeyPEM(testMLDSA44KeyPEM)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectSignatureScheme(VersionTLS12, &cert, []SignatureScheme{MLDSA44}); err == nil {
		t.Fatal("TLS 1.2 selected ML-DSA signature scheme")
	}
	got, err := selectSignatureScheme(VersionTLS13, &cert, []SignatureScheme{MLDSA44})
	if err != nil {
		t.Fatal(err)
	}
	if got != MLDSA44 {
		t.Fatalf("selected %v, want %v", got, MLDSA44)
	}
}
