//go:build !nomldsa

package tls

import (
	"crypto"
	"crypto/fips140"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

func goMLDSASupported() bool {
	return fips140.Version() != "v1.0.0"
}

func defaultMLDSASignatureAlgorithms() []SignatureScheme {
	if !goMLDSASupported() {
		return nil
	}
	return []SignatureScheme{MLDSA44, MLDSA65, MLDSA87}
}

func mldsaSignatureSchemeForPublicKey(pub crypto.PublicKey) (SignatureScheme, bool) {
	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return 0, false
	}

	switch key.Parameters() {
	case mldsa.MLDSA44():
		return MLDSA44, true
	case mldsa.MLDSA65():
		return MLDSA65, true
	case mldsa.MLDSA87():
		return MLDSA87, true
	default:
		return 0, false
	}
}

func isMLDSAPrivateKey(priv crypto.PrivateKey) bool {
	_, ok := priv.(*mldsa.PrivateKey)
	return ok
}

func verifyMLDSAHandshakeSignature(pubkey crypto.PublicKey, signed, sig []byte) error {
	pub, ok := pubkey.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("tls: expected ML-DSA public key, got %T", pubkey)
	}
	if err := mldsa.Verify(pub, signed, sig, nil); err != nil {
		return fmt.Errorf("tls: ML-DSA verification failure: %w", err)
	}
	return nil
}

func parseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

var (
	oidPublicKeyMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidPublicKeyMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidPublicKeyMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

const (
	mldsa44ExpandedPrivateKeySize = 2560
	mldsa65ExpandedPrivateKeySize = 4032
	mldsa87ExpandedPrivateKeySize = 4896
)

// parseMLDSAPrivateKey handles the RFC 9881 seed-plus-expanded PKCS#8 form
// emitted by OpenSSL by default. crypto/x509 accepts only seed-only keys.
// The expanded component is validated for size but ignored; X509KeyPair later
// verifies that the key derived from the seed matches the certificate.
func parseMLDSAPrivateKey(der []byte) (crypto.PrivateKey, error) {
	var key struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &key); err != nil || len(rest) != 0 {
		return nil, errors.New("tls: invalid ML-DSA PKCS#8 private key")
	}
	if key.Version != 0 || len(key.Algorithm.Parameters.FullBytes) != 0 {
		return nil, errors.New("tls: invalid ML-DSA PKCS#8 private key parameters")
	}

	params, expandedSize, ok := mldsaParametersFromOID(key.Algorithm.Algorithm)
	if !ok {
		return nil, errors.New("tls: PKCS#8 private key is not ML-DSA")
	}

	var both struct {
		Seed     []byte
		Expanded []byte
	}
	if rest, err := asn1.Unmarshal(key.PrivateKey, &both); err != nil || len(rest) != 0 {
		return nil, errors.New("tls: invalid ML-DSA seed-plus-expanded private key")
	}
	if len(both.Seed) != mldsa.PrivateKeySize || len(both.Expanded) != expandedSize {
		return nil, errors.New("tls: invalid ML-DSA seed-plus-expanded private key size")
	}
	return mldsa.NewPrivateKey(params, both.Seed)
}

func mldsaParametersFromOID(oid asn1.ObjectIdentifier) (mldsa.Parameters, int, bool) {
	switch {
	case oid.Equal(oidPublicKeyMLDSA44):
		return mldsa.MLDSA44(), mldsa44ExpandedPrivateKeySize, true
	case oid.Equal(oidPublicKeyMLDSA65):
		return mldsa.MLDSA65(), mldsa65ExpandedPrivateKeySize, true
	case oid.Equal(oidPublicKeyMLDSA87):
		return mldsa.MLDSA87(), mldsa87ExpandedPrivateKeySize, true
	default:
		return mldsa.Parameters{}, 0, false
	}
}
