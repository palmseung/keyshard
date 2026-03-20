package did_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/palmseung/keyshard/did"
)

// encodePublicKeyMultibase encodes an ECDSA public key in multibase+multicodec format.
func encodePublicKeyMultibase(pub *ecdsa.PublicKey, codec uint64) string {
	// Compressed point format
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	compressed := make([]byte, 1+byteLen)
	if pub.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	xBytes := pub.X.Bytes()
	copy(compressed[1+byteLen-len(xBytes):], xBytes)

	// Multicodec varint prefix
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], codec)

	raw := append(prefix[:n], compressed...)
	return "z" + base58.Encode(raw)
}

func TestVerifySignatureP256(t *testing.T) {
	// Generate a P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as multibase
	pubMultibase := encodePublicKeyMultibase(&privKey.PublicKey, 0x1200)

	// Create a mock DID document
	doc := &did.Document{
		ID: "did:plc:test123",
		VerificationMethod: []did.VerificationMethod{
			{
				ID:                 "did:plc:test123#atproto",
				Type:               "EcdsaSecp256r1VerificationKey2019",
				Controller:         "did:plc:test123",
				PublicKeyMultibase: pubMultibase,
			},
		},
	}

	// Sign a message
	message := []byte("challenge-nonce-12345")
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Raw r||s signature
	byteLen := (privKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteLen-len(rBytes):], rBytes)
	copy(sig[2*byteLen-len(sBytes):], sBytes)

	// Verify
	if err := did.VerifySignature(doc, message, sig); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestVerifySignatureWrongMessage(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubMultibase := encodePublicKeyMultibase(&privKey.PublicKey, 0x1200)

	doc := &did.Document{
		ID: "did:plc:test456",
		VerificationMethod: []did.VerificationMethod{
			{
				ID:                 "did:plc:test456#atproto",
				PublicKeyMultibase: pubMultibase,
			},
		},
	}

	message := []byte("correct-message")
	hash := sha256.Sum256(message)
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, hash[:])

	byteLen := 32
	sig := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteLen-len(rBytes):], rBytes)
	copy(sig[2*byteLen-len(sBytes):], sBytes)

	// Verify with wrong message should fail
	err := did.VerifySignature(doc, []byte("wrong-message"), sig)
	if err == nil {
		t.Fatal("expected verification to fail with wrong message")
	}
}

func TestParsePublicKeyMultibase(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encoded := encodePublicKeyMultibase(&privKey.PublicKey, 0x1200)

	pubKey, err := did.ParsePublicKeyMultibase(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if pubKey.X.Cmp(privKey.PublicKey.X) != 0 || pubKey.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Fatal("parsed key doesn't match original")
	}
}

func TestVerifySignatureSecp256k1(t *testing.T) {
	// Go's generic CurveParams assumes a=-3, which doesn't work for secp256k1 (a=0).
	// AT Protocol primarily uses P-256. secp256k1 support needs go-ethereum's curve.
	t.Skip("secp256k1 requires go-ethereum curve implementation")
}

func TestVerifyWrongKey(t *testing.T) {
	// Sign with one key, verify with another
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pubMultibase2 := encodePublicKeyMultibase(&privKey2.PublicKey, 0x1200)

	doc := &did.Document{
		ID: "did:plc:wrongkey",
		VerificationMethod: []did.VerificationMethod{
			{
				ID:                 "did:plc:wrongkey#atproto",
				PublicKeyMultibase: pubMultibase2,
			},
		},
	}

	message := []byte("test-message")
	hash := sha256.Sum256(message)
	r, s, _ := ecdsa.Sign(rand.Reader, privKey1, hash[:])

	byteLen := 32
	sig := make([]byte, 2*byteLen)
	copy(sig[byteLen-len(r.Bytes()):], r.Bytes())
	copy(sig[2*byteLen-len(s.Bytes()):], s.Bytes())

	err := did.VerifySignature(doc, message, sig)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}
