package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/mr-tron/base58"
)

// VerifySignature verifies a signature against the signing key in a DID document.
// The message should be the raw challenge bytes, and sig is the DER-encoded ECDSA signature.
func VerifySignature(doc *Document, message, sig []byte) error {
	vm, err := SigningKey(doc)
	if err != nil {
		return err
	}

	pubKey, err := ParsePublicKeyMultibase(vm.PublicKeyMultibase)
	if err != nil {
		return fmt.Errorf("keyshard: failed to parse public key: %w", err)
	}

	hash := sha256.Sum256(message)

	// Parse DER-encoded signature (or raw r||s)
	r, s, err := parseSignature(sig, pubKey.Curve)
	if err != nil {
		return fmt.Errorf("keyshard: failed to parse signature: %w", err)
	}

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("keyshard: signature verification failed")
	}

	return nil
}

// ParsePublicKeyMultibase decodes a multibase+multicodec public key.
// AT Protocol uses 'z' prefix (base58btc) with multicodec varint prefix.
func ParsePublicKeyMultibase(encoded string) (*ecdsa.PublicKey, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("empty publicKeyMultibase")
	}

	// First char is multibase prefix
	prefix := encoded[0]
	if prefix != 'z' {
		return nil, fmt.Errorf("unsupported multibase prefix: %c (expected 'z' for base58btc)", prefix)
	}

	raw, err := base58.Decode(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("base58 decode failed: %w", err)
	}

	if len(raw) < 2 {
		return nil, fmt.Errorf("multicodec data too short")
	}

	// Read multicodec varint prefix
	codec, n := binary.Uvarint(raw)
	if n <= 0 {
		return nil, fmt.Errorf("failed to read multicodec prefix")
	}
	keyBytes := raw[n:]

	switch codec {
	case 0x1200: // p256-pub
		return unmarshalECDSAPublicKey(elliptic.P256(), keyBytes)
	case 0xe7: // secp256k1-pub
		return unmarshalSecp256k1PublicKey(keyBytes)
	default:
		return nil, fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}
}

// unmarshalECDSAPublicKey parses a compressed or uncompressed EC public key.
func unmarshalECDSAPublicKey(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty key data")
	}

	var x, y *big.Int

	switch data[0] {
	case 0x04: // uncompressed
		byteLen := (curve.Params().BitSize + 7) / 8
		if len(data) != 1+2*byteLen {
			return nil, fmt.Errorf("invalid uncompressed key length")
		}
		x = new(big.Int).SetBytes(data[1 : 1+byteLen])
		y = new(big.Int).SetBytes(data[1+byteLen:])

	case 0x02, 0x03: // compressed
		byteLen := (curve.Params().BitSize + 7) / 8
		if len(data) != 1+byteLen {
			return nil, fmt.Errorf("invalid compressed key length")
		}
		x, y = decompressPoint(curve, data)
		if x == nil {
			return nil, fmt.Errorf("failed to decompress point")
		}

	default:
		return nil, fmt.Errorf("unknown key format prefix: 0x%02x", data[0])
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// decompressPoint recovers the y coordinate from a compressed EC point.
func decompressPoint(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
	params := curve.Params()
	x := new(big.Int).SetBytes(data[1:])

	// y² = x³ + ax + b (for P-256, a = -3)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, params.P)

	// For P-256: a = -3
	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, params.P)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, params.B)
	y2.Mod(y2, params.P)

	// sqrt(y²) mod p
	y := new(big.Int).ModSqrt(y2, params.P)
	if y == nil {
		return nil, nil
	}

	// Check parity
	if y.Bit(0) != uint(data[0]&1) {
		y.Sub(params.P, y)
	}

	return x, y
}

// unmarshalSecp256k1PublicKey handles secp256k1 keys.
// Go's standard library doesn't include secp256k1, so we use the curve params directly.
func unmarshalSecp256k1PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	curve := Secp256k1()
	return unmarshalECDSAPublicKey(curve, data)
}

// parseSignature parses a raw r||s signature (each half is curve byte length).
func parseSignature(sig []byte, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	byteLen := (curve.Params().BitSize + 7) / 8

	if len(sig) == 2*byteLen {
		// Raw r||s format
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		return r, s, nil
	}

	// Try DER format
	if len(sig) > 2 && sig[0] == 0x30 {
		return parseDER(sig)
	}

	return nil, nil, fmt.Errorf("unrecognized signature format (len=%d)", len(sig))
}

// parseDER parses a DER-encoded ECDSA signature.
func parseDER(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) < 6 || sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid DER signature")
	}

	pos := 2 // skip 0x30 + length byte

	if sig[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected integer tag for r")
	}
	pos++
	rLen := int(sig[pos])
	pos++
	r := new(big.Int).SetBytes(sig[pos : pos+rLen])
	pos += rLen

	if sig[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected integer tag for s")
	}
	pos++
	sLen := int(sig[pos])
	pos++
	s := new(big.Int).SetBytes(sig[pos : pos+sLen])

	return r, s, nil
}
