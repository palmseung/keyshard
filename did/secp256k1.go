package did

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var (
	secp256k1Once  sync.Once
	secp256k1Curve *elliptic.CurveParams
)

// Secp256k1 returns the secp256k1 elliptic curve parameters.
func Secp256k1() elliptic.Curve {
	secp256k1Once.Do(func() {
		secp256k1Curve = &elliptic.CurveParams{
			Name:    "secp256k1",
			BitSize: 256,
		}
		secp256k1Curve.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
		secp256k1Curve.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
		secp256k1Curve.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
		secp256k1Curve.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
		secp256k1Curve.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	})
	return secp256k1Curve
}
