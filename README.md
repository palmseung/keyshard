# keyshard

A Go library for key protection and recovery based on Shamir's Secret Sharing.

Split a secret into N shares and recover the original with any T of them. Useful for AT Protocol DID rotation key recovery, cryptocurrency wallet seed custody, password inheritance, and more.

## Packages

```
keyshard/
├── shamir/    # Shamir Secret Sharing — Split/Combine
├── crypto/    # AES-256-GCM encryption + Shamir — Seal/Unseal
└── did/       # AT Protocol DID — Resolve/Verify/Protect/Recover
```

## Usage

### Basic: Split & Combine

```go
import "github.com/palmseung/keyshard/shamir"

// Split a secret into 5 shares (3 required to recover)
result, _ := shamir.Split([]byte("my-secret"), 5, 3)

// Recover with any 3 shares
recovered, _ := shamir.Combine(result.Shares[:3])
// recovered == []byte("my-secret")
```

### Encrypt + Split

```go
import "github.com/palmseung/keyshard/crypto"

// Encrypt with AES-256-GCM, then split the key with Shamir
sealed, _ := crypto.Seal([]byte("my-secret"), 5, 3)

// Recover with the envelope (ciphertext) + any 3 shares
recovered, _ := crypto.Unseal(sealed.Envelope, sealed.Shares[:3])
```

### DID Key Protection

```go
import "github.com/palmseung/keyshard/did"

// Resolve a DID document
doc, _ := did.Resolve("did:plc:abc123...")
handle, _ := did.Handle(doc)       // "user.bsky.social"
pds, _ := did.PDSEndpoint(doc)     // "https://bsky.social"

// Verify DID ownership via signature
err := did.VerifySignature(doc, challenge, signature)

// Distribute a rotation key to guardians
guardians := []string{"did:plc:guardian1", "did:plc:guardian2", "did:plc:guardian3"}
protected, _ := did.Protect("did:plc:owner", "rotation", rotationKeyBytes, guardians, 2)
// → 3 shares, 2 required to recover

// Recover
rawShares := did.ExtractShares(submittedShares)
recovered, _ := did.Recover(protected.Envelope, rawShares)
```

## DID Signature Verification

Proves DID ownership via challenge-response:

1. Server issues a random nonce
2. Client signs the nonce with their DID signing key (ECDSA)
3. Server verifies the signature against the public key in the DID document

Supported key types:
- **P-256** (secp256r1) — AT Protocol default
- **secp256k1** — parsing only (verification requires go-ethereum curve)

## Install

```bash
go get github.com/palmseung/keyshard
```

## Test

```bash
go test ./...
```

## License

MIT
