// Package keyshard provides Shamir's Secret Sharing based key protection
// and recovery. It enables splitting cryptographic keys (AT Protocol DID keys,
// wallet seeds, or arbitrary secrets) among trusted guardians, requiring a
// threshold number of shares to reconstruct the original.
//
// Core packages:
//   - shamir: Low-level split/combine operations
//   - crypto: AES-256-GCM encryption + Shamir key splitting
//   - did:    AT Protocol DID resolution and key protection
package keyshard
