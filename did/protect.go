package did

import (
	"fmt"

	"github.com/palmseung/keyshard/crypto"
	"github.com/palmseung/keyshard/shamir"
)

// ProtectedKey represents a DID key that has been split among guardians.
type ProtectedKey struct {
	DID      string               `json:"did"`
	KeyType  string               `json:"key_type"` // "rotation" or "signing"
	Envelope crypto.Envelope      `json:"envelope"`
	Shares   []GuardianShare      `json:"shares"`
}

// GuardianShare is a key share assigned to a specific guardian (by DID).
type GuardianShare struct {
	GuardianDID string       `json:"guardian_did"`
	Share       shamir.Share `json:"share"`
}

// Protect encrypts a DID key and splits it among guardians using Shamir's SSS.
//
// Example:
//
//	guardians := []string{"did:plc:abc...", "did:plc:def...", "did:plc:ghi..."}
//	protected, _ := did.Protect("did:plc:myid", "rotation", rotationKeyBytes, guardians, 2)
//	// → 3 shares, 2 needed to recover
func Protect(ownerDID, keyType string, key []byte, guardianDIDs []string, threshold int) (*ProtectedKey, error) {
	if len(guardianDIDs) == 0 {
		return nil, fmt.Errorf("keyshard: at least one guardian is required")
	}
	if threshold < 1 {
		return nil, fmt.Errorf("keyshard: threshold must be at least 1")
	}
	if threshold > len(guardianDIDs) {
		return nil, fmt.Errorf("keyshard: threshold (%d) cannot exceed number of guardians (%d)", threshold, len(guardianDIDs))
	}

	total := len(guardianDIDs)

	sealed, err := crypto.Seal(key, total, threshold)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to seal key: %w", err)
	}

	guardianShares := make([]GuardianShare, total)
	for i, gDID := range guardianDIDs {
		guardianShares[i] = GuardianShare{
			GuardianDID: gDID,
			Share:       sealed.Shares[i],
		}
	}

	return &ProtectedKey{
		DID:      ownerDID,
		KeyType:  keyType,
		Envelope: sealed.Envelope,
		Shares:   guardianShares,
	}, nil
}

// ShareFromGuardian is an alias for GuardianShare, used when collecting shares back.
type ShareFromGuardian = GuardianShare

// ExtractShares converts guardian shares to raw shamir shares for recovery.
func ExtractShares(guardianShares []ShareFromGuardian) []shamir.Share {
	shares := make([]shamir.Share, len(guardianShares))
	for i, gs := range guardianShares {
		shares[i] = gs.Share
	}
	return shares
}

// Recover reconstructs the original key from guardian shares.
func Recover(envelope crypto.Envelope, shares []shamir.Share) ([]byte, error) {
	return crypto.Unseal(envelope, shares)
}
