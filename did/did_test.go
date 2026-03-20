package did_test

import (
	"testing"

	"github.com/palmseung/keyshard/did"
)

func TestProtectAndRecover(t *testing.T) {
	ownerDID := "did:plc:testowner123"
	rotationKey := []byte("this-is-a-32-byte-rotation-key!!")
	guardians := []string{
		"did:plc:guardian1",
		"did:plc:guardian2",
		"did:plc:guardian3",
	}

	protected, err := did.Protect(ownerDID, "rotation", rotationKey, guardians, 2)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	if protected.DID != ownerDID {
		t.Fatalf("DID mismatch: got %s", protected.DID)
	}
	if protected.KeyType != "rotation" {
		t.Fatalf("KeyType mismatch: got %s", protected.KeyType)
	}
	if len(protected.Shares) != 3 {
		t.Fatalf("expected 3 guardian shares, got %d", len(protected.Shares))
	}

	// Verify guardian DIDs are assigned
	for i, gs := range protected.Shares {
		if gs.GuardianDID != guardians[i] {
			t.Fatalf("guardian DID mismatch at index %d", i)
		}
	}

	// Recover with 2 of 3 guardians
	submittedShares := []did.GuardianShare{
		protected.Shares[0],
		protected.Shares[2],
	}

	shares := make([]did.ShareFromGuardian, len(submittedShares))
	for i, gs := range submittedShares {
		shares[i] = did.ShareFromGuardian(gs)
	}

	rawShares := did.ExtractShares(shares)
	recovered, err := did.Recover(protected.Envelope, rawShares)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	if string(recovered) != string(rotationKey) {
		t.Fatalf("recovered key mismatch: got %q", string(recovered))
	}
}

func TestProtectValidation(t *testing.T) {
	key := []byte("test-key-material")

	_, err := did.Protect("did:plc:x", "rotation", key, []string{}, 1)
	if err == nil {
		t.Fatal("expected error for empty guardians")
	}

	_, err = did.Protect("did:plc:x", "rotation", key, []string{"did:plc:a", "did:plc:b"}, 3)
	if err == nil {
		t.Fatal("expected error for threshold > guardians")
	}
}
