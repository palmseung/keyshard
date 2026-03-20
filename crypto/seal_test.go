package crypto_test

import (
	"testing"

	"github.com/palmseung/keyshard/crypto"
	"github.com/palmseung/keyshard/shamir"
)

func TestSealAndUnseal(t *testing.T) {
	secret := []byte("did:plc:rotation-key-material-here")

	sealed, err := crypto.Seal(secret, 3, 2)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if len(sealed.Shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(sealed.Shares))
	}

	// Recover with 2 shares (threshold)
	recovered, err := crypto.Unseal(sealed.Envelope, sealed.Shares[:2])
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if string(recovered) != string(secret) {
		t.Fatalf("recovered secret mismatch")
	}
}

func TestSealSingleGuardian(t *testing.T) {
	secret := []byte("single-guardian-secret")

	sealed, err := crypto.Seal(secret, 1, 1)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	recovered, err := crypto.Unseal(sealed.Envelope, sealed.Shares)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if string(recovered) != string(secret) {
		t.Fatalf("recovered secret mismatch")
	}
}

func TestUnsealWrongShares(t *testing.T) {
	secret := []byte("test-secret")

	sealed, err := crypto.Seal(secret, 3, 2)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Tamper with a share
	badShares := []shamir.Share{
		{Index: 1, Data: "YmFkZGF0YQ=="},
		{Index: 2, Data: "YmFkZGF0YQ=="},
	}

	_, err = crypto.Unseal(sealed.Envelope, badShares)
	if err == nil {
		t.Fatal("expected error with wrong shares, got nil")
	}
}

func TestSealLargeSecret(t *testing.T) {
	// Simulate a real key (64 bytes)
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i)
	}

	sealed, err := crypto.Seal(secret, 5, 3)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	recovered, err := crypto.Unseal(sealed.Envelope, sealed.Shares[:3])
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if len(recovered) != len(secret) {
		t.Fatalf("length mismatch: got %d, want %d", len(recovered), len(secret))
	}

	for i := range secret {
		if recovered[i] != secret[i] {
			t.Fatalf("byte mismatch at index %d", i)
		}
	}
}
