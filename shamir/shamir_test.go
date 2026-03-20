package shamir_test

import (
	"testing"

	"github.com/palmseung/keyshard/shamir"
)

func TestSplitAndCombine(t *testing.T) {
	secret := []byte("my-super-secret-rotation-key-32b")

	result, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(result.Shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(result.Shares))
	}

	// Recover with exactly threshold shares
	recovered, err := shamir.Combine(result.Shares[:3])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if string(recovered) != string(secret) {
		t.Fatalf("recovered secret mismatch: got %q", string(recovered))
	}
}

func TestCombineWithMoreThanThreshold(t *testing.T) {
	secret := []byte("another-secret-key")

	result, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Use 4 shares (more than threshold of 3)
	recovered, err := shamir.Combine(result.Shares[:4])
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if string(recovered) != string(secret) {
		t.Fatalf("recovered secret mismatch")
	}
}

func TestSplitValidation(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		total     int
		threshold int
	}{
		{"empty secret", []byte{}, 3, 2},
		{"total too low", []byte("x"), 1, 1},
		{"threshold > total", []byte("x"), 3, 4},
		{"threshold too low", []byte("x"), 3, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := shamir.Split(tt.secret, tt.total, tt.threshold)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
