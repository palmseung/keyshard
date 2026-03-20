package shamir

import (
	"encoding/base64"
	"fmt"

	vault "github.com/hashicorp/vault/shamir"
)

// Split divides a secret into n shares, requiring threshold shares to reconstruct.
// The secret can be arbitrary bytes (cryptographic keys, seed phrases, etc.).
func Split(secret []byte, total, threshold int) (*SplitResult, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("keyshard: secret must not be empty")
	}
	if total < 2 {
		return nil, fmt.Errorf("keyshard: total must be at least 2")
	}
	if threshold < 2 || threshold > total {
		return nil, fmt.Errorf("keyshard: threshold must be >= 2 and <= total")
	}

	parts, err := vault.Split(secret, total, threshold)
	if err != nil {
		return nil, fmt.Errorf("keyshard: split failed: %w", err)
	}

	shares := make([]Share, len(parts))
	for i, part := range parts {
		shares[i] = Share{
			Index: i + 1,
			Data:  base64.StdEncoding.EncodeToString(part),
		}
	}

	return &SplitResult{
		Total:     total,
		Threshold: threshold,
		Shares:    shares,
	}, nil
}
