package shamir

import (
	"encoding/base64"
	"fmt"

	vault "github.com/hashicorp/vault/shamir"
)

// Combine reconstructs the original secret from the given shares.
// At least threshold shares are required to successfully recover the secret.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("keyshard: at least 2 shares are required")
	}

	parts := make([][]byte, len(shares))
	for i, share := range shares {
		decoded, err := base64.StdEncoding.DecodeString(share.Data)
		if err != nil {
			return nil, fmt.Errorf("keyshard: failed to decode share %d: %w", share.Index, err)
		}
		parts[i] = decoded
	}

	secret, err := vault.Combine(parts)
	if err != nil {
		return nil, fmt.Errorf("keyshard: combine failed: %w", err)
	}

	return secret, nil
}
