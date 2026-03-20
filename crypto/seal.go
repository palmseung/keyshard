package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/palmseung/keyshard/shamir"
)

// Envelope holds the encrypted secret and metadata needed for recovery.
type Envelope struct {
	Ciphertext string `json:"ciphertext"` // AES-GCM ciphertext (Base64)
	Nonce      string `json:"nonce"`      // GCM nonce (Base64)
	Total      int    `json:"total"`
	Threshold  int    `json:"threshold"`
}

// SealedSecret is the complete output: envelope + key shares.
type SealedSecret struct {
	Envelope Envelope       `json:"envelope"`
	Shares   []shamir.Share `json:"shares"`
}

// Seal encrypts a secret using AES-256-GCM, then splits the encryption key
// into shares using Shamir's Secret Sharing.
//
// Flow:
//  1. Generate random AES-256 key (32 bytes)
//  2. Encrypt secret with AES-GCM
//  3. Split the AES key into shares via SSS
//  4. Return encrypted envelope + key shares
func Seal(secret []byte, total, threshold int) (*SealedSecret, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("keyshard: secret must not be empty")
	}

	// 1. Generate random AES-256 key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("keyshard: failed to generate key: %w", err)
	}

	// 2. AES-GCM encrypt
	ciphertext, nonce, err := encryptAESGCM(key, secret)
	if err != nil {
		return nil, err
	}

	// 3. Split the AES key
	var shares []shamir.Share
	if total <= 1 {
		shares = []shamir.Share{{Index: 1, Data: base64.StdEncoding.EncodeToString(key)}}
		total = 1
		threshold = 1
	} else {
		result, err := shamir.Split(key, total, threshold)
		if err != nil {
			return nil, fmt.Errorf("keyshard: failed to split key: %w", err)
		}
		shares = result.Shares
	}

	return &SealedSecret{
		Envelope: Envelope{
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Total:      total,
			Threshold:  threshold,
		},
		Shares: shares,
	}, nil
}

// Unseal reconstructs the AES key from shares and decrypts the secret.
func Unseal(envelope Envelope, shares []shamir.Share) ([]byte, error) {
	var key []byte

	if envelope.Total <= 1 && len(shares) == 1 {
		decoded, err := base64.StdEncoding.DecodeString(shares[0].Data)
		if err != nil {
			return nil, fmt.Errorf("keyshard: failed to decode key: %w", err)
		}
		key = decoded
	} else {
		recovered, err := shamir.Combine(shares)
		if err != nil {
			return nil, fmt.Errorf("keyshard: failed to combine shares: %w", err)
		}
		key = recovered
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to decode nonce: %w", err)
	}

	return decryptAESGCM(key, nonce, ciphertext)
}

func encryptAESGCM(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("keyshard: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("keyshard: failed to create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("keyshard: failed to generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func decryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("keyshard: decryption failed (wrong shares or tampered data): %w", err)
	}

	return plaintext, nil
}
