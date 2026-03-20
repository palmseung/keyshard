package did

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const plcDirectoryURL = "https://plc.directory"

// Document represents a DID document with essential fields.
type Document struct {
	ID                 string             `json:"id"`
	AlsoKnownAs       []string           `json:"alsoKnownAs"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Service            []Service          `json:"service"`
}

// VerificationMethod represents a public key entry in a DID document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// Service represents a service endpoint (e.g., PDS).
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// Resolve fetches and parses a DID document.
// Supports did:plc (via plc.directory) and did:web.
func Resolve(did string) (*Document, error) {
	if did == "" {
		return nil, fmt.Errorf("keyshard: DID must not be empty")
	}

	var url string
	switch {
	case strings.HasPrefix(did, "did:plc:"):
		url = fmt.Sprintf("%s/%s", plcDirectoryURL, did)
	case strings.HasPrefix(did, "did:web:"):
		domain := strings.TrimPrefix(did, "did:web:")
		domain = strings.ReplaceAll(domain, ":", "/")
		url = fmt.Sprintf("https://%s/.well-known/did.json", domain)
	default:
		return nil, fmt.Errorf("keyshard: unsupported DID method: %s", did)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to resolve DID: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyshard: DID resolution returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("keyshard: failed to read response: %w", err)
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("keyshard: failed to parse DID document: %w", err)
	}

	return &doc, nil
}

// PDSEndpoint extracts the PDS URL from a DID document.
func PDSEndpoint(doc *Document) (string, error) {
	for _, svc := range doc.Service {
		if svc.Type == "AtprotoPersonalDataServer" {
			return svc.ServiceEndpoint, nil
		}
	}
	return "", fmt.Errorf("keyshard: no PDS endpoint found in DID document")
}

// Handle extracts the atproto handle from a DID document.
func Handle(doc *Document) (string, error) {
	for _, aka := range doc.AlsoKnownAs {
		if strings.HasPrefix(aka, "at://") {
			return strings.TrimPrefix(aka, "at://"), nil
		}
	}
	return "", fmt.Errorf("keyshard: no handle found in DID document")
}

// SigningKey extracts the primary signing public key from a DID document.
func SigningKey(doc *Document) (*VerificationMethod, error) {
	for _, vm := range doc.VerificationMethod {
		if strings.HasSuffix(vm.ID, "#atproto") {
			return &vm, nil
		}
	}
	if len(doc.VerificationMethod) > 0 {
		return &doc.VerificationMethod[0], nil
	}
	return nil, fmt.Errorf("keyshard: no signing key found in DID document")
}
