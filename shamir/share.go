package shamir

// Share represents a single Shamir share with Base64-encoded data.
type Share struct {
	Index int    `json:"index"`
	Data  string `json:"data"` // Base64-encoded
}

// SplitResult holds the output of a Split operation.
type SplitResult struct {
	Total     int     `json:"total"`
	Threshold int     `json:"threshold"`
	Shares    []Share `json:"shares"`
}
