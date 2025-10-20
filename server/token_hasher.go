package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// TokenHasher derives deterministic, salted hashes for enrollment tokens.
type TokenHasher struct {
	salt []byte
}

// NewTokenHasher constructs a hasher with the provided salt bytes.
func NewTokenHasher(salt []byte) TokenHasher {
	return TokenHasher{salt: append([]byte(nil), salt...)}
}

// HashString hashes the given token using HMAC-SHA256 and returns a base64 string.
func (h TokenHasher) HashString(token string) string {
	mac := hmac.New(sha256.New, h.salt)
	mac.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
