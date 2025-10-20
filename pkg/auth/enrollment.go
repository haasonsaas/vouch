package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

type Identity struct {
	AgentID    string         `json:"agent_id"`
	NodeID     string         `json:"node_id"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	PrivateKey ed25519.PrivateKey `json:"-"`
}

type EnrollmentRequest struct {
	Token         string `json:"token"`
	NodeID        string `json:"node_id"`
	Hostname      string `json:"hostname"`
	PublicKeyB64  string `json:"public_key"`
	OSInfo        string `json:"os_info"`
}

type EnrollmentResponse struct {
	AgentID       string `json:"agent_id"`
	ServerVersion string `json:"server_version"`
	MinVersion    string `json:"min_version"`
	PolicyETag    string `json:"policy_etag"`
}

// GenerateIdentity creates a new Ed25519 keypair
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Identity{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Save stores the identity to disk with 0600 permissions
func (i *Identity) Save(path string) error {
	data := map[string]string{
		"agent_id":    i.AgentID,
		"node_id":     i.NodeID,
		"public_key":  base64.StdEncoding.EncodeToString(i.PublicKey),
		"private_key": base64.StdEncoding.EncodeToString(i.PrivateKey),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	// Create parent directory if needed
	dir := path[:len(path)-len("/agent_key")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write with restricted permissions
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return err
	}

	return nil
}

// Load reads identity from disk
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var stored map[string]string
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}

	pubBytes, err := base64.StdEncoding.DecodeString(stored["public_key"])
	if err != nil {
		return nil, err
	}

	privBytes, err := base64.StdEncoding.DecodeString(stored["private_key"])
	if err != nil {
		return nil, err
	}

	return &Identity{
		AgentID:    stored["agent_id"],
		NodeID:     stored["node_id"],
		PublicKey:  ed25519.PublicKey(pubBytes),
		PrivateKey: ed25519.PrivateKey(privBytes),
	}, nil
}

// Sign creates a signature for the given message
func (i *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(i.PrivateKey, message)
}

// Verify checks a signature against a message
func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

func (i *Identity) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(i.PublicKey)
}
