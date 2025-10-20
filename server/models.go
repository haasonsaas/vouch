package main

import "time"

// DeviceState captures posture, identity bindings, and enforcement status for an agent.
type DeviceState struct {
	ID                uint   `gorm:"primaryKey"`
	AgentID           string `gorm:"uniqueIndex"`
	Hostname          string `gorm:"index"`
	NodeID            string `gorm:"uniqueIndex"`
	PublicKey         []byte
	Compliant         bool
	LastSeen          time.Time
	Violations        string `gorm:"type:text"`
	PostureRaw        string `gorm:"type:text"`
	ConsecutiveFail   int
	ConsecutivePass   int
	NonCompliantSince *time.Time
	TagCompliant      bool
	LastEnforcedAt    *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// AgentNonce tracks recently seen nonces for replay detection.
type AgentNonce struct {
	ID      uint      `gorm:"primaryKey"`
	AgentID string    `gorm:"uniqueIndex:agent_nonce"`
	Nonce   string    `gorm:"uniqueIndex:agent_nonce"`
	SeenAt  time.Time `gorm:"index"`
}

// EnrollmentToken stores hashed, single-use enrollment tokens.
type EnrollmentToken struct {
	ID         uint `gorm:"primaryKey"`
	Label      string
	TokenHash  string `gorm:"uniqueIndex"`
	ExpiresAt  time.Time
	UsedAt     *time.Time
	RedeemedBy string
	CreatedAt  time.Time
}
