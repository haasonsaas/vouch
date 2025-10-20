package main

import "time"

// DeviceState captures the latest posture and identity details for an agent.
type DeviceState struct {
	ID                uint       `gorm:"primaryKey"`
	AgentID           string     `gorm:"uniqueIndex"`
	Hostname          string     `gorm:"index"`
	NodeID            string     `gorm:"index"`
	PublicKey         []byte
	Compliant         bool
	LastSeen          time.Time
	Violations        string     `gorm:"type:text"`
	PostureRaw        string     `gorm:"type:text"`
	ConsecutiveFail   int
	ConsecutivePass   int
	NonCompliantSince *time.Time
	TagCompliant      bool
	LastEnforcedAt    *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// AgentNonce tracks recently seen nonces to reject replayed reports.
type AgentNonce struct {
	ID      uint      `gorm:"primaryKey"`
	AgentID string    `gorm:"index"`
	Nonce   string    `gorm:"index"`
	SeenAt  time.Time `gorm:"index"`
}

// EnrollmentToken stores hashed, single-use enrollment tokens.
type EnrollmentToken struct {
	ID        uint       `gorm:"primaryKey"`
	Label     string
	TokenHash string     `gorm:"uniqueIndex"`
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
