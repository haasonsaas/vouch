package main

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// NonceStore provides persistent replay protection using the database.
type NonceStore struct {
	db        *gorm.DB
	window    time.Duration
	pruneFreq time.Duration
}

func NewNonceStore(db *gorm.DB, window time.Duration) *NonceStore {
	return &NonceStore{db: db, window: window, pruneFreq: window}
}

// CheckAndStore attempts to store a nonce for an agent, returning an error on replay.
func (s *NonceStore) CheckAndStore(agentID, nonce string, ts time.Time) error {
	if agentID == "" || nonce == "" {
		return errors.New("missing agent or nonce")
	}

	cutoff := time.Now().Add(-s.window)
	if err := s.db.Where("seen_at < ?", cutoff).Delete(&AgentNonce{}).Error; err != nil {
		return err
	}

	record := AgentNonce{AgentID: agentID, Nonce: nonce, SeenAt: ts}
	if err := s.db.Create(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return errors.New("nonce replay detected")
		}
		return err
	}

	return nil
}
