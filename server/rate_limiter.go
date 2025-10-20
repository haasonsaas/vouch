package main

import (
	"sync"
	"time"
)

type rateRecord struct {
	count  int
	reset  time.Time
	window time.Duration
}

// RateLimiter tracks per-key request usage within a sliding window.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateRecord
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{entries: make(map[string]rateRecord)}
}

// Allow returns true if the caller may proceed under the provided limit and window.
func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	now := time.Now()
	rl.mu.Lock()
	rec := rl.entries[key]
	if rec.window == 0 || now.After(rec.reset) {
		rec.count = 0
		rec.window = window
		rec.reset = now.Add(window)
	}
	if rec.count >= limit {
		rl.mu.Unlock()
		return false
	}
	rec.count++
	rl.entries[key] = rec
	rl.mu.Unlock()
	return true
}

type RateLimiterStats struct {
	Keys int `json:"keys"`
}

func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return RateLimiterStats{Keys: len(rl.entries)}
}
