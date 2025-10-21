package main

import (
	"errors"
	"math"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type retrier struct {
	initial    time.Duration
	max        time.Duration
	maxRetries int
}

func newRetrier(initialMs, maxMs, maxRetries int) *retrier {
	if initialMs <= 0 {
		initialMs = 500
	}
	if maxMs <= 0 {
		maxMs = initialMs
	}
	if maxMs < initialMs {
		maxMs = initialMs
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &retrier{
		initial:    time.Duration(initialMs) * time.Millisecond,
		max:        time.Duration(maxMs) * time.Millisecond,
		maxRetries: maxRetries,
	}
}

func (r *retrier) do(fn func() error, retryable func(error) bool) error {
	var attempt int
	for {
		err := fn()
		if err == nil {
			return nil
		}
		if attempt >= r.maxRetries || !retryable(err) {
			return err
		}
		delay := backoffWithJitter(r.initial, r.max, attempt)
		log.Warn().Err(err).Int("attempt", attempt+1).Dur("sleep", delay).Msg("Retrying operation")
		time.Sleep(delay)
		attempt++
	}
}

func backoffWithJitter(initial, max time.Duration, attempt int) time.Duration {
	b := float64(initial) * math.Pow(2, float64(attempt))
	if b > float64(max) {
		b = float64(max)
	}
	j := b / 2
	return time.Duration(j + rand.Float64()*j)
}

func isRetryableHTTP(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var statusErr retryableStatusError
	return errors.As(err, &statusErr)
}

func isRetryableStatus(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		return true
	}
	return resp.StatusCode == http.StatusTooManyRequests
}

type retryableStatusError struct {
	status int
}

func (e retryableStatusError) Error() string {
	return http.StatusText(e.status)
}
