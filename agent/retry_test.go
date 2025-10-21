package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestBackoffWithJitterBounds(t *testing.T) {
	initial := 100 * time.Millisecond
	maxDelay := 800 * time.Millisecond
	for attempt := 0; attempt < 6; attempt++ {
		delay := backoffWithJitter(initial, maxDelay, attempt)
		if delay < initial/2 {
			t.Fatalf("delay below jitter floor: %v", delay)
		}
		if delay > maxDelay {
			t.Fatalf("delay exceeded max: %v", delay)
		}
	}
}

func TestRetrierStopsAfterSuccess(t *testing.T) {
	r := newRetrier(100, 200, 3)
	var attempts int
	err := r.do(func() error {
		attempts++
		if attempts < 2 {
			return retryableStatusError{status: 503}
		}
		return nil
	}, isRetryableHTTP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestIsRetryableHTTP(t *testing.T) {
	if isRetryableHTTP(nil) {
		t.Fatal("nil error should not be retryable")
	}
	if !isRetryableHTTP(retryableStatusError{status: 503}) {
		t.Fatal("retryable status error should be retryable")
	}
	if isRetryableHTTP(errors.New("generic")) {
		t.Fatal("generic error should not be retryable")
	}
	if !isRetryableHTTP(&net.DNSError{IsTemporary: true}) {
		t.Fatal("temporary net error should be retryable")
	}
}
