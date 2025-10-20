package posture

import (
	"testing"
	"time"
)

func TestCollect(t *testing.T) {
	report, err := Collect()
	if err != nil {
		t.Fatalf("Collect() failed: %v", err)
	}

	if report.Hostname == "" {
		t.Error("Hostname should not be empty")
	}

	if report.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	if time.Since(report.Timestamp) > time.Minute {
		t.Error("Timestamp should be recent")
	}

	if report.Kernel == "" && report.Kernel != "unknown" {
		t.Error("Kernel should be detected or marked unknown")
	}
}

func TestGetKernel(t *testing.T) {
	kernel := getKernel()
	if kernel == "" {
		t.Error("getKernel() should return a value")
	}
}

func TestGetOSRelease(t *testing.T) {
	os := getOSRelease()
	if os == "" {
		t.Error("getOSRelease() should return a value")
	}
}
