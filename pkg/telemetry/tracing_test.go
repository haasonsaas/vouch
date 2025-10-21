package telemetry

import (
	context "context"
	testing "testing"
)

func TestSetupTracingDefaults(t *testing.T) {
	ctx := context.Background()
	provider, err := SetupTracing(ctx, "vouch-server", "test", "", false, 0)
	if err != nil {
		t.Fatalf("setup tracing failed: %v", err)
	}
	if provider == nil {
		t.Fatal("expected provider")
	}
	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}
