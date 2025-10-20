package policy

import (
	"testing"
	"time"

	"github.com/haasonsaas/vouch/pkg/posture"
)

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		report     *posture.Report
		policy     *Policy
		wantPass   bool
		wantViolations int
	}{
		{
			name: "compliant device",
			report: &posture.Report{
				Hostname:       "test-host",
				LastUpdateTime: time.Now().Unix() - (20 * 86400), // 20 days ago
				DiskEncrypted:  true,
			},
			policy: &Policy{
				Rules: []Rule{
					{Name: "updates", Check: "update_age_days < 30", Action: "deny"},
					{Name: "encryption", Check: "disk_encrypted == true", Action: "deny"},
				},
			},
			wantPass:       true,
			wantViolations: 0,
		},
		{
			name: "non-compliant device - old updates",
			report: &posture.Report{
				Hostname:       "test-host",
				LastUpdateTime: time.Now().Unix() - (40 * 86400), // 40 days ago
				DiskEncrypted:  true,
			},
			policy: &Policy{
				Rules: []Rule{
					{Name: "updates", Check: "update_age_days < 30", Action: "deny"},
					{Name: "encryption", Check: "disk_encrypted == true", Action: "deny"},
				},
			},
			wantPass:       false,
			wantViolations: 1,
		},
		{
			name: "non-compliant device - no encryption",
			report: &posture.Report{
				Hostname:       "test-host",
				LastUpdateTime: time.Now().Unix() - (20 * 86400),
				DiskEncrypted:  false,
			},
			policy: &Policy{
				Rules: []Rule{
					{Name: "updates", Check: "update_age_days < 30", Action: "deny"},
					{Name: "encryption", Check: "disk_encrypted == true", Action: "deny"},
				},
			},
			wantPass:       false,
			wantViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := Evaluate(tt.report, tt.policy)

			if eval.Compliant != tt.wantPass {
				t.Errorf("Evaluate() compliant = %v, want %v", eval.Compliant, tt.wantPass)
			}

			if len(eval.Violations) != tt.wantViolations {
				t.Errorf("Evaluate() violations = %d, want %d", len(eval.Violations), tt.wantViolations)
			}
		})
	}
}
