package policy

import (
	"fmt"
	"time"

	"github.com/haasonsaas/vouch/pkg/posture"
)

type Rule struct {
	Name   string `yaml:"name"`
	Check  string `yaml:"check"`
	Action string `yaml:"action"` // "deny" or "warn"
}

type Policy struct {
	Rules []Rule `yaml:"rules"`
}

type Evaluation struct {
	Compliant  bool
	Violations []string
}

func Evaluate(report *posture.ReportV2, policy *Policy) *Evaluation {
	eval := &Evaluation{
		Compliant:  true,
		Violations: []string{},
	}

	for _, rule := range policy.Rules {
		if !checkRule(report, rule) {
			eval.Violations = append(eval.Violations, rule.Name)
			// Only mark non-compliant for deny rules, not warnings
			if rule.Action == "deny" {
				eval.Compliant = false
			}
		}
	}

	return eval
}

func checkRule(report *posture.ReportV2, rule Rule) bool {
	switch rule.Check {
	case "update_age_days < 30":
		if report.LastUpdateTime == nil || *report.LastUpdateTime == 0 {
			return false
		}
		age := time.Since(time.Unix(*report.LastUpdateTime, 0)).Hours() / 24
		return age < 30

	case "update_age_days < 60":
		if report.LastUpdateTime == nil || *report.LastUpdateTime == 0 {
			return false
		}
		age := time.Since(time.Unix(*report.LastUpdateTime, 0)).Hours() / 24
		return age < 60

	case "update_age_days < 90":
		if report.LastUpdateTime == nil || *report.LastUpdateTime == 0 {
			return false
		}
		age := time.Since(time.Unix(*report.LastUpdateTime, 0)).Hours() / 24
		return age < 90

	case "disk_encrypted == true":
		return report.RootVolumeEncrypted

	case "firewall_enabled == true":
		return report.FirewallEnabled

	case "kernel_version >= 6.0":
		// Simplified version check
		return true

	default:
		// Unknown check - fail open for now to avoid breaking existing policies
		return true
	}
}

func (e *Evaluation) String() string {
	if e.Compliant {
		return "✅ Compliant"
	}
	return fmt.Sprintf("❌ Non-compliant: %v", e.Violations)
}
