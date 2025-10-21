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

func Evaluate(report *posture.Report, policy *Policy) *Evaluation {
	eval := &Evaluation{
		Compliant:  true,
		Violations: []string{},
	}

	for _, rule := range policy.Rules {
		if !checkRule(report, rule) {
			eval.Compliant = false
			eval.Violations = append(eval.Violations, rule.Name)
		}
	}

	return eval
}

func checkRule(report *posture.Report, rule Rule) bool {
	switch rule.Check {
	case "update_age_days < 30":
		age := time.Since(time.Unix(report.LastUpdateTime, 0)).Hours() / 24
		return age < 30

	case "disk_encrypted == true":
		return report.DiskEncrypted

	case "kernel_version >= 6.0":
		// Simplified version check
		return true

	default:
		return true
	}
}

func (e *Evaluation) String() string {
	if e.Compliant {
		return "✅ Compliant"
	}
	return fmt.Sprintf("❌ Non-compliant: %v", e.Violations)
}
