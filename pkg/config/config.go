package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	Server    ServerConfig    `yaml:"server"`
	Auth      AuthConfig      `yaml:"auth"`
	Reporting ReportingConfig `yaml:"reporting"`
	Checks    ChecksConfig    `yaml:"checks"`
	Health    HealthConfig    `yaml:"health"`
	Logging   LoggingConfig   `yaml:"logging"`
	Updates   UpdatesConfig   `yaml:"updates"`
	Tracing   TracingConfig   `yaml:"tracing"`
}

type ServerConfig struct {
	URL             string `yaml:"url"`
	EnrollToken     string `yaml:"enroll_token"`
	EnrollTokenFile string `yaml:"enroll_token_file"`
	RequestTimeout  int    `yaml:"request_timeout_s"`
	MetricsEndpoint string `yaml:"metrics_endpoint"`
	RetryInitialMs  int    `yaml:"retry_initial_ms"`
	RetryMaxMs      int    `yaml:"retry_max_ms"`
	RetryMaxRetries int    `yaml:"retry_max_attempts"`
}

type AuthConfig struct {
	KeyPath          string `yaml:"key_path"`
	AllowKeyRotation bool   `yaml:"allow_key_rotation"`
}

type ReportingConfig struct {
	Interval                 int  `yaml:"interval_s"`
	Jitter                   int  `yaml:"jitter_s"`
	IncludeListeningServices bool `yaml:"include_listening_services"`
	RedactHostnames          bool `yaml:"redact_hostnames"`
}

type ChecksConfig struct {
	Tailscale      TailscaleCheck      `yaml:"tailscale"`
	Firewall       FirewallCheck       `yaml:"firewall"`
	Updates        UpdatesCheck        `yaml:"updates"`
	DiskEncryption DiskEncryptionCheck `yaml:"disk_encryption"`
	SecureBoot     SecureBootCheck     `yaml:"secure_boot_tpm"`
	AntiMalware    AntiMalwareCheck    `yaml:"antimalware"`
	Hardening      HardeningCheck      `yaml:"hardening"`
}

type TailscaleCheck struct {
	Enable         bool   `yaml:"enable"`
	LocalAPISocket string `yaml:"localapi_socket"`
}

type FirewallCheck struct {
	Enable      bool   `yaml:"enable"`
	LinuxPrefer string `yaml:"linux_prefer"`
}

type UpdatesCheck struct {
	Enable             bool `yaml:"enable"`
	MaxDaysSinceUpdate int  `yaml:"max_days_since_update"`
}

type DiskEncryptionCheck struct {
	Enable            bool `yaml:"enable"`
	RequireRootVolume bool `yaml:"require_root_volume"`
}

type SecureBootCheck struct {
	Enable bool `yaml:"enable"`
}

type AntiMalwareCheck struct {
	Enable            bool `yaml:"enable"`
	MinSigRecencyDays int  `yaml:"min_sig_recency_days"`
}

type HardeningCheck struct {
	SELinuxAppArmorEnforcing bool `yaml:"selinux_apparmor_enforcing"`
	SSHPasswordAuthDisabled  bool `yaml:"ssh_password_auth_disabled"`
}

type HealthConfig struct {
	TimeDriftMaxS       int    `yaml:"time_drift_max_s"`
	TailscalePingTarget string `yaml:"tailscale_ping_target"`
}

type LoggingConfig struct {
	Level         string `yaml:"level"`
	JSON          bool   `yaml:"json"`
	HumanReadable bool   `yaml:"human_readable"`
}

type UpdatesConfig struct {
	SelfUpdate      bool   `yaml:"self_update"`
	Channel         string `yaml:"channel"`
	UpdateURL       string `yaml:"update_url"`
	VerifySignature bool   `yaml:"verify_signature"`
}

type TracingConfig struct {
	Endpoint    string  `yaml:"endpoint" json:"endpoint"`
	Insecure    bool    `yaml:"insecure" json:"insecure"`
	SampleRatio float64 `yaml:"sample_ratio" json:"sample_ratio"`
	LogSpans    bool    `yaml:"log_spans" json:"log_spans"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *AgentConfig {
	return &AgentConfig{
		Server: ServerConfig{
			URL:             "https://localhost:8443",
			RequestTimeout:  10,
			MetricsEndpoint: "",
			RetryInitialMs:  500,
			RetryMaxMs:      5000,
			RetryMaxRetries: 5,
		},
		Auth: AuthConfig{
			KeyPath:          "/var/lib/vouch/agent_key",
			AllowKeyRotation: true,
		},
		Reporting: ReportingConfig{
			Interval:                 300,
			Jitter:                   30,
			IncludeListeningServices: false,
			RedactHostnames:          false,
		},
		Checks: ChecksConfig{
			Tailscale: TailscaleCheck{
				Enable:         true,
				LocalAPISocket: "/var/run/tailscale/tailscaled.sock",
			},
			Firewall: FirewallCheck{
				Enable:      true,
				LinuxPrefer: "auto",
			},
			Updates: UpdatesCheck{
				Enable:             true,
				MaxDaysSinceUpdate: 30,
			},
			DiskEncryption: DiskEncryptionCheck{
				Enable:            true,
				RequireRootVolume: true,
			},
			SecureBoot: SecureBootCheck{
				Enable: true,
			},
			AntiMalware: AntiMalwareCheck{
				Enable:            true,
				MinSigRecencyDays: 7,
			},
			Hardening: HardeningCheck{
				SELinuxAppArmorEnforcing: false,
				SSHPasswordAuthDisabled:  false,
			},
		},
		Health: HealthConfig{
			TimeDriftMaxS: 120,
		},
		Logging: LoggingConfig{
			Level:         "info",
			JSON:          false,
			HumanReadable: true,
		},
		Updates: UpdatesConfig{
			SelfUpdate:      false,
			Channel:         "stable",
			VerifySignature: true,
		},
		Tracing: TracingConfig{
			Endpoint:    "",
			Insecure:    false,
			SampleRatio: 1,
			LogSpans:    false,
		},
	}
}

// Load reads config from file with env var and CLI overrides
func Load(path string) (*AgentConfig, error) {
	cfg := DefaultConfig()

	// Load from file if exists
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}

	// Override with env vars
	if url := os.Getenv("VOUCH_SERVER_URL"); url != "" {
		cfg.Server.URL = url
	}
	if token := os.Getenv("VOUCH_ENROLL_TOKEN"); token != "" {
		cfg.Server.EnrollToken = token
	}
	if tokenFile := os.Getenv("VOUCH_ENROLL_TOKEN_FILE"); tokenFile != "" {
		cfg.Server.EnrollTokenFile = tokenFile
	}
	if level := os.Getenv("VOUCH_LOG_LEVEL"); level != "" {
		cfg.Logging.Level = level
	}
	if cfg.Server.EnrollToken == "" && cfg.Server.EnrollTokenFile == "" {
		if defaultPath := defaultTokenPath(path); defaultPath != "" {
			cfg.Server.EnrollTokenFile = defaultPath
		}
	}

	return cfg, nil
}

func defaultTokenPath(configPath string) string {
	if configPath == "" {
		return ""
	}
	dir := filepath.Dir(configPath)
	if dir == "." || dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "enroll.token")
}

func (c *AgentConfig) Validate() error {
	if c.Server.URL == "" {
		return ErrMissingServerURL
	}
	if c.Reporting.Interval < 10 {
		return ErrInvalidInterval
	}
	if !strings.HasPrefix(c.Server.URL, "https://") {
		return &Error{"server URL must be https"}
	}
	if c.Server.RequestTimeout <= 0 {
		c.Server.RequestTimeout = 10
	}
	if c.Server.RetryInitialMs <= 0 {
		c.Server.RetryInitialMs = 500
	}
	if c.Server.RetryMaxMs <= 0 {
		c.Server.RetryMaxMs = 5000
	}
	if c.Server.RetryMaxRetries < 0 {
		c.Server.RetryMaxRetries = 5
	}
	if c.Server.RetryMaxMs < c.Server.RetryInitialMs {
		c.Server.RetryMaxMs = c.Server.RetryInitialMs
	}
	if c.Tracing.SampleRatio <= 0 || c.Tracing.SampleRatio > 1 {
		c.Tracing.SampleRatio = 1
	}
	// no extra validation for log spans; defaults already set
	return nil
}

var (
	ErrMissingServerURL = &Error{"server URL is required"}
	ErrInvalidInterval  = &Error{"reporting interval must be >= 10s"}
)

type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}
