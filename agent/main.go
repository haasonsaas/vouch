package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/haasonsaas/vouch/pkg/auth"
	"github.com/haasonsaas/vouch/pkg/config"
	"github.com/haasonsaas/vouch/pkg/health"
	"github.com/haasonsaas/vouch/pkg/posture"
	"github.com/haasonsaas/vouch/pkg/telemetry"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

var (
	configPath      = flag.String("config", "/etc/vouch/agent.yaml", "Config file path")
	enrollTokenPath = flag.String("enroll-token-file", "", "Path to one-time enrollment token")
	serverURL       = flag.String("server", "", "Vouch server URL (overrides config)")
	interval        = flag.Duration("interval", 0, "Report interval (overrides config)")
	enrollToken     = flag.String("enroll", "", "One-time enrollment token")
	Version         = "dev"
)

type Agent struct {
	config     *config.AgentConfig
	configPath string
	identity   *auth.Identity
	client     *http.Client
	keyPath    string
	retrier    *retrier
}

func main() {
	flag.Parse()

	configureAgentLogger()
	log.Info().Str("version", Version).Msg("Vouch Agent starting")

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// CLI overrides
	if *serverURL != "" {
		cfg.Server.URL = *serverURL
	}
	if *interval > 0 {
		cfg.Reporting.Interval = int(interval.Seconds())
	}
	if *enrollToken != "" {
		cfg.Server.EnrollToken = *enrollToken
	}
	if *enrollTokenPath != "" {
		cfg.Server.EnrollTokenFile = *enrollTokenPath
	}

	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("Invalid config")
	}

	applyAgentLogging(cfg.Logging)

	ctx := context.Background()
	traceEndpoint := os.Getenv("VOUCH_AGENT_TRACE_ENDPOINT")
	if traceEndpoint == "" {
		traceEndpoint = cfg.Tracing.Endpoint
	}
	traceInsecure := cfg.Tracing.Insecure
	if raw := os.Getenv("VOUCH_AGENT_TRACE_INSECURE"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			traceInsecure = parsed
		}
	}
	traceRatio := cfg.Tracing.SampleRatio
	if raw := os.Getenv("VOUCH_AGENT_TRACE_SAMPLE_RATIO"); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 && parsed <= 1 {
			traceRatio = parsed
		}
	}
	logSpans := cfg.Tracing.LogSpans
	if raw := os.Getenv("VOUCH_AGENT_TRACE_LOG_SPANS"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			logSpans = parsed
		}
	}

	if tp, err := telemetry.SetupTracing(ctx, "vouch-agent", Version, traceEndpoint, traceInsecure, traceRatio, logSpans); err != nil {
		log.Warn().Err(err).Msg("Agent tracing disabled")
	} else if tp != nil {
		defer func() {
			if err := tp.Shutdown(ctx); err != nil {
				log.Warn().Err(err).Msg("Failed to shutdown agent tracer")
			}
		}()
	}

	agent := &Agent{
		config:     cfg,
		configPath: *configPath,
		client:     &http.Client{Timeout: time.Duration(cfg.Server.RequestTimeout) * time.Second},
		keyPath:    cfg.Auth.KeyPath,
		retrier:    newRetrier(cfg.Server.RetryInitialMs, cfg.Server.RetryMaxMs, cfg.Server.RetryMaxRetries),
	}

	// Load or enroll identity
	if err := agent.loadOrEnroll(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize identity")
	}
	log.Info().Str("agent_id", agent.identity.AgentID).Msg("Agent initialized")
	log.Info().Str("node_id", agent.identity.NodeID).Msg("Agent identity")
	log.Info().Str("server", cfg.Server.URL).Int("interval_s", cfg.Reporting.Interval).Msg("Configuration loaded")

	// Run health check
	healthStatus := health.Check(cfg.Server.URL, cfg.Health.TimeDriftMaxS)
	if !healthStatus.Healthy {
		log.Warn().Interface("issues", healthStatus.Issues).Msg("Health check reported issues")
	}

	// Report immediately on startup
	agent.reportPosture()

	// Then report on interval with jitter
	jitter := time.Duration(cfg.Reporting.Jitter) * time.Second
	ticker := time.NewTicker(time.Duration(cfg.Reporting.Interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Add jitter to avoid thundering herd
		if jitter > 0 {
			time.Sleep(time.Duration(rand.Int63n(int64(jitter))))
		}
		agent.reportPosture()
	}
}

func configureAgentLogger() {
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.DurationFieldUnit = time.Millisecond

	level := zerolog.InfoLevel
	if raw := strings.ToLower(strings.TrimSpace(os.Getenv("VOUCH_AGENT_LOG_LEVEL"))); raw != "" {
		if parsed, err := zerolog.ParseLevel(raw); err == nil {
			level = parsed
		}
	}

	format := strings.ToLower(strings.TrimSpace(os.Getenv("VOUCH_AGENT_LOG_FORMAT")))

	logger := newAgentLogger(format)
	log.Logger = logger.Level(level)
	zerolog.SetGlobalLevel(level)
}

func applyAgentLogging(cfg config.LoggingConfig) {
	level := zerolog.InfoLevel
	if parsed, err := zerolog.ParseLevel(strings.ToLower(strings.TrimSpace(cfg.Level))); err == nil {
		level = parsed
	}

	format := "console"
	if cfg.JSON {
		format = "json"
	}

	logger := newAgentLogger(format)
	log.Logger = logger.Level(level)
	zerolog.SetGlobalLevel(level)
}

func newAgentLogger(format string) zerolog.Logger {
	if format == "json" {
		return zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
	writer := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	return zerolog.New(writer).With().Timestamp().Logger()
}

func (a *Agent) loadOrEnroll() error {
	// Try loading existing identity
	identity, err := auth.LoadIdentity(a.keyPath)
	if err == nil {
		a.identity = identity
		log.Info().Str("agent_id", identity.AgentID).Msg("Loaded existing identity")
		if a.config.Auth.AllowKeyRotation {
			if err := a.ensureFreshKey(); err != nil {
				log.Warn().Err(err).Msg("Key rotation check failed")
			}
		}
		return nil
	}

	// Need to enroll
	token, err := a.consumeEnrollmentToken()
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("no existing identity and no enrollment token provided")
	}

	a.config.Server.EnrollToken = token

	log.Info().Msg("Enrolling new agent")
	return a.enroll()
}

func (a *Agent) consumeEnrollmentToken() (string, error) {
	if a.config.Server.EnrollToken != "" {
		token := a.config.Server.EnrollToken
		a.config.Server.EnrollToken = ""
		return token, nil
	}
	if a.config.Server.EnrollTokenFile != "" {
		token, err := readTokenFile(a.config.Server.EnrollTokenFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if token != "" {
			return token, nil
		}
	}
	if token := strings.TrimSpace(os.Getenv("VOUCH_ENROLL_TOKEN")); token != "" {
		return token, nil
	}
	if path := strings.TrimSpace(os.Getenv("VOUCH_ENROLL_TOKEN_FILE")); path != "" {
		token, err := readTokenFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if token != "" {
			return token, nil
		}
	}
	if a.configPath != "" {
		tokenPath := resolveTokenPath(a.configPath)
		if tokenPath != "" {
			token, err := readTokenFile(tokenPath)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
			if token != "" {
				return token, nil
			}
		}
	}
	return "", nil
}

func (a *Agent) enroll() error {
	ctx, span := otel.Tracer("github.com/haasonsaas/vouch/agent").Start(context.Background(), "agent.enroll")
	defer span.End()

	identity, err := auth.GenerateIdentity()
	if err != nil {
		span.RecordError(err)
		return err
	}

	tsPosture, _ := posture.CollectTailscalePosture(a.config.Checks.Tailscale.LocalAPISocket)
	nodeID := tsPosture.NodeID
	if nodeID == "" || nodeID == "unknown" {
		err := fmt.Errorf("could not determine Tailscale node ID")
		span.RecordError(err)
		return err
	}

	hostname, _ := os.Hostname()

	enrollToken := a.config.Server.EnrollToken
	if enrollToken == "" {
		var readErr error
		enrollToken, readErr = a.consumeEnrollmentToken()
		if readErr != nil {
			span.RecordError(readErr)
			return readErr
		}
		if enrollToken == "" {
			err := errors.New("enrollment token unavailable")
			span.RecordError(err)
			return err
		}
	}

	a.config.Server.EnrollToken = enrollToken

	enrollReq := auth.EnrollmentRequest{
		Token:        enrollToken,
		NodeID:       nodeID,
		Hostname:     hostname,
		PublicKeyB64: identity.PublicKeyB64(),
		OSInfo:       runtime.GOOS + "/" + runtime.GOARCH,
	}

	data, _ := json.Marshal(enrollReq)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.Server.URL+"/v1/enroll", bytes.NewBuffer(data))
	if err != nil {
		span.RecordError(err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))
	span.SetAttributes(attribute.String("vouch.node_id", nodeID))

	resp, err := a.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("enrollment failed: status %d", resp.StatusCode)
		span.RecordError(err)
		span.SetAttributes(attribute.String("http.response.body", strings.TrimSpace(string(body))))
		return err
	}

	var enrollResp auth.EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return err
	}

	identity.AgentID = enrollResp.AgentID
	identity.NodeID = nodeID

	// Save identity
	if err := identity.Save(a.keyPath); err != nil {
		return err
	}

	a.identity = identity
	log.Info().Str("agent_id", identity.AgentID).Msg("Enrollment successful")

	if a.config.Auth.AllowKeyRotation {
		if err := a.ensureFreshKey(); err != nil {
			log.Warn().Err(err).Msg("Post-enrollment rotation check failed")
		}
	}

	if err := a.clearEnrollmentToken(); err != nil {
		log.Warn().Err(err).Msg("Failed to clear enrollment token after successful enrollment")
	}

	return nil
}

func (a *Agent) clearEnrollmentToken() error {
	if a.config.Server.EnrollTokenFile != "" {
		if err := os.Remove(a.config.Server.EnrollTokenFile); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if path := strings.TrimSpace(os.Getenv("VOUCH_ENROLL_TOKEN_FILE")); path != "" {
		if err := os.Remove(path); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if tokenPath := resolveTokenPath(a.configPath); tokenPath != "" {
		if err := os.Remove(tokenPath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	a.config.Server.EnrollToken = ""
	return nil
}

func readTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func resolveTokenPath(configPath string) string {
	if configPath == "" {
		return ""
	}
	base := filepath.Dir(configPath)
	defaultPath := filepath.Join(base, "enroll.token")
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}

func (a *Agent) reportPosture() {
	ctx, span := otel.Tracer("github.com/haasonsaas/vouch/agent").Start(context.Background(), "agent.report")
	defer span.End()

	report := a.collectComprehensivePosture()
	data, _ := json.Marshal(report)
	signedReq := auth.CreateSignedRequest(a.identity, data)

	req, _ := http.NewRequest("POST", a.config.Server.URL+"/v1/report", bytes.NewBuffer(signedReq.Body))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vouch-Agent-ID", a.identity.AgentID)
	req.Header.Set("X-Vouch-Signature", signedReq.Signature)
	req.Header.Set("X-Vouch-Timestamp", signedReq.Timestamp.Format(time.RFC3339))
	req.Header.Set("X-Vouch-Nonce", signedReq.Nonce)
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))

	span.SetAttributes(attribute.String("agent.id", a.identity.AgentID))

	var resp *http.Response
	operation := func() error {
		var err error
		resp, err = a.client.Do(req)
		if err != nil {
			return err
		}
		if isRetryableStatus(resp) {
			return retryableStatusError{status: resp.StatusCode}
		}
		return nil
	}
	if err := a.retrier.do(operation, isRetryableHTTP); err != nil {
		span.RecordError(err)
		log.Error().Err(err).Msg("Failed sending report")
		return
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("report failed: %d", resp.StatusCode)
		span.RecordError(err)
		span.SetAttributes(attribute.String("http.response.body", strings.TrimSpace(string(data))))
		log.Error().Int("status", resp.StatusCode).Bytes("body", data).Msg("Server returned non-OK status")
		return
	}

	var response struct {
		Status     string   `json:"status"`
		Compliant  bool     `json:"compliant"`
		Violations []string `json:"violations"`
		MinVersion string   `json:"min_version,omitempty"`
		RequestID  string   `json:"request_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		span.RecordError(err)
		log.Error().Err(err).Msg("Failed decoding report response")
		return
	}

	span.SetAttributes(attribute.Bool("agent.compliant", response.Compliant))
	if response.RequestID != "" {
		span.SetAttributes(attribute.String("request_id", response.RequestID))
	}

	if response.Compliant {
		log.Info().Str("request_id", response.RequestID).Msg("Posture report accepted")
	} else {
		log.Warn().Str("request_id", response.RequestID).Interface("violations", response.Violations).Msg("Non-compliant posture")
	}

	// Check version
	if response.MinVersion != "" && response.MinVersion > Version {
		log.Warn().Str("current_version", Version).Str("required_version", response.MinVersion).Msg("Agent version below minimum")
	}
}

func (a *Agent) collectComprehensivePosture() map[string]interface{} {
	// Use production-ready CollectorV2
	collector := posture.NewCollectorV2(10 * time.Second)
	ctx := context.Background()

	reportV2 := collector.Collect(ctx)

	// Convert to map for JSON marshaling
	data, _ := json.Marshal(reportV2)
	var report map[string]interface{}
	json.Unmarshal(data, &report)

	// Add agent metadata
	report["agent_version"] = Version

	return report
}

func (a *Agent) ensureFreshKey() error {
	if !a.config.Auth.AllowKeyRotation {
		return nil
	}
	challenge, err := a.requestRotationChallenge()
	if err != nil || challenge == nil {
		return err
	}

	newID, err := auth.GenerateIdentity()
	if err != nil {
		return err
	}

	sig, err := auth.SignChallenge(newID.PrivateKey, challenge.Challenge)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"challenge":  challenge.Challenge,
		"public_key": base64.StdEncoding.EncodeToString(newID.PublicKey),
		"signature":  sig,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if err := a.submitRotation(body); err != nil {
		return err
	}

	newID.AgentID = a.identity.AgentID
	newID.NodeID = a.identity.NodeID

	if err := a.persistIdentity(newID); err != nil {
		return err
	}

	a.identity = newID
	log.Info().Msg("Rotated agent key successfully")
	return nil
}

type rotationChallenge struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *Agent) requestRotationChallenge() (*rotationChallenge, error) {
	req, err := a.newSignedRequest(http.MethodPost, "/v1/keys/rotate", []byte("{}"))
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	operation := func() error {
		var err error
		resp, err = a.client.Do(req)
		if err != nil {
			return err
		}
		if isRetryableStatus(resp) {
			return retryableStatusError{status: resp.StatusCode}
		}
		return nil
	}
	if err := a.retrier.do(operation, isRetryableHTTP); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var challenge rotationChallenge
		if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
			return nil, err
		}
		if challenge.Challenge == "" {
			return nil, errors.New("rotation challenge missing nonce")
		}
		return &challenge, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rotation challenge rate limited")
	default:
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("challenge request failed: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
}

func (a *Agent) submitRotation(body []byte) error {
	req, err := a.newSignedRequest(http.MethodPut, "/v1/keys/rotate", body)
	if err != nil {
		return err
	}

	var resp *http.Response
	operation := func() error {
		var err error
		resp, err = a.client.Do(req)
		if err != nil {
			return err
		}
		if isRetryableStatus(resp) {
			return retryableStatusError{status: resp.StatusCode}
		}
		return nil
	}
	if err := a.retrier.do(operation, isRetryableHTTP); err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rotate failed: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	return nil
}

func (a *Agent) newSignedRequest(method, path string, body []byte) (*http.Request, error) {
	payload := body
	if payload == nil {
		payload = []byte("{}")
	}
	signed := auth.CreateSignedRequest(a.identity, payload)
	req, err := http.NewRequest(method, a.endpoint(path), bytes.NewReader(signed.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vouch-Agent-ID", a.identity.AgentID)
	req.Header.Set("X-Vouch-Signature", signed.Signature)
	req.Header.Set("X-Vouch-Timestamp", signed.Timestamp.Format(time.RFC3339))
	req.Header.Set("X-Vouch-Nonce", signed.Nonce)
	return req, nil
}

func (a *Agent) persistIdentity(newID *auth.Identity) error {
	backup := a.keyPath + ".bak"
	if _, err := os.Stat(a.keyPath); err == nil {
		if err := os.Rename(a.keyPath, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := newID.Save(a.keyPath); err != nil {
		if _, restoreErr := os.Stat(backup); restoreErr == nil {
			_ = os.Rename(backup, a.keyPath)
		}
		return err
	}

	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (a *Agent) endpoint(path string) string {
	base := strings.TrimRight(a.config.Server.URL, "/")
	return base + path
}
