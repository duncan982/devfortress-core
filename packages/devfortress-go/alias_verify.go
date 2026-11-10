package devfortress

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"time"
)

// AliasOperationClass classifies the kind of operation observed against an
// aliased credential.
type AliasOperationClass string

const (
	OpRead    AliasOperationClass = "read"
	OpDownload AliasOperationClass = "download"
	OpList    AliasOperationClass = "list"
	OpWrite   AliasOperationClass = "write"
	OpPublish AliasOperationClass = "publish"
	OpMessage AliasOperationClass = "message"
)

// AliasVerifyContext is the observed invocation context, reported from
// outside the aliased workload.
type AliasVerifyContext struct {
	RequestIP               string
	GeoCountry              string
	WorkloadID              string
	DeviceFingerprint       string
	AppBundleID             string
	AgentToolID             string
	RequestTimestamp        string // ISO-8601
	ContainerID             string
	EgressPath              string
	ProcessSignature        string
	ObservedOperationClass  AliasOperationClass
	ObservedModelIdentifier string
}

// AliasBindingViolation is one binding-check failure reported by the
// platform.
type AliasBindingViolation struct {
	Type     string
	AliasID  string
	Expected any
	Received any
	Severity string
	Response string
}

// AliasVerifyResult is the platform's verdict on an alias-binding check.
type AliasVerifyResult struct {
	HTTPStatus int
	Valid      bool
	Violations []AliasBindingViolation
	Note       string
	Code       string
	State      string
	Error      string
}

// AliasVerifyError is returned for a 4xx response (other than 403, which
// is a normal verdict) or for a 5xx/network failure once retries are
// exhausted.
type AliasVerifyError struct {
	Message    string
	HTTPStatus int
	Body       any
}

func (e *AliasVerifyError) Error() string { return e.Message }

const (
	defaultAliasVerifyBaseURL = "https://www.devfortress.net"
	defaultAliasVerifyTimeout = 15 * time.Second
	defaultAliasVerifyRetries = 3
)

// AliasVerifyOptions configures VerifyAliasBinding.
type AliasVerifyOptions struct {
	BaseURL   string
	Timeout   time.Duration
	Retries   int
	Transport Transport
	Sleeper   func(time.Duration)
}

// VerifyAliasBinding verifies an alias's observed context against its
// recorded binding. Resolves for HTTP 200 and 403 (the platform's normal
// verdicts); returns *AliasVerifyError for 400/401 and for 5xx/network
// failures once retries are exhausted. Retry behavior matches Client:
// exponential backoff on 5xx and network errors only, never on 4xx.
func VerifyAliasBinding(ctx context.Context, aliasID, aliasKey string, vctx AliasVerifyContext, opts AliasVerifyOptions) (AliasVerifyResult, error) {
	if aliasID == "" {
		return AliasVerifyResult{}, fmt.Errorf("devfortress: VerifyAliasBinding: aliasID is required")
	}
	if aliasKey == "" {
		return AliasVerifyResult{}, fmt.Errorf("devfortress: VerifyAliasBinding: aliasKey is required")
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = defaultAliasVerifyBaseURL
	}
	for len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultAliasVerifyTimeout
	}
	retries := opts.Retries
	if retries <= 0 {
		retries = defaultAliasVerifyRetries
	}
	transport := opts.Transport
	if transport == nil {
		transport = NewHTTPTransport()
	}
	sleeper := opts.Sleeper
	if sleeper == nil {
		sleeper = func(d time.Duration) { time.Sleep(d) }
	}

	verifyURL := fmt.Sprintf("%s/api/aliases/%s/verify", baseURL, url.PathEscape(aliasID))
	body, err := json.Marshal(map[string]any{"aliasKey": aliasKey, "context": vctx})
	if err != nil {
		return AliasVerifyResult{}, fmt.Errorf("devfortress: encode verify request: %w", err)
	}

	var lastErr error
	for attempt := 1; ; attempt++ {
		resp, sendErr := transport.Send(ctx, "POST", verifyURL, map[string]string{
			"Content-Type":              "application/json",
			"X-DevFortress-SDK-Version": Version,
		}, body, timeout)

		if sendErr == nil {
			var data map[string]any
			_ = json.Unmarshal(resp.Body, &data)

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				return decodeAliasVerifyResult(resp.StatusCode, data), nil
			}
			if resp.StatusCode < 500 {
				return AliasVerifyResult{}, &AliasVerifyError{
					Message:    errorMessageOr(data, fmt.Sprintf("Alias verification failed with status %d", resp.StatusCode)),
					HTTPStatus: resp.StatusCode, Body: data,
				}
			}
			lastErr = &AliasVerifyError{
				Message:    errorMessageOr(data, fmt.Sprintf("Alias verification failed with status %d", resp.StatusCode)),
				HTTPStatus: resp.StatusCode, Body: data,
			}
		} else {
			lastErr = &AliasVerifyError{Message: fmt.Sprintf("Alias verification request failed: %v", sendErr)}
		}

		if attempt >= retries {
			return AliasVerifyResult{}, lastErr
		}
		if err := ctx.Err(); err != nil {
			return AliasVerifyResult{}, err
		}
		sleeper(time.Duration(math.Pow(2, float64(attempt))) * time.Second)
	}
}

func decodeAliasVerifyResult(status int, data map[string]any) AliasVerifyResult {
	result := AliasVerifyResult{HTTPStatus: status}
	if v, ok := data["valid"].(bool); ok {
		result.Valid = v
	}
	if v, ok := data["note"].(string); ok {
		result.Note = v
	}
	if v, ok := data["code"].(string); ok {
		result.Code = v
	}
	if v, ok := data["state"].(string); ok {
		result.State = v
	}
	if v, ok := data["error"].(string); ok {
		result.Error = v
	}
	if raw, ok := data["violations"].([]any); ok {
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			v := AliasBindingViolation{}
			if s, ok := m["type"].(string); ok {
				v.Type = s
			}
			if s, ok := m["aliasId"].(string); ok {
				v.AliasID = s
			}
			if s, ok := m["severity"].(string); ok {
				v.Severity = s
			}
			if s, ok := m["response"].(string); ok {
				v.Response = s
			}
			v.Expected = m["expected"]
			v.Received = m["received"]
			result.Violations = append(result.Violations, v)
		}
	}
	return result
}

func errorMessageOr(data map[string]any, fallback string) string {
	if s, ok := data["error"].(string); ok && s != "" {
		return s
	}
	return fallback
}
