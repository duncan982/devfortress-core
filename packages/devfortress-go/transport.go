package devfortress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TransportResponse is one HTTP response, whatever its status.
type TransportResponse struct {
	StatusCode int
	Body       []byte
}

// Transport sends one HTTP request and returns the response. The URL and
// the header/body bytes must go on the wire exactly as given: the request
// signature covers them. Send returns an error only on a network-level
// failure (no HTTP response); an HTTP error status is a normal
// *TransportResponse.
type Transport interface {
	Send(ctx context.Context, method, rawURL string, headers map[string]string, body []byte, timeout time.Duration) (*TransportResponse, error)
}

// HTTPTransport is the default Transport: net/http, HTTP/1.1, no redirects
// followed (a 3xx is returned to the caller as-is, never re-requested).
type HTTPTransport struct {
	client *http.Client
}

// NewHTTPTransport returns the default Transport. The RoundTripper (and so
// the underlying connection pool, proxy and TLS settings) can be swapped
// through Option.
func NewHTTPTransport(opts ...func(*http.Client)) *HTTPTransport {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, opt := range opts {
		opt(client)
	}
	return &HTTPTransport{client: client}
}

// Send implements Transport.
func (t *HTTPTransport) Send(ctx context.Context, method, rawURL string, headers map[string]string, body []byte, timeout time.Duration) (*TransportResponse, error) {
	sendCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	req, err := buildRequest(sendCtx, method, rawURL, headers, body)
	if err != nil {
		return nil, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &TransportResponse{StatusCode: resp.StatusCode, Body: respBody}, nil
}

// buildRequest constructs an *http.Request whose URL.RequestURI() is
// byte-for-byte the request target RequestTargetFromURL(rawURL) computed
// (including a gateway prefix or an already-encoded query), by setting
// URL.Opaque and URL.RawQuery directly rather than letting net/url
// re-escape the path.
func buildRequest(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) (*http.Request, error) {
	if method == "" {
		return nil, errors.New("devfortress: empty HTTP method")
	}

	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("devfortress: invalid endpoint URL: %w", err)
	}

	target := RequestTargetFromURL(rawURL)
	path, query, hasQuery := splitRequestTarget(target)

	u := &url.URL{
		Scheme: base.Scheme,
		Host:   base.Host,
		User:   base.User,
		Opaque: path,
	}
	if hasQuery {
		u.RawQuery = query
		if query == "" {
			u.ForceQuery = true
		}
	}
	if got := u.RequestURI(); got != target {
		return nil, fmt.Errorf("devfortress: could not preserve the exact request target: got %q, want %q", got, target)
	}

	req := &http.Request{
		Method:     strings.ToUpper(method),
		URL:        u,
		Host:       base.Host,
		Header:     make(http.Header, len(headers)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req = req.WithContext(ctx)
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	if len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}

	return req, nil
}

func splitRequestTarget(target string) (path, query string, hasQuery bool) {
	if idx := strings.IndexByte(target, '?'); idx != -1 {
		return target[:idx], target[idx+1:], true
	}
	return target, "", false
}
