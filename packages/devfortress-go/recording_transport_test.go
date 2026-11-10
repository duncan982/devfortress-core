package devfortress

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// recordedRequest is one request a recordingTransport observed.
type recordedRequest struct {
	method  string
	url     string
	headers map[string]string
	body    []byte
}

// recordingTransport is a scripted Transport that records every request it
// is given. The script is consumed in order and its last entry repeats. It
// is safe for concurrent use (the background-flush test drives it from more
// than one goroutine).
type recordingTransport struct {
	script []any // *TransportResponse or error

	mu       sync.Mutex
	requests []recordedRequest
}

func okTransport() *recordingTransport {
	return &recordingTransport{script: []any{&TransportResponse{StatusCode: 200, Body: []byte(`{"success":true}`)}}}
}

func downError() error { return errors.New("connection refused") }

func (rt *recordingTransport) Send(_ context.Context, method, rawURL string, headers map[string]string, body []byte, _ time.Duration) (*TransportResponse, error) {
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	bodyCopy := append([]byte(nil), body...)

	rt.mu.Lock()
	rt.requests = append(rt.requests, recordedRequest{method: method, url: rawURL, headers: h, body: bodyCopy})
	idx := len(rt.requests)
	if idx > len(rt.script) {
		idx = len(rt.script)
	}
	step := rt.script[idx-1]
	rt.mu.Unlock()

	switch s := step.(type) {
	case error:
		return nil, s
	case *TransportResponse:
		return s, nil
	default:
		return nil, fmt.Errorf("recordingTransport: bad script entry %#v", step)
	}
}

// count returns how many requests have been recorded so far (safe for
// concurrent use).
func (rt *recordingTransport) count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.requests)
}

// panicTransport always panics; used to prove the client recovers.
type panicTransport struct{}

func (panicTransport) Send(context.Context, string, string, map[string]string, []byte, time.Duration) (*TransportResponse, error) {
	panic("boom")
}

// panicLogger always panics; used to prove the client recovers.
type panicLogger struct{}

func (panicLogger) Log(string, string, map[string]any) { panic("logger down") }

// recordingLogger records every log line without panicking.
type recordingLogger struct {
	lines []string
}

func (l *recordingLogger) Log(level, message string, fields map[string]any) {
	l.lines = append(l.lines, fmt.Sprintf("%s %s %v", level, message, fields))
}
