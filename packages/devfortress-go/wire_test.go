package devfortress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capturedRequest is what the httptest server observed on the wire, as the
// platform would see it (request line target exactly as sent, not
// re-parsed).
type capturedRequest struct {
	target  string
	headers http.Header
	body    []byte
}

// recordingRoundTripper wraps http.DefaultTransport and records every
// request it sees, in addition to whatever the request actually does.
type recordingRoundTripper struct {
	mu    sync.Mutex
	count int
}

func (rt *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.count++
	rt.mu.Unlock()
	return http.DefaultTransport.RoundTrip(req)
}

func (rt *recordingRoundTripper) seen() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.count
}

// TestWireLevelLifecycleNeverLeaksTheKeyAndPreservesTheExactTarget drives a
// construct -> TestConnection -> TrackEvent -> TrackEvents -> Flush
// lifecycle against a real httptest.Server behind a gateway-style path
// prefix with an already-encoded query, through both a recording
// http.RoundTripper and the server itself, and asserts: the API key appears
// in no header, query or body; the key ID and version 2 are present; every
// attempt (including the one retry the server forces) carries a fresh nonce
// and timestamp; and the server receives the exact signed request target.
func TestWireLevelLifecycleNeverLeaksTheKeyAndPreservesTheExactTarget(t *testing.T) {
	const wantTarget = "/gateway/api/events/ingest?v=1&x=a%20b"

	var mu sync.Mutex
	var captured []capturedRequest
	var failedOnce int32

	mux := http.NewServeMux()
	mux.HandleFunc("/gateway/api/events/ingest", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = append(captured, capturedRequest{target: r.RequestURI, headers: r.Header.Clone(), body: body})
		mu.Unlock()

		if atomic.CompareAndSwapInt32(&failedOnce, 0, 1) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	endpoint := server.URL + wantTarget
	rrt := &recordingRoundTripper{}
	transport := NewHTTPTransport(func(c *http.Client) { c.Transport = rrt })

	var sleeps []time.Duration
	client, err := NewClient(testKey, endpoint,
		WithTransport(transport),
		WithSleeper(func(d time.Duration) {
			sleeps = append(sleeps, d)
			time.Sleep(2 * time.Millisecond) // let the millisecond clock advance
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if !client.TestConnection(ctx) {
		t.Fatal("expected TestConnection to succeed after the forced retry")
	}
	client.TrackEvent(ctx, testEvent)
	client.TrackEvents(ctx, []Event{testEvent, testEvent})
	results := client.Flush(ctx)
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("results = %+v", results)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 3 {
		t.Fatalf("expected 3 requests on the wire (1 failed + 1 retry + 1 flush), got %d", len(captured))
	}
	if rrt.seen() != 3 {
		t.Errorf("recording round tripper saw %d requests, want 3", rrt.seen())
	}

	nonces := map[string]bool{}
	timestamps := map[string]bool{}
	for i, req := range captured {
		if req.target != wantTarget {
			t.Errorf("request %d: target = %q, want %q", i, req.target, wantTarget)
		}
		if req.headers.Get(KeyIDHeader) != DeriveKeyID(testKey) {
			t.Errorf("request %d: key id mismatch", i)
		}
		if req.headers.Get(VersionHeader) != "2" {
			t.Errorf("request %d: version = %q", i, req.headers.Get(VersionHeader))
		}
		nonces[req.headers.Get(NonceHeader)] = true
		timestamps[req.headers.Get(TimestampHeader)] = true

		// Comparison only; nothing about the key is printed.
		carriesKey := strings.Contains(string(req.body), testKey) || strings.Contains(req.target, testKey)
		for name, values := range req.headers {
			for _, v := range values {
				if strings.Contains(v, testKey) {
					carriesKey = true
				}
			}
			if strings.EqualFold(name, "X-DevFortress-Key") || strings.EqualFold(name, "X-Api-Key") || strings.EqualFold(name, "Authorization") {
				t.Errorf("request %d: carries forbidden header %s", i, name)
			}
		}
		if carriesKey {
			t.Errorf("request %d carries the API key", i)
		}
	}
	if len(nonces) != 3 {
		t.Errorf("expected 3 distinct nonces, got %d", len(nonces))
	}
	if len(timestamps) != 3 {
		t.Errorf("expected 3 distinct timestamps, got %d", len(timestamps))
	}
	if len(sleeps) != 1 {
		t.Errorf("expected exactly 1 backoff sleep (the forced retry), got %d", len(sleeps))
	}
}
