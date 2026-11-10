package devfortress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddlewareDeliversAnEventForASuspiciousRequestWithoutDelayingTheResponse(t *testing.T) {
	rt := okTransport()
	// A large batch size proves delivery does not depend on reaching it:
	// Middleware must flush the single event itself (sparse-traffic fix).
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(rt), WithBatchSize(1000))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(client)(next)

	req := httptest.NewRequest(http.MethodGet, "/items?id=1%27%20or%20%271%27%3D%271", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec := httptest.NewRecorder()

	started := time.Now()
	handler.ServeHTTP(rec, req)
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Errorf("handler took %v; Middleware must not block the response on delivery", elapsed)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	deadline := time.Now().Add(2 * time.Second)
	for rt.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if rt.count() != 1 {
		t.Fatalf("expected 1 delivered event, got %d", rt.count())
	}
	if client.PendingEvents() != 0 {
		t.Fatalf("expected the queue to be drained after delivery, got %d pending", client.PendingEvents())
	}
}

func TestMiddlewareDoesNotQueueANormalRequest(t *testing.T) {
	rt := okTransport()
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(client)(next)

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	time.Sleep(50 * time.Millisecond) // give the detached goroutine a chance to (not) queue anything
	if client.PendingEvents() != 0 {
		t.Errorf("expected no queued event for a plain 200, got %d", client.PendingEvents())
	}
}

func TestMiddlewarePropagatesAHandlerPanicAfterObserving(t *testing.T) {
	rt := okTransport()
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("handler boom")
	})
	handler := Middleware(client)(next)

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	rec := httptest.NewRecorder()

	defer func() {
		if recover() == nil {
			t.Fatal("expected the handler's panic to propagate")
		}
	}()
	handler.ServeHTTP(rec, req)
}

func TestRemoteHostStripsThePort(t *testing.T) {
	if got := RemoteHost("203.0.113.7:54321"); got != "203.0.113.7" {
		t.Errorf("got %q", got)
	}
	if got := RemoteHost("not-a-host-port"); got != "not-a-host-port" {
		t.Errorf("got %q", got)
	}
}
