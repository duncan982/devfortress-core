package devfortressgin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	devfortress "github.com/duncan982/devfortress-core/packages/devfortress-go"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// recordingTransport is a minimal devfortress.Transport double: it just
// accepts everything, which is all these adapter tests need (the core
// module's own tests already cover delivery in depth). Middleware now
// flushes from a detached goroutine (see ObserveAndFlush), so Send can run
// concurrently with a test's own goroutine polling the count — sent is
// guarded accordingly.
type recordingTransport struct {
	mu   sync.Mutex
	sent int
}

func (rt *recordingTransport) Send(context.Context, string, string, map[string]string, []byte, time.Duration) (*devfortress.TransportResponse, error) {
	rt.mu.Lock()
	rt.sent++
	rt.mu.Unlock()
	return &devfortress.TransportResponse{StatusCode: 200, Body: []byte(`{"success":true}`)}, nil
}

func (rt *recordingTransport) count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.sent
}

func newTestClient(t *testing.T) (*devfortress.Client, *recordingTransport) {
	t.Helper()
	rt := &recordingTransport{}
	client, err := devfortress.NewClient("vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest", devfortress.WithTransport(rt), devfortress.WithBatchSize(1000))
	if err != nil {
		t.Fatal(err)
	}
	return client, rt
}

func TestMiddlewareDeliversAnEventForASuspiciousRequestWithoutDelayingTheResponse(t *testing.T) {
	// newTestClient uses WithBatchSize(1000), so delivery here can only come
	// from Middleware's own flush, not a batch-size auto-flush — proving the
	// sparse-traffic fix (a lone event is not left sitting in the queue).
	client, rt := newTestClient(t)
	defer client.Close(context.Background())

	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/items?id=1%27%20or%20%271%27%3D%271", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec := httptest.NewRecorder()

	started := time.Now()
	r.ServeHTTP(rec, req)
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
	if got := rt.count(); got != 1 {
		t.Fatalf("expected 1 delivered event, got %d", got)
	}
	if client.PendingEvents() != 0 {
		t.Fatalf("expected the queue to be drained after delivery, got %d pending", client.PendingEvents())
	}
}

func TestMiddlewareDoesNotQueueANormalRequest(t *testing.T) {
	client, _ := newTestClient(t)
	defer client.Close(context.Background())

	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	time.Sleep(50 * time.Millisecond)
	if client.PendingEvents() != 0 {
		t.Errorf("expected no queued event for a plain 200, got %d", client.PendingEvents())
	}
}

func TestMiddlewareReportsA404ForAnUnknownRoute(t *testing.T) {
	client, rt := newTestClient(t)
	defer client.Close(context.Background())

	r := gin.New()
	r.Use(Middleware(client))
	r.NoRoute(func(c *gin.Context) { c.Status(http.StatusNotFound) })
	r.GET("/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}

	deadline := time.Now().Add(2 * time.Second)
	for rt.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rt.count(); got != 1 {
		t.Fatalf("expected 1 delivered event for the 404, got %d", got)
	}
}
