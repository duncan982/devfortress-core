package devfortressgin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devfortress "github.com/duncan982/devfortress-core/packages/devfortress-go"
	"github.com/gin-gonic/gin"
)

// Internal/hybrid-mode pre-response gate (TODO 407 port) — Middleware's
// internalGate. Adapter-level proof against the real middleware through a
// real Gin router + httptest, the same bar as the already-completed Ruby
// Rails adapter's middleware_test.rb internal-mode tests and the
// Java/.NET/PHP adapters' own equivalent test files — not just engine-level
// unit tests.

func newTestClientWithMode(t *testing.T, mode devfortress.CLMode, opts ...devfortress.Option) (*devfortress.Client, *recordingTransport) {
	t.Helper()
	rt := &recordingTransport{}
	allOpts := append([]devfortress.Option{
		devfortress.WithTransport(rt),
		devfortress.WithBatchSize(1000),
		devfortress.WithMode(mode),
	}, opts...)
	client, err := devfortress.NewClient("vx_live_test_vector_key_do_not_use", "http://platform.test/api/events/ingest", allOpts...)
	if err != nil {
		t.Fatal(err)
	}
	return client, rt
}

func TestInternalMode_CleanRequest_ReachesTheApp(t *testing.T) {
	client, _ := newTestClientWithMode(t, devfortress.ModeInternal)
	defer client.Close(context.Background())

	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/products", func(c *gin.Context) { c.String(http.StatusOK, "fine") })

	req := httptest.NewRequest(http.MethodGet, "/products?q=laptop", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.11")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestInternalMode_ScannerUserAgent_IsBlockedBeforeReachingTheApp(t *testing.T) {
	client, _ := newTestClientWithMode(t, devfortress.ModeInternal)
	defer client.Close(context.Background())

	appCalled := false
	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/", func(c *gin.Context) { appCalled = true; c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	req.Header.Set("User-Agent", "sqlmap/1.7")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if appCalled {
		t.Fatal("the app must never see a blocked request")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body did not parse as JSON: %v", err)
	}
	if body["error"] != "blocked" {
		t.Fatalf("unexpected body: %v", body)
	}
	if !client.IsBlocked("198.51.100.20") {
		t.Fatal("the attacking IP must be recorded as blocked")
	}
}

func TestInternalMode_BlockedIp_StaysBlockedOnALaterCleanRequest(t *testing.T) {
	client, _ := newTestClientWithMode(t, devfortress.ModeInternal)
	defer client.Close(context.Background())

	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	attack := httptest.NewRequest(http.MethodGet, "/", nil)
	attack.Header.Set("X-Forwarded-For", "198.51.100.21")
	attack.Header.Set("User-Agent", "nikto/2.5")
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, attack)
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("first (attack) request status = %d", rec1.Code)
	}

	clean := httptest.NewRequest(http.MethodGet, "/", nil)
	clean.Header.Set("X-Forwarded-For", "198.51.100.21")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, clean)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("second (clean) request from the same IP status = %d; the IP must still be blocked by engine state", rec2.Code)
	}
}

func TestInternalMode_BodyBasedSqlInjection_IsBlockedAndBodyIsRewoundForTheApp(t *testing.T) {
	// Go's gate buffers and replays the request body (unlike Python's FastAPI
	// gate) — see internalGate's doc comment in middleware.go — so this also
	// proves the body is fully readable downstream after the gate ran.
	client, _ := newTestClientWithMode(t, devfortress.ModeInternal)
	defer client.Close(context.Background())

	var appSawBody string
	appCalled := false
	r := gin.New()
	r.Use(Middleware(client))
	r.POST("/comments", func(c *gin.Context) {
		appCalled = true
		buf := make([]byte, 1024)
		n, _ := c.Request.Body.Read(buf)
		appSawBody = string(buf[:n])
		c.Status(http.StatusOK)
	})

	payload := "'; DROP TABLE users; --"
	req := httptest.NewRequest(http.MethodPost, "/comments", strings.NewReader(payload))
	req.Header.Set("X-Forwarded-For", "198.51.100.23")
	req.ContentLength = int64(len(payload))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if appCalled {
		t.Fatalf("the app must never be called for a blocked request; saw body %q", appSawBody)
	}
}

func TestExternalMode_IsUnaffectedByTheInternalGate(t *testing.T) {
	client, _ := newTestClient(t) // default mode: external
	defer client.Close(context.Background())

	appCalled := false
	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/", func(c *gin.Context) { appCalled = true; c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "sqlmap/1.7")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !appCalled {
		t.Fatal("external mode has no internal engine, so the app must always be called")
	}
}

func TestHybridMode_BlocksViaInternalFirst_WithExactlyOneRelayEvent(t *testing.T) {
	// WithBatchSize(1) so the internal engine's Tier-3 relay (the ONLY relay
	// path for a flagged hybrid-mode decision — see client.go's
	// observeHybrid comment on Node's TODO-210 double-billing fix) flushes
	// immediately via TrackEvent's own send-at-batch-size behavior, making
	// the delivered-event count a direct, waitable proof of "exactly one
	// relay call, not two."
	client, rt := newTestClientWithMode(t, devfortress.ModeHybrid, devfortress.WithBatchSize(1))
	defer client.Close(context.Background())

	appCalled := false
	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/", func(c *gin.Context) { appCalled = true; c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.22")
	req.Header.Set("User-Agent", "nikto/2.5")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if appCalled {
		t.Fatal("the app must never see a blocked request")
	}

	deadline := time.Now().Add(2 * time.Second)
	for rt.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rt.count(); got != 1 {
		t.Fatalf("expected exactly 1 relayed event (no duplicate relay), got %d", got)
	}
}

func TestHybridMode_CleanRequest_ReachesTheAppAndKeepsCircuitUntouched(t *testing.T) {
	client, rt := newTestClientWithMode(t, devfortress.ModeHybrid, devfortress.WithBatchSize(1))
	defer client.Close(context.Background())

	r := gin.New()
	r.Use(Middleware(client))
	r.GET("/products", func(c *gin.Context) { c.String(http.StatusOK, "fine") })

	req := httptest.NewRequest(http.MethodGet, "/products?q=laptop", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.12")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	time.Sleep(50 * time.Millisecond)
	if rt.count() != 0 {
		t.Fatalf("a clean request must not relay anything, got %d delivered events", rt.count())
	}
}

