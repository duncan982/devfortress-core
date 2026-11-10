package devfortress

import (
	"context"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testKey = "vx_live_test_vector_key_do_not_use"

var testEvent = Event{
	"eventType": "auth_failure",
	"ip":        "203.0.113.7",
	"method":    "POST",
	"path":      "/login",
	"severity":  "LOW",
}

func newTestClient(t *testing.T, transport Transport, opts ...Option) (*Client, *recordingTransport) {
	t.Helper()
	rt, ok := transport.(*recordingTransport)
	if !ok {
		t.Fatal("newTestClient requires a *recordingTransport")
	}
	var sleeps []time.Duration
	base := []Option{
		WithTimeout(2 * time.Second),
		WithTransport(rt),
		WithSleeper(func(d time.Duration) { sleeps = append(sleeps, d) }),
	}
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return client, rt
}

func bodyOf(t *testing.T, rt *recordingTransport, i int) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rt.requests[i].body, &m); err != nil {
		t.Fatalf("request %d body is not JSON: %v", i, err)
	}
	return m
}

func TestConstructionRequiresAnAPIKey(t *testing.T) {
	if _, err := NewClient("", "http://x"); err == nil {
		t.Fatal("expected an error for an empty API key")
	}
}

func TestDefaultsMatchTheOtherSDKs(t *testing.T) {
	if DefaultTimeout != 15*time.Second {
		t.Errorf("DefaultTimeout = %v", DefaultTimeout)
	}
	if DefaultRetries != 3 {
		t.Errorf("DefaultRetries = %v", DefaultRetries)
	}
	if DefaultBatchSize != 25 {
		t.Errorf("DefaultBatchSize = %v", DefaultBatchSize)
	}
	if MaxServerBatch != 100 {
		t.Errorf("MaxServerBatch = %v", MaxServerBatch)
	}
	if DefaultEndpoint != "https://www.devfortress.net/api/events/ingest" {
		t.Errorf("DefaultEndpoint = %v", DefaultEndpoint)
	}
}

func TestEventsAreQueuedUntilFlushAndSentAsABatch(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	ctx := context.Background()
	client.TrackEvent(ctx, testEvent)
	client.TrackEvent(ctx, testEvent)
	client.TrackEvents(ctx, []Event{testEvent})
	if got := client.PendingEvents(); got != 3 {
		t.Fatalf("PendingEvents() = %d, want 3", got)
	}
	if len(rt.requests) != 0 {
		t.Fatalf("expected no requests before flush, got %d", len(rt.requests))
	}

	results := client.Flush(ctx)
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("results = %+v", results)
	}
	if got := client.PendingEvents(); got != 0 {
		t.Errorf("PendingEvents() after flush = %d", got)
	}
	if len(rt.requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(rt.requests))
	}
	body := bodyOf(t, rt, 0)
	events, _ := body["events"].([]any)
	if len(events) != 3 {
		t.Errorf("events in batch = %d, want 3", len(events))
	}
	if rt.requests[0].method != "POST" {
		t.Errorf("method = %s", rt.requests[0].method)
	}
	if rt.requests[0].url != "http://platform.test/api/events/ingest" {
		t.Errorf("url = %s", rt.requests[0].url)
	}
}

func TestEveryQueuedEventGetsATimestamp(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	client.TrackEvent(context.Background(), testEvent)
	client.Flush(context.Background())
	events := bodyOf(t, rt, 0)["events"].([]any)
	ts, _ := events[0].(map[string]any)["timestamp"].(string)
	if !isoMillisPattern.MatchString(ts) {
		t.Errorf("timestamp %q does not match the expected shape", ts)
	}
}

var isoMillisPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func TestFlushWithNothingQueuedMakesNoRequest(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	if results := client.Flush(context.Background()); results != nil {
		t.Errorf("expected nil results, got %v", results)
	}
	if len(rt.requests) != 0 {
		t.Errorf("expected no requests, got %d", len(rt.requests))
	}
}

func TestTheQueueFlushesAtTheBatchSize(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	ctx := context.Background()
	for i := 0; i < 24; i++ {
		client.TrackEvent(ctx, testEvent)
	}
	if len(rt.requests) != 0 {
		t.Fatalf("expected no requests yet, got %d", len(rt.requests))
	}
	client.TrackEvent(ctx, testEvent)
	if len(rt.requests) != 1 {
		t.Fatalf("expected auto-flush at batch size, got %d requests", len(rt.requests))
	}
	events := bodyOf(t, rt, 0)["events"].([]any)
	if len(events) != 25 {
		t.Errorf("batch size = %d, want 25", len(events))
	}
}

func TestFlushSplitsAtTheServerMaximum(t *testing.T) {
	client, rt := newTestClient(t, okTransport(), WithBatchSize(1000))
	ctx := context.Background()
	for i := 0; i < 150; i++ {
		client.TrackEvent(ctx, testEvent)
	}
	client.Flush(ctx)
	var sizes []int
	for i := range rt.requests {
		events := bodyOf(t, rt, i)["events"].([]any)
		sizes = append(sizes, len(events))
	}
	if len(sizes) != 2 || sizes[0] != 100 || sizes[1] != 50 {
		t.Errorf("chunk sizes = %v, want [100 50]", sizes)
	}
}

func TestStrictPrivacyHashesTheIPAndDropsTheUserAgent(t *testing.T) {
	client, rt := newTestClient(t, okTransport(), WithPrivacy("strict"))
	event := Event{}
	for k, v := range testEvent {
		event[k] = v
	}
	event["userAgent"] = "ua"
	client.TrackEvent(context.Background(), event)
	client.Flush(context.Background())
	events := bodyOf(t, rt, 0)["events"].([]any)
	first := events[0].(map[string]any)
	if first["ip"] == "203.0.113.7" {
		t.Error("expected the ip to be hashed")
	}
	if _, hasUA := first["userAgent"]; hasUA {
		t.Error("expected userAgent to be dropped under strict privacy")
	}
}

func TestDefaultsAreMergedUnderTheEvent(t *testing.T) {
	rt := okTransport()
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(rt), WithDefaults(map[string]any{"appId": "a", "environment": "e"}))
	if err != nil {
		t.Fatal(err)
	}
	event := Event{}
	for k, v := range testEvent {
		event[k] = v
	}
	event["environment"] = "override"
	client.TrackEvent(context.Background(), event)
	client.Flush(context.Background())
	first := bodyOf(t, rt, 0)["events"].([]any)[0].(map[string]any)
	if first["appId"] != "a" || first["environment"] != "override" {
		t.Errorf("appId=%v environment=%v", first["appId"], first["environment"])
	}
}

func TestEveryRequestIsSignedWithAKeyIDAndNeverTheKey(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	ctx := context.Background()
	if !client.TestConnection(ctx) {
		t.Fatal("expected TestConnection to succeed")
	}
	client.TrackEvent(ctx, testEvent)
	client.TrackEvents(ctx, []Event{testEvent, testEvent})
	client.Flush(ctx)

	if len(rt.requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(rt.requests))
	}
	for i, req := range rt.requests {
		wire := req.headers
		if got := Verify(testKey, "POST", "/api/events/ingest", string(req.body), wire, mustSignedNowMs(t, wire)); got != ResultValid {
			t.Errorf("request %d: verify = %s", i, got)
		}
		if wire[VersionHeader] != "2" {
			t.Errorf("request %d: version = %s", i, wire[VersionHeader])
		}
		if wire[KeyIDHeader] != DeriveKeyID(testKey) {
			t.Errorf("request %d: key id mismatch", i)
		}
		for _, forbidden := range []string{"X-DevFortress-Key", "X-Api-Key", "Authorization"} {
			if _, ok := wire[forbidden]; ok {
				t.Errorf("request %d: carries forbidden header %s", i, forbidden)
			}
		}
		carriesKey := strings.Contains(string(req.body), testKey) || strings.Contains(req.url, testKey)
		for _, v := range wire {
			carriesKey = carriesKey || strings.Contains(v, testKey)
		}
		if carriesKey {
			t.Errorf("request %d carries the API key", i)
		}
	}
}

func mustSignedNowMs(t *testing.T, headers map[string]string) int64 {
	t.Helper()
	ms, err := strconv.ParseInt(headers[TimestampHeader], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func TestEachRetryAttemptCarriesAFreshNonceAndTimestamp(t *testing.T) {
	rt := &recordingTransport{script: []any{
		&TransportResponse{StatusCode: 503, Body: []byte("{}")},
		&TransportResponse{StatusCode: 502, Body: []byte("{}")},
		&TransportResponse{StatusCode: 200, Body: []byte(`{"success":true}`)},
	}}
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(rt), WithSleeper(func(time.Duration) {
		time.Sleep(3 * time.Millisecond) // let the millisecond clock advance between attempts
	}))
	if err != nil {
		t.Fatal(err)
	}
	client.TrackEvent(context.Background(), testEvent)
	results := client.Flush(context.Background())

	if !results[0].OK || results[0].Attempts != 3 {
		t.Fatalf("results[0] = %+v", results[0])
	}
	if len(rt.requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(rt.requests))
	}
	nonces := map[string]bool{}
	stamps := map[string]bool{}
	for _, req := range rt.requests {
		if got := Verify(testKey, "POST", "/api/events/ingest", string(req.body), req.headers, mustSignedNowMs(t, req.headers)); got != ResultValid {
			t.Errorf("verify = %s", got)
		}
		nonces[req.headers[NonceHeader]] = true
		stamps[req.headers[TimestampHeader]] = true
	}
	if len(nonces) != 3 {
		t.Error("each attempt needs its own nonce")
	}
	if len(stamps) != 3 {
		t.Error("each attempt needs its own timestamp")
	}
}

func TestFiveHundredsAreRetriedThenGivenUpOnWithoutThrowing(t *testing.T) {
	rt := &recordingTransport{script: []any{&TransportResponse{StatusCode: 502, Body: []byte(`{"error":"bad gateway"}`)}}}
	var sleeps []time.Duration
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(rt), WithSleeper(func(d time.Duration) { sleeps = append(sleeps, d) }))
	if err != nil {
		t.Fatal(err)
	}
	client.TrackEvent(context.Background(), testEvent)
	results := client.Flush(context.Background())

	if len(rt.requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(rt.requests))
	}
	if results[0].OK || results[0].StatusCode != 502 {
		t.Fatalf("results[0] = %+v", results[0])
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if len(sleeps) != len(want) || sleeps[0] != want[0] || sleeps[1] != want[1] {
		t.Errorf("sleeps = %v, want %v", sleeps, want)
	}
}

func TestNonRetryableStatusesAreSentOnce(t *testing.T) {
	for _, status := range []int{400, 401, 403, 429, 301} {
		client, rt := newTestClient(t, &recordingTransport{script: []any{&TransportResponse{StatusCode: status, Body: []byte(`{"error":"nope"}`)}}})
		client.TrackEvent(context.Background(), testEvent)
		results := client.Flush(context.Background())
		if len(rt.requests) != 1 {
			t.Errorf("status %d: expected 1 request, got %d", status, len(rt.requests))
		}
		if results[0].OK || results[0].StatusCode != status {
			t.Errorf("status %d: results[0] = %+v", status, results[0])
		}
	}
}

func TestNetworkErrorsAreRetriedAndNeverThrown(t *testing.T) {
	client, rt := newTestClient(t, &recordingTransport{script: []any{downError()}})
	client.TrackEvent(context.Background(), testEvent)
	results := client.Flush(context.Background())
	if len(rt.requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(rt.requests))
	}
	if results[0].OK || results[0].StatusCode != 0 {
		t.Fatalf("results[0] = %+v", results[0])
	}
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "connection refused") {
		t.Errorf("err = %v", results[0].Err)
	}
}

func TestATransportThatPanicsNeverReachesTheHost(t *testing.T) {
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest", WithTransport(panicTransport{}), WithSleeper(func(time.Duration) {}))
	if err != nil {
		t.Fatal(err)
	}
	client.TrackEvent(context.Background(), testEvent)
	results := client.Flush(context.Background())
	if results[0].OK {
		t.Fatal("expected failure")
	}
	if client.TestConnection(context.Background()) {
		t.Fatal("expected TestConnection to report false")
	}
}

func TestAThrowingLoggerNeverReachesTheHost(t *testing.T) {
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest",
		WithTransport(&recordingTransport{script: []any{&TransportResponse{StatusCode: 500, Body: []byte("{}")}}}),
		WithLogger(panicLogger{}), WithRetries(1))
	if err != nil {
		t.Fatal(err)
	}
	client.TrackEvent(context.Background(), testEvent)
	if client.Flush(context.Background())[0].OK {
		t.Fatal("expected failure")
	}
}

func TestFailuresAreLoggedThroughTheLoggerWithoutTheKey(t *testing.T) {
	logger := &recordingLogger{}
	client, err := NewClient(testKey, "http://platform.test/api/events/ingest",
		WithTransport(&recordingTransport{script: []any{&TransportResponse{StatusCode: 401, Body: []byte(`{"error":"no"}`)}}}),
		WithLogger(logger), WithRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	client.TrackEvent(context.Background(), testEvent)
	client.Flush(context.Background())
	if len(logger.lines) != 1 {
		t.Fatalf("expected 1 log line, got %d: %v", len(logger.lines), logger.lines)
	}
	if !strings.HasPrefix(logger.lines[0], "warning devfortress: delivery failed: HTTP 401") {
		t.Errorf("log line = %q", logger.lines[0])
	}
	if strings.Contains(logger.lines[0], testKey) {
		t.Error("log line carries the API key")
	}
}

func TestAnUnauthorizedKeyIsSurfacedByTestConnection(t *testing.T) {
	client, rt := newTestClient(t, &recordingTransport{script: []any{&TransportResponse{StatusCode: 401, Body: []byte(`{"error":"no"}`)}}})
	if client.TestConnection(context.Background()) {
		t.Fatal("expected TestConnection to report false")
	}
	if len(rt.requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(rt.requests))
	}
	body := bodyOf(t, rt, 0)
	if body["path"] != "/__devfortress/test" {
		t.Errorf("path = %v", body["path"])
	}
	meta, _ := body["metadata"].(map[string]any)
	if meta["test"] != true || meta["sdk"] != "go" {
		t.Errorf("metadata = %v", meta)
	}
}

func TestAnUnreachablePlatformMakesTestConnectionFalseNotAPanic(t *testing.T) {
	client, _ := newTestClient(t, &recordingTransport{script: []any{downError()}})
	if client.TestConnection(context.Background()) {
		t.Fatal("expected false")
	}
}

func TestUnencodableEventsAreDroppedWithoutThrowing(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	client.TrackEvent(context.Background(), Event{"eventType": "custom", "metadata": map[string]any{"x": math.NaN()}})
	if client.Flush(context.Background())[0].OK {
		t.Fatal("expected failure")
	}
	if len(rt.requests) != 0 {
		t.Errorf("expected no requests, got %d", len(rt.requests))
	}
}

func TestCloseFlushesWhateverIsQueued(t *testing.T) {
	client, rt := newTestClient(t, okTransport())
	client.TrackEvent(context.Background(), testEvent)
	client.Close(context.Background())
	if len(rt.requests) != 1 {
		t.Errorf("expected Close to flush, got %d requests", len(rt.requests))
	}
	client.Close(context.Background()) // safe to call twice
}

func TestBackgroundFlushSendsOnTheConfiguredInterval(t *testing.T) {
	client, rt := newTestClient(t, okTransport(), WithFlushInterval(10*time.Millisecond))
	client.TrackEvent(context.Background(), testEvent)
	deadline := time.Now().Add(2 * time.Second)
	for rt.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if rt.count() == 0 {
		t.Fatal("expected the background flush to have sent the event")
	}
	client.Close(context.Background())
}
