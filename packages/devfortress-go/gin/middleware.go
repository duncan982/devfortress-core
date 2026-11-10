// Package devfortressgin is the Gin adapter for the DevFortress Go SDK. It
// observes each request the same way the core module's net/http Middleware
// does, reusing its classification and event-queuing logic: no signing or
// HTTP delivery code lives here.
package devfortressgin

import (
	"bytes"
	"io"
	"net/http"
	"time"

	devfortress "github.com/duncan982/devfortress-core/packages/devfortress-go"
	"github.com/gin-gonic/gin"
)

// maxGatedBodyBytes bounds how much of the request body the internal/
// hybrid-mode gate (see internalGate below) will buffer for Tier-1
// body-pattern matching (e.g. a SQLi payload in a POST body). A request
// body larger than this is left unread by the gate — body-based rules
// simply don't fire for it, the same as if no body were present — rather
// than buffering an attacker-controlled, unbounded amount of memory per
// request. Path/query/header-based rules are unaffected either way.
const maxGatedBodyBytes = 1 << 20 // 1 MiB

// Middleware observes each Gin request (method, path, status, timing,
// client IP and classifier result) and queues and delivers a security event
// for it. Reporting happens off the request path: devfortress.ObserveAndFlush
// classifies, queues and flushes the event in its own goroutine, after
// c.Next() has already returned and the response has gone out — so delivery
// never delays the response, even under sparse traffic where a batch-size
// auto-flush alone would leave the event sitting in the queue indefinitely.
//
// In internal/hybrid mode (client.Mode(), set via devfortress.WithMode),
// this also runs a pre-response gate (see internalGate) before the request
// reaches the handler: a flagged decision short-circuits with a 403 JSON
// response via c.AbortWithStatusJSON, and the handler and the after-response
// event report are both skipped. External mode (the default) is unaffected
// — client.Observe is a no-op there, so nothing here changes behavior for
// existing callers.
func Middleware(client *devfortress.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		if client.Mode() == devfortress.ModeInternal || client.Mode() == devfortress.ModeHybrid {
			if internalGate(client, c) {
				return // blocked: do not forward to the handler or report an event
			}
		}

		started := time.Now()
		c.Next()

		req := c.Request
		devfortress.ObserveAndFlush(client, devfortress.ObserveInput{
			Method:       req.Method,
			Path:         req.URL.Path, // the actual path, not gin's route template
			RawQuery:     req.URL.RawQuery,
			StatusCode:   c.Writer.Status(),
			LatencyMs:    int(time.Since(started).Milliseconds()),
			UserAgent:    req.UserAgent(),
			ForwardedFor: req.Header.Get("X-Forwarded-For"),
			RealIP:       req.Header.Get("X-Real-IP"),
			RemoteAddr:   req.RemoteAddr,
		})
	}
}

// internalGate runs the internal/hybrid-mode pre-response gate. Returns
// true if the request was blocked (the caller must not forward it to the
// handler).
//
// Scope decision (documented explicitly, not silently scope-limited): this
// gate DOES include the request body in Tier-1 matching, unlike the Python
// port's FastAPI/ASGI gate, which excludes the body because re-reading the
// ASGI body stream there without replaying it to the downstream app would
// break any route that reads its own body. Go's http.Request.Body is also
// a single-read stream, but — unlike raw ASGI — it can be read once with
// io.ReadAll and then cleanly replaced with io.NopCloser(bytes.NewReader(...))
// so every downstream handler (and Gin's own c.ShouldBindJSON etc.) still
// sees a fresh, fully-readable body exactly as if the gate had never run.
// This gives Go fuller parity with Node's body-inspecting rules than the
// Python port's FastAPI gate has (Python's Flask gate, which buffers the
// body eagerly for its own unrelated reasons, already gets this for free).
// The one bound: maxGatedBodyBytes, to avoid buffering an unbounded,
// attacker-controlled body into memory per request.
func internalGate(client *devfortress.Client, c *gin.Context) bool {
	req := c.Request

	var body string
	if req.Body != nil && req.ContentLength >= 0 && req.ContentLength <= maxGatedBodyBytes {
		if raw, err := io.ReadAll(io.LimitReader(req.Body, maxGatedBodyBytes+1)); err == nil {
			if len(raw) <= maxGatedBodyBytes {
				body = string(raw)
			}
			req.Body = io.NopCloser(bytes.NewReader(raw))
		}
	}

	headers := map[string]string{}
	for k := range req.Header {
		headers[k] = req.Header.Get(k)
	}

	clReq := devfortress.InternalCLRequest{
		IP:        devfortress.ResolveClientIP(req.Header.Get("X-Forwarded-For"), req.Header.Get("X-Real-IP"), devfortress.RemoteHost(req.RemoteAddr)),
		Method:    req.Method,
		Path:      req.URL.Path,
		UserAgent: req.UserAgent(),
		Query:     req.URL.RawQuery,
		Headers:   headers,
		Body:      body,
	}

	result := client.Observe(clReq)
	if result == nil || !result.Flagged {
		return false
	}

	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   "blocked",
		"reason":  result.Decision,
		"eventId": result.EventID,
	})
	return true
}
