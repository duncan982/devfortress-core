package devfortress

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"time"
)

// Middleware observes each request (method, path, status, timing, client IP
// and classifier result) and queues and delivers a security event for it.
// Reporting happens off the request path: the event is built, queued and
// flushed in its own goroutine after the response has gone out (see
// ObserveAndFlush), so delivery never blocks the response. Nothing here
// changes or fails the response, even if the handler panics.
func Middleware(client *Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

			defer func() {
				rec := recover()
				ObserveAndFlush(client, ObserveInput{
					Method:       r.Method,
					Path:         r.URL.Path,
					RawQuery:     r.URL.RawQuery,
					StatusCode:   sw.status,
					LatencyMs:    int(time.Since(started).Milliseconds()),
					UserAgent:    r.Header.Get("User-Agent"),
					ForwardedFor: r.Header.Get("X-Forwarded-For"),
					RealIP:       r.Header.Get("X-Real-IP"),
					RemoteAddr:   r.RemoteAddr,
				})
				if rec != nil {
					panic(rec) // Middleware must not swallow the handler's own panic.
				}
			}()

			next.ServeHTTP(sw, r)
		})
	}
}

// ObserveInput is what Observe needs to classify and queue an event for one
// request. It is the shared shape every framework adapter (this package's
// own net/http Middleware, the nested gin module, ...) fills in from its
// own request type, so the classification and queuing logic itself lives
// in exactly one place.
type ObserveInput struct {
	Method       string
	Path         string
	RawQuery     string
	StatusCode   int
	LatencyMs    int
	UserAgent    string
	ForwardedFor string
	RealIP       string
	// RemoteAddr is the socket address, "host:port" or a bare host; the
	// port (if any) is stripped before it is used as a client IP.
	RemoteAddr string
}

// Observe classifies one request/response and, when it is security-relevant,
// queues an event for it — in its own goroutine, detached from the
// request's own context (which is cancelled once the response is written),
// so a batch-size auto-flush can never delay the caller. The event is only
// queued: under sparse traffic (fewer requests than the batch size between
// flushes) it can sit undelivered indefinitely unless something else
// flushes it — WithFlushInterval, an explicit Flush/Close, or
// ObserveAndFlush below. Framework adapters call ObserveAndFlush, not
// Observe, for exactly this reason.
func Observe(client *Client, in ObserveInput) {
	observe(client, in, false)
}

// ObserveAndFlush behaves like Observe, but also flushes the queue once the
// event has been classified and queued, in that same detached goroutine —
// so a single event is delivered even under sparse traffic, with no
// separate goroutine racing the enqueue. This is what every framework
// adapter (this package's own net/http Middleware, the nested gin module,
// ...) calls.
func ObserveAndFlush(client *Client, in ObserveInput) {
	observe(client, in, true)
}

func observe(client *Client, in ObserveInput, flush bool) {
	ip := ResolveClientIP(in.ForwardedFor, in.RealIP, RemoteHost(in.RemoteAddr))
	classify := ClassifyInput{
		IP:         ip,
		Method:     in.Method,
		Path:       in.Path,
		StatusCode: in.StatusCode,
		LatencyMs:  in.LatencyMs,
		UserAgent:  in.UserAgent,
		Query:      in.RawQuery,
	}
	go func() {
		event := BuildEvent(classify)
		if event == nil {
			return
		}
		client.TrackEvent(context.Background(), event)
		if flush {
			client.Flush(context.Background())
		}
	}()
}

// RemoteHost strips the port from a "host:port" remote address, or returns
// remoteAddr unchanged when it isn't in that form.
func RemoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// statusWriter records the response status without changing behaviour, and
// preserves http.Flusher and http.Hijacker where the wrapped
// ResponseWriter implements them.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}
