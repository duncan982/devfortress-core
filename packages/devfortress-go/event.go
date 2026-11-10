package devfortress

// Event is a security event as the ingest endpoint takes it. Keys are the
// wire field names (eventType, ip, method, path, severity, ...).
type Event map[string]any

// DeliveryResult is the outcome of one delivery attempt (or batch chunk).
// The client returns this instead of returning an error or panicking.
type DeliveryResult struct {
	// OK is true when the platform accepted the delivery (2xx).
	OK bool
	// StatusCode is the HTTP status received, or 0 when no response was
	// received at all (a network error, or the request was never sent).
	StatusCode int
	// Body is the decoded JSON response body (map, slice, string, or nil
	// for an empty body); it is the raw string when the body isn't valid
	// JSON.
	Body any
	// Err describes why delivery failed; nil when OK is true.
	Err error
	// Attempts is how many delivery attempts were made (at least 1, or 0
	// when no attempt was made at all, e.g. the payload could not be
	// encoded).
	Attempts int
}
