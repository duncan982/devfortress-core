package devfortress

import (
	"net"
	"strings"
)

// ResolveClientIP picks the end-user IP for an event from what the request
// shows.
//
// Precedence: the first X-Forwarded-For entry, then X-Real-IP, then the
// socket address, then "0.0.0.0". A candidate that is not an IP address is
// skipped, so a malformed forwarded header cannot poison a batch.
func ResolveClientIP(forwardedFor, realIP, remoteAddr string) string {
	first := ""
	if forwardedFor != "" {
		first = strings.TrimSpace(strings.SplitN(forwardedFor, ",", 2)[0])
	}
	for _, candidate := range []string{first, strings.TrimSpace(realIP), strings.TrimSpace(remoteAddr)} {
		if candidate != "" && net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return "0.0.0.0"
}
