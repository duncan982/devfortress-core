package devfortress

import "log/slog"

// Logger is the one logging method the client needs. Levels are the
// lowercase strings "warning" and "error" (the client never logs at any
// other level).
type Logger interface {
	Log(level, message string, fields map[string]any)
}

// SlogLogger adapts a *slog.Logger to Logger.
type SlogLogger struct {
	logger *slog.Logger
}

// NewSlogLogger returns a Logger backed by logger.
func NewSlogLogger(logger *slog.Logger) *SlogLogger {
	return &SlogLogger{logger: logger}
}

// Log implements Logger.
func (s *SlogLogger) Log(level, message string, fields map[string]any) {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	switch level {
	case "error":
		s.logger.Error(message, args...)
	default:
		s.logger.Warn(message, args...)
	}
}
