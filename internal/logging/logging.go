// Package logging builds the structured logger of tsigoat on top of log/slog.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Format is the output format of the logs.
type Format string

// Supported formats.
const (
	// FormatText writes key=value lines, for humans.
	FormatText Format = "text"
	// FormatJSON writes one JSON object per line, for log collectors.
	FormatJSON Format = "json"
)

// Formats lists the supported formats.
func Formats() []string {
	return []string{string(FormatText), string(FormatJSON)}
}

// Levels lists the supported levels.
func Levels() []string {
	return []string{"debug", "info", "warn", "error"}
}

// New returns a logger writing to w in the given format, from the given
// level up.
func New(w io.Writer, format Format, level slog.Level) (*slog.Logger, error) {
	options := &slog.HandlerOptions{Level: level}
	switch format {
	case FormatText:
		return slog.New(slog.NewTextHandler(w, options)), nil
	case FormatJSON:
		return slog.New(slog.NewJSONHandler(w, options)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q (expected %s)", format, strings.Join(Formats(), " or "))
	}
}

// ParseLevel parses a level name: debug, info, warn or error.
func ParseLevel(name string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(name)); err != nil {
		return 0, fmt.Errorf("unknown log level %q (expected one of %s)", name, strings.Join(Levels(), ", "))
	}
	return level, nil
}
