package logging_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/enix/tsigoat/internal/logging"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format  logging.Format
		want    string
		wantErr bool
	}{
		{format: logging.FormatText, want: "level=WARN msg=hello key=value"},
		{format: logging.FormatJSON, want: `"level":"WARN","msg":"hello","key":"value"`},
		{format: "xml", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			logger, err := logging.New(&out, tt.format, slog.LevelWarn)
			if tt.wantErr {
				if err == nil {
					t.Fatal("New() succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			logger.Info("filtered out")
			logger.Warn("hello", "key", "value")
			if got := out.String(); !strings.Contains(got, tt.want) || strings.Contains(got, "filtered out") {
				t.Errorf("output %q, want it to contain %q and only the warning", got, tt.want)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	} {
		got, err := logging.ParseLevel(name)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v, want %v", name, got, err, want)
		}
	}
	if _, err := logging.ParseLevel("verbose"); err == nil {
		t.Error("ParseLevel(verbose) succeeded, want an error")
	}
}
