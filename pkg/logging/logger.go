package logging

import (
	"fmt"
	"io"
	"log/slog"

	slogzap "github.com/samber/slog-zap/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(format Format, level zapcore.Level, stdout io.Writer, stderr io.Writer) *zap.Logger {
	var (
		encoderConfig zapcore.EncoderConfig
		config        zap.Config
	)

	atomicLevel := zap.NewAtomicLevelAt(level)

	switch format {
	case DeveloperFormat:
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	case SimpleFormat:
		fmt.Println("!!! NOT IMPLEMENTED !!!")
	default:
		encoderConfig = zap.NewProductionEncoderConfig()
	}

	config = zap.Config{
		Level:            atomicLevel,
		Encoding:         "console",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stdout"}, // FIXME
		ErrorOutputPaths: []string{"stderr"}, // FIXME
	}

	switch format {
	case DeveloperFormat:
		config.Development = true
	case JSONFormat:
		config.Encoding = "json"
	}

	return zap.Must(config.Build())
}

func NewSlogHandler(zapLogger *zap.Logger) *slog.Logger {
	return slog.New(slogzap.Option{Logger: zapLogger}.NewZapHandler())
}
