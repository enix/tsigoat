package logging

import (
	"fmt"

	"github.com/enix/tsigan/pkg/types"

	"go.uber.org/zap/zapcore"
)

var (
	sortedLevels []zapcore.Level = []zapcore.Level{
		zapcore.DebugLevel,
		zapcore.InfoLevel,
		zapcore.WarnLevel,
		zapcore.ErrorLevel,
		zapcore.DPanicLevel,
		zapcore.PanicLevel,
		zapcore.FatalLevel,
	}
	sortedLevelNames []string
)

func init() {
	for _, level := range sortedLevels {
		sortedLevelNames = append(sortedLevelNames, level.String())
	}
}

type LevelFlag struct {
	*types.Enum
	defaultValue zapcore.Level
}

func SortedLevels() []zapcore.Level {
	return sortedLevels
}

func SortedLevelNames() []string {
	return sortedLevelNames
}

func ParseLevel(name string) (zapcore.Level, error) {
	level, err := zapcore.ParseLevel(name)
	if err != nil {
		return zapcore.InvalidLevel, fmt.Errorf("invalid logging level '%s'", name)
	}
	return level, nil
}

func NewLevelFlag(defaultValue zapcore.Level) *LevelFlag {
	return &LevelFlag{
		Enum:         types.NewEnum(defaultValue.String(), sortedLevelNames...),
		defaultValue: defaultValue,
	}
}
