package logging

import (
	"github.com/enix/tsigoat/pkg/types"
)

type Format string

const (
	SimpleFormat     Format = "simple"
	StructuredFormat Format = "structured"
	JSONFormat       Format = "json"
	DeveloperFormat  Format = "developer"
)

type FormatFlag struct {
	*types.Enum
	defaultValue Format
}

func NewServerFormatFlag(defaultValue Format) *FormatFlag {
	return &FormatFlag{
		Enum: types.NewEnum(
			string(defaultValue),
			string(StructuredFormat),
			string(JSONFormat),
			string(DeveloperFormat),
		),
		defaultValue: defaultValue,
	}
}
