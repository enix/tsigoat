package common

import (
	"reflect"

	"go.uber.org/zap"
)

type AdapterSlug string

type AdapterFactory func(string, IAdapterConfiguration, *zap.SugaredLogger) (IAdapter, error)

type TransactionFactory func(IAdapter, *zap.SugaredLogger) (IAdapterTransaction, error)

type AdapterInfo struct {
	Slug       AdapterSlug
	ConfigType reflect.Type
	Type       reflect.Type
	Factory    AdapterFactory
}
