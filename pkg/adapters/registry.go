package adapters

import (
	"fmt"
	"reflect"

	"github.com/enix/tsigan/pkg/adapters/common"
	"github.com/enix/tsigan/pkg/adapters/powerdns"
	"go.uber.org/zap"
)

// TODO refactor
var adapters = map[common.AdapterSlug]*common.AdapterInfo{}

func init() {
	registerAdapter(
		powerdns.PowerDNSAdapterSlug,
		reflect.TypeFor[powerdns.PowerDNSAdapterConfiguration](),
		reflect.TypeFor[powerdns.PowerDNSAdapter](),
		powerdns.NewPowerDNSAdapter)
}

func registerAdapter(slug common.AdapterSlug, configType reflect.Type, concreteType reflect.Type,
	factory common.AdapterFactory) {

	if _, found := adapters[slug]; found {
		panic("adapter slug collision")
	}

	adapters[slug] = &common.AdapterInfo{
		Slug:       slug,
		ConfigType: configType,
		Type:       concreteType,
		Factory:    factory,
	}
}

// TODO refactor
func adapterInfoBySlug(slug common.AdapterSlug) (*common.AdapterInfo, error) {
	info, found := adapters[slug]
	if !found {
		return nil, fmt.Errorf("invalid adapter type '%s'", slug)
	}
	return info, nil
}

// TODO refactor
func adapterInfoByConfigType(configType reflect.Type) (*common.AdapterInfo, error) {
	slug := common.AdapterSlug("")
	for k, adapter := range adapters {
		if configType == adapter.ConfigType {
			slug = k
			break
		}
	}
	return adapterInfoBySlug(slug)
}

// TODO refactor
func adapterInfoByAdapterType(concreteType reflect.Type) (*common.AdapterInfo, error) {
	slug := common.AdapterSlug("")
	for k, adapter := range adapters {
		if concreteType == adapter.Type {
			slug = k
			break
		}
	}
	return adapterInfoBySlug(slug)
}

// TODO refactor
func IsSlug(slug common.AdapterSlug) (valid bool) {
	_, valid = adapters[slug]
	return
}

func NewAdapterConfiguration(slug common.AdapterSlug) (config common.IAdapterConfiguration, err error) {
	info, err := adapterInfoBySlug(slug)
	if err != nil {
		return
	}

	config = reflect.New(info.ConfigType).Interface()
	return
}

func NewAdapter(name string, configuration common.IAdapterConfiguration, logger *zap.SugaredLogger) (adapter common.IAdapter, err error) {
	info, err := adapterInfoByConfigType(reflect.TypeOf(configuration).Elem())
	if err != nil {
		return
	}

	logger.Debugw("registry creating a new adapter", "slug", info.Slug)

	adapter, err = info.Factory(name, configuration, logger)
	if err != nil {
		panic("FIXME message")
	}
	return
}
