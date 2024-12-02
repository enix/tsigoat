package server

import (
	"fmt"
	"reflect"

	"github.com/enix/tsigan/internal/product"
	"github.com/enix/tsigan/pkg/adapters"
	"github.com/enix/tsigan/pkg/adapters/common"
	"github.com/enix/tsigan/pkg/types"
	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
	validate.RegisterValidation("uniquedefault", validateUniqueDefault)
	validate.RegisterValidation("adapterslug", validateAdapterSlug)
	validate.RegisterValidation("zoneconfig", validateZoneConfiguration)
}

const (
	YamlConfiguration ConfigFormat = "yaml"
	JsonConfiguration ConfigFormat = "json"
	TomlConfiguration ConfigFormat = "toml"
)

type ConfigFormat string

type ConfigFormatFlag struct {
	*types.Enum
	defaultValue ConfigFormat
}

type ConfigurationFile struct {
	Type        ConfigFormatFlag
	Name        string
	SearchPaths []string
	FullPath    string
}

type Configuration struct {
	Tsig     TsigConfiguration
	Handlers []HandlerConfiguration `validate:"gt=0,unique=Name,uniquedefault,dive"`
	Zones    []ZoneConfiguration    `validate:"gt=0,unique=Zone,dive,zoneconfig"`
}

type TsigConfiguration struct {
	Keys []TsigKeyConfiguration `validate:"unique=Name,uniquedefault,dive"`
}

type TsigKeyConfiguration struct {
	Default bool
	Name    string `validate:"required,printascii"` // FIXME check RFC (format and length)
	Key     string `validate:"required,base64"`
}

type EmbeddedHandlerConfiguration struct {
	Default bool
	Name    string             `validate:"required,printascii"`
	Adapter common.AdapterSlug `validate:"required,adapterslug"`
}

type HandlerConfiguration struct {
	EmbeddedHandlerConfiguration
	Settings common.IAdapterConfiguration
}

type ZoneConfiguration struct {
	Zone     string   `validate:"required,fqdn"`
	Handler  string   `validate:"omitempty,printascii"`
	Keys     []string `validate:"omitempty,dive,printascii"` // FIXME check RFC (format and length)
	Unsecure bool
}

func NewConfigurationFile(defaultFormat ConfigFormat) *ConfigurationFile {
	return &ConfigurationFile{
		Name: product.Slug,
		Type: ConfigFormatFlag{
			Enum: types.NewEnum(
				string(defaultFormat),
				string(YamlConfiguration),
				string(JsonConfiguration),
				string(TomlConfiguration),
			),
			defaultValue: defaultFormat,
		},
	}
}

func (c *Configuration) Unmarshal(viper *viper.Viper) error {
	var err error

	err = viper.Unmarshal(c, func(decoderConfig *mapstructure.DecoderConfig) {
		decoderConfig.ErrorUnused = true
		decoderConfig.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			decodeHandlerConfiguration(),
		)
	})
	if err != nil {
		return fmt.Errorf("parsing error: %w", err)
	}

	if err = validate.Struct(c); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	return nil
}

func decodeHandlerConfiguration() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		var err error

		if to != reflect.TypeFor[HandlerConfiguration]() {
			return data, nil
		}

		if from.Kind() != reflect.Map {
			return data, fmt.Errorf("expected handler configuration to be a map")
		}

		embeddedConfig := EmbeddedHandlerConfiguration{}
		embeddedConfigDecoder, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			Result:      &embeddedConfig,
			ErrorUnused: false,
			ErrorUnset:  false,
		})
		if err = embeddedConfigDecoder.Decode(data); err != nil {
			return data, fmt.Errorf("failed to decode handler configuration (embedded)")
		}

		abstractAdapterConfig, err := adapters.NewAdapterConfiguration(embeddedConfig.Adapter)
		if err != nil {
			return data, fmt.Errorf("handler decoder: %w", err)
		}

		adapterData, found := data.(map[string]interface{})[string(embeddedConfig.Adapter)]
		if !found {
			return data, fmt.Errorf("missing settings for %s adapter '%s'", embeddedConfig.Adapter, embeddedConfig.Name)
		}

		adapterConfigDecoder, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			Result:      abstractAdapterConfig,
			ErrorUnused: true,
			ErrorUnset:  false,
		})
		if err = adapterConfigDecoder.Decode(adapterData); err != nil {
			return data, fmt.Errorf("failed to decode handler adapter configuration")
		}

		config := HandlerConfiguration{
			EmbeddedHandlerConfiguration: embeddedConfig,
			Settings:                     abstractAdapterConfig,
		}
		return config, nil
	}
}

func validateUniqueDefault(fl validator.FieldLevel) bool {
	if !fl.Field().Type().CanSeq2() {
		panic("bad type for default element uniqueness validation")
	}

	defaultFound := false
	for _, elem := range fl.Field().Seq2() {
		field := elem.FieldByName("Default")
		if field.Kind() != reflect.Bool {
			panic("bad field type for the default property")
		}
		if field.Bool() {
			if defaultFound {
				return false
			} else {
				defaultFound = true
			}
		}
	}

	return true
}

func validateAdapterSlug(fl validator.FieldLevel) bool {
	if fl.Field().Type() != reflect.TypeFor[common.AdapterSlug]() {
		panic("wrong type for adapter slug validation")
	}

	// TODO refactor
	return adapters.IsSlug(fl.Field().Interface().(common.AdapterSlug))
}

func validateZoneConfiguration(fl validator.FieldLevel) bool {
	top := fl.Top().Interface().(*Configuration)
	val := fl.Field().Interface().(ZoneConfiguration)

	// validate the handler
	if val.Handler != "" {
		found := false
		for _, handler := range top.Handlers {
			if val.Handler == handler.Name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	} else {
		// check the default handler exists
		hasDefault := false
		for _, handler := range top.Handlers {
			if handler.Default {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			return false
		}
	}

	if val.Unsecure {
		// want no key when auth disabled
		// enforced to make it more difficult to craft unsafe config by accident
		if len(val.Keys) > 0 {
			return false
		}
	} else {
		if len(val.Keys) > 0 {
			// check all key references resolve
			for _, key := range val.Keys {
				found := false
				for _, tkey := range top.Tsig.Keys {
					if key == tkey.Name {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		} else {
			// check the default key exists
			hasDefault := false
			for _, key := range top.Tsig.Keys {
				if key.Default {
					hasDefault = true
					break
				}
			}
			if !hasDefault {
				return false
			}
		}
	}

	return true
}
