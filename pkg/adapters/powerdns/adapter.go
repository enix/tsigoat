package powerdns

import (
	"github.com/enix/tsigan/pkg/adapters/common"
	"go.uber.org/zap"
)

const PowerDNSAdapterSlug common.AdapterSlug = "powerdns"

type PowerDNSAdapterConfiguration struct {
	Url        string `validate:"required,http_url"`
	VHost      string `validate:"hostname"`
	Key        string `validate:"base64"`
	decodedKey string
}

type PowerDNSAdapter struct {
	name   string
	config *PowerDNSAdapterConfiguration
	logger *zap.SugaredLogger
}

func NewPowerDNSAdapter(name string, config common.IAdapterConfiguration, logger *zap.SugaredLogger) (adapter common.IAdapter, err error) {
	var pdnsConfig *PowerDNSAdapterConfiguration

	switch value := config.(type) {
	case *PowerDNSAdapterConfiguration:
		pdnsConfig = value
	default:
		panic("invalid config type for this adapter")
	}

	// FIXME config option to have b64 encoded key in config
	pdnsConfig.decodedKey = pdnsConfig.Key
	// key, error := base64.RawStdEncoding.DecodeString(pdnsConfig.Key)
	// if error != nil {
	// 	return nil, fmt.Errorf("failed to decode PowerDNS API key with base64: %w", error)
	// }
	// pdnsConfig.decodedKey = string(key)

	logger.Debugw("creating a PowerDNS adapter", "name", name, "url", pdnsConfig.Url, "vhost", pdnsConfig.VHost)

	adapter = &PowerDNSAdapter{
		name,
		pdnsConfig,
		logger,
	}
	return
}

func (a *PowerDNSAdapter) Name() string {
	return a.name
}
