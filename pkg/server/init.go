package server

import (
	"fmt"

	"github.com/enix/tsigoat/pkg/adapters"
	"github.com/enix/tsigoat/pkg/adapters/common"
	"github.com/enix/tsigoat/pkg/dns"
)

func (s *Server) init() (err error) {
	Logger.Debug("initializing server state")

	// process TSIG keys from configuration
	Logger.Debugw("initializing keyring", "count", len(s.Configuration.Tsig.Keys))
	for _, config := range s.Configuration.Tsig.Keys {
		if err = s.newKey(&config); err != nil {
			return
		}
	}
	Logger.Debug("finished initializing keyring")

	// process handlers from configuration
	Logger.Debugw("initializing handler", "count", len(s.Configuration.Handlers))
	for _, config := range s.Configuration.Handlers {
		if err = s.newHandler(&config); err != nil {
			return
		}
	}
	Logger.Debug("finished initializing handler")

	// process zones from configuration
	Logger.Debugw("initializing zones", "count", len(s.Configuration.Zones))
	for _, config := range s.Configuration.Zones {
		if err = s.newZone(&config); err != nil {
			return
		}
	}
	Logger.Debug("finished initializing zones")

	Logger.Debug("finished initializing server state")
	return
}

func (s *Server) newKey(config *TsigKeyConfiguration) error {
	Logger.Debugw("adding new key", "name", config.Name)

	if err := s.keyring.AddEncodedKey(config.Name, config.Key); err != nil {
		return fmt.Errorf("failed to add key '%s' to keyring: %w", config.Name, err)
	}

	if config.Default {
		if len(s.defaultKeyName) > 0 {
			// to force code refactoring when config reload is implemented
			// this would otherwise cause auth bugs with zones using a default key
			Logger.Fatal("changing the default key is not supported")
		}
		Logger.Debugw("key promoted as default for the server", "name", config.Name)
		s.defaultKeyName = config.Name
	}
	return nil
}

func (s *Server) newHandler(config *HandlerConfiguration) error {
	Logger.Debugw("adding new handler", "name", config.Name)

	adapter, err := adapters.NewAdapter(config.Name, config.Settings, Logger)
	if err != nil {
		return fmt.Errorf("failed to create adapter '%s': %w", config.Name, err)
	}

	s.adapters = append(s.adapters, adapter)
	s.adaptersByName[config.Name] = adapter

	Logger.Debugw("initialized handler adapter", "name", config.Name, "object", fmt.Sprintf("%p", adapter))

	if config.Default {
		if s.defaultAdapter != nil {
			// to force code refactoring when config reload is implemented
			// this would otherwise cause bugs with zones using a default handler
			Logger.Fatal("changing the default handler is not supported")
		}
		s.defaultAdapter = adapter
		Logger.Debugw("handler promoted as default for the server", "name", config.Name, "object", fmt.Sprintf("%p", adapter))
	}
	return nil
}

func (s *Server) newZone(config *ZoneConfiguration) error {
	Logger.Debugw("adding new zone", "name", config.Zone)

	zone, err := dns.NewZone(config.Zone)
	if err != nil {
		Logger.Fatalw("failed to initialize zone", "name", config.Zone, "error", err.Error())
	}

	if config.Unsecure == false {
		// auth enabled, processing keys
		Logger.Debugw("zone has authentication enabled", "name", config.Zone)

		addKeys := make([]string, 0)
		if len(config.Keys) > 0 {
			// add keys from zone config
			addKeys = append(addKeys, config.Keys...)
		} else {
			// or try adding the default key
			if len(s.defaultKeyName) > 0 {
				addKeys = append(addKeys, s.defaultKeyName)
			}
		}

		if len(addKeys) == 0 {
			Logger.Fatalw("zone with authentication enabled but no key", "name", config.Zone)
		}

		// push keys to zone
		for _, key := range addKeys {
			if s.keyring.HasKey(key) {
				zone.AddValidKey(key)
			} else {
				Logger.Fatalw("zone requesting an unknown key", "name", config.Zone, "keyname", key)
			}
		}
	} else {
		Logger.Warnw("zone has authentication disabled", "name", config.Zone)
		zone.DisableAuthentication()
	}

	var adapter common.IAdapter
	if config.Handler != "" {
		var found bool
		adapter, found = s.adaptersByName[config.Handler]
		if !found {
			Logger.Fatalw("zone requesting an unknown handler", "name", config.Zone, "handler", config.Handler)
		}
	} else {
		if s.defaultAdapter != nil {
			adapter = s.defaultAdapter
		} else {
			Logger.Fatalw("zone has no handler set and server has no default handler", "name", config.Zone)
		}
	}
	Logger.Debugw("affecting handler to zone", "name", config.Zone, "object", fmt.Sprintf("%p", adapter))
	zone.SetHandler(adapter)

	s.zones = append(s.zones, zone)
	s.zonesByFqdn[zone.Fqdn()] = zone
	return nil
}
