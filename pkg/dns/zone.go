package dns

import (
	"fmt"

	"github.com/enix/tsigan/pkg/adapters/common"
	miekgdns "github.com/miekg/dns"
)

type Zone struct {
	fqdn      string
	handler   common.IAdapter
	validKeys []string
	unsecure  bool
}

func NewZone(name string) (*Zone, error) {
	fqdn := miekgdns.Fqdn(miekgdns.CanonicalName(name))
	if len(fqdn) == 0 {
		return nil, fmt.Errorf("zone FQDN was empty after canonicalization")
	}

	return &Zone{
		fqdn:     fqdn,
		handler:  nil,
		unsecure: false,
	}, nil
}

func (z *Zone) Fqdn() string {
	return z.fqdn
}

func (z *Zone) Handler() common.IAdapter {
	return z.handler
}

func (z *Zone) SetHandler(adapter common.IAdapter) {
	z.handler = adapter
}

func (z *Zone) AddValidKey(name string) {
	z.validKeys = append(z.validKeys, name)
}

func (z *Zone) KeyIsAuthorized(name string) bool {
	for _, k := range z.validKeys {
		if k == name {
			return true
		}
	}
	return false
}

func (a *Zone) AlgorithmIsPermitted(algorithm string) bool {
	// FIXME not implemented
	return true
}

func (z *Zone) DisableAuthentication() {
	z.unsecure = true
	z.validKeys = nil
}

func (z *Zone) HasAuthenticationDisabled() bool {
	return z.unsecure
}
