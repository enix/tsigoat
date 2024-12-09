package update

import (
	"fmt"

	"github.com/enix/tsigoat/pkg/dns"
)

type Authorization struct {
	Zone       *dns.Zone
	authKey    string
	authAlg    string
	authPassed bool
}

func (a *Authorization) VerifiedIssuer(key string, algorithm string) {
	if a.authPassed {
		panic("cannot mark authentication status again")
	}
	a.authKey = key
	a.authAlg = algorithm
	a.authPassed = true
}

func (a *Authorization) Evaluate() error {
	if a.authPassed == true {
		// Check the key can perform updates on this zone
		if a.Zone.KeyIsAuthorized(a.authKey) == false {
			return fmt.Errorf("unauthorized key")
		}

		// Check the HMAC algorithm is allowed
		if a.Zone.AlgorithmIsPermitted(a.authAlg) == false {
			return fmt.Errorf("forbidden HMAC algorithm")
		}
	} else {
		// Check if we should block unauthenticated updates
		if a.Zone.HasAuthenticationDisabled() == false {
			// An early check should have been made in Server.Handle() too
			return fmt.Errorf("zone require authentication")
		}
	}

	// FIXME implement non crypto authorization schemes here

	return nil
}
