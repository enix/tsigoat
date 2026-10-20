package scenario

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/miekg/dns"
)

// DefaultKey signs the requests that do not name a key.
const DefaultKey = "e2e"

// Key is a TSIG key of the test keyring.
type Key struct {
	// ID identifies the key in scenario files.
	ID string
	// Name is the key name on the wire.
	Name string
	// ConfigName is the key name written in tsigoat's configuration. It
	// differs from Name for the key that checks name canonicalisation.
	ConfigName string
	// Algorithm is the TSIG algorithm of the key.
	Algorithm string
	// Configured is false for keys that tsigoat does not know.
	Configured bool
}

// Secret returns the base64 secret of the key. It is derived from the key
// identifier, so that no secret is written in the repository.
func (k Key) Secret() string {
	sum := sha256.Sum256([]byte("tsigoat test key " + k.ID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Keyring returns the test keys.
func Keyring() []Key {
	return []Key{
		{ID: "e2e", Name: "e2e.", ConfigName: "e2e.", Algorithm: dns.HmacSHA256, Configured: true},
		{ID: "e2e-sha1", Name: "e2e-sha1.", ConfigName: "e2e-sha1.", Algorithm: dns.HmacSHA1, Configured: true},
		{ID: "e2e-sha512", Name: "e2e-sha512.", ConfigName: "e2e-sha512.", Algorithm: dns.HmacSHA512, Configured: true},
		{ID: "e2e-md5", Name: "e2e-md5.", ConfigName: "e2e-md5.", Algorithm: dns.HmacMD5, Configured: true},
		{ID: "e2e-nodot", Name: "e2e-nodot.", ConfigName: "e2e-nodot", Algorithm: dns.HmacSHA256, Configured: true},
		{ID: "unknown", Name: "unknown.", ConfigName: "unknown.", Algorithm: dns.HmacSHA256, Configured: false},
	}
}

// KeyByID returns the test key with the given identifier.
func KeyByID(id string) (Key, bool) {
	for _, key := range Keyring() {
		if key.ID == id {
			return key, true
		}
	}
	return Key{}, false
}
