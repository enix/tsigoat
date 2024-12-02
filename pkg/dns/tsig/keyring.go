package tsig

import (
	"encoding/base64"
	"fmt"
)

type TsigKey []byte

type TsigKeyring map[string]TsigKey

func NewTsigKeyring() TsigKeyring {
	return make(TsigKeyring, 0)
}

func (k TsigKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(k)
}

func (keyring TsigKeyring) AddEncodedKey(name string, key string) error {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("key decoding: %w", err)
	}
	return keyring.AddKey(name, decoded)
}

func (keyring TsigKeyring) AddKey(name string, key []byte) error {
	if _, found := keyring[name]; found {
		return fmt.Errorf("key '%s' exists in keyring", name)
	}

	keyring[name] = key
	return nil
}

func (keyring TsigKeyring) HasKey(name string) bool {
	_, found := keyring[name]
	return found
}

func (keyring TsigKeyring) Key(name string) TsigKey {
	key, found := keyring[name]
	if !found {
		return nil
	}
	return key
}
