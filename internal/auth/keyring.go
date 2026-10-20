// Package auth authenticates DNS requests with TSIG (RFC 8945) and decides
// which updates each key may make.
package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // HMAC-MD5 is a legacy algorithm that keys must opt into
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is a legacy algorithm that keys must opt into
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/config"
)

// hmacMD5 is the TSIG name of HMAC-MD5, which miekg/dns no longer supports.
const hmacMD5 = "hmac-md5.sig-alg.reg.int."

var (
	// ErrUnknownKey reports a request signed with a key that is not
	// configured.
	ErrUnknownKey = errors.New("unknown TSIG key")
	// ErrAlgorithmMismatch reports a request signed with another algorithm
	// than the one of its key.
	ErrAlgorithmMismatch = errors.New("TSIG algorithm mismatch")
	// ErrMACSize reports a MAC longer than the output of its algorithm, or
	// truncated below the larger of 10 octets and half that output: RFC 8945
	// 5.2.2.1 makes the message corrupt.
	ErrMACSize = errors.New("TSIG MAC size out of bounds")
	// ErrTruncatedMAC reports a MAC that RFC 8945 allows to truncate, and
	// that verifies, but shorter than the full output of its algorithm,
	// which tsigoat requires.
	ErrTruncatedMAC = errors.New("truncated TSIG MAC")
)

// minMACSize is the shortest truncated MAC that RFC 8945 5.2.2.1 allows,
// whatever the algorithm.
const minMACSize = 10

// Keyring holds the TSIG keys. It implements dns.TsigProvider: every key
// signs and verifies with its own algorithm only.
type Keyring struct {
	keys map[string]*key
}

type key struct {
	// algorithm is the canonical TSIG name of the algorithm.
	algorithm string
	newHash   func() hash.Hash
	secret    []byte
}

var _ dns.TsigProvider = (*Keyring)(nil)

// NewKeyring returns a keyring holding the keys.
func NewKeyring(keys []config.Key) (*Keyring, error) {
	ring := &Keyring{keys: make(map[string]*key, len(keys))}
	for _, k := range keys {
		name := dns.CanonicalName(k.Name)
		algorithm, newHash, err := tsigAlgorithm(k.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", name, err)
		}
		if len(k.Secret) == 0 {
			return nil, fmt.Errorf("key %s: empty secret", name)
		}
		if _, duplicate := ring.keys[name]; duplicate {
			return nil, fmt.Errorf("duplicate key %s", name)
		}
		ring.keys[name] = &key{algorithm: algorithm, newHash: newHash, secret: bytes.Clone(k.Secret)}
	}
	return ring, nil
}

// tsigAlgorithm returns the TSIG name and the hash function of an algorithm.
func tsigAlgorithm(algorithm config.Algorithm) (name string, newHash func() hash.Hash, err error) {
	switch algorithm {
	case config.HMACSHA256:
		return dns.HmacSHA256, sha256.New, nil
	case config.HMACSHA384:
		return dns.HmacSHA384, sha512.New384, nil
	case config.HMACSHA512:
		return dns.HmacSHA512, sha512.New, nil
	case config.HMACSHA224:
		return dns.HmacSHA224, sha256.New224, nil
	case config.HMACSHA1:
		return dns.HmacSHA1, sha1.New, nil
	case config.HMACMD5:
		return hmacMD5, md5.New, nil
	default:
		return "", nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

// Algorithm returns the TSIG name of the algorithm of a key.
func (r *Keyring) Algorithm(name string) (string, bool) {
	k, ok := r.keys[dns.CanonicalName(name)]
	if !ok {
		return "", false
	}
	return k.algorithm, true
}

// Generate implements dns.TsigProvider.
func (r *Keyring) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	k, err := r.key(t)
	if err != nil {
		return nil, err
	}
	return k.sign(msg), nil
}

// Verify implements dns.TsigProvider: it checks the key, then the MAC, which
// RFC 8945 5.2.2.1 allows to truncate down to the larger of 10 octets and
// half the output of the algorithm. miekg/dns checks the time afterwards, and
// CheckTruncation the truncation, last, as RFC 8945 5.2 orders.
func (r *Keyring) Verify(msg []byte, t *dns.TSIG) error {
	k, err := r.key(t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return dns.ErrSig
	}
	full := k.sign(msg)
	if len(mac) > len(full) || len(mac) < max(minMACSize, len(full)/2) {
		return fmt.Errorf("%w: %d octets, for an output of %d", ErrMACSize, len(mac), len(full))
	}
	if !hmac.Equal(full[:len(mac)], mac) {
		return dns.ErrSig
	}
	return nil
}

// CheckTruncation returns ErrTruncatedMAC for a request whose MAC, which
// verified, is shorter than the full output of its algorithm: tsigoat
// requires full MACs, which RFC 8945 7 lets a local policy do.
func (r *Keyring) CheckTruncation(t *dns.TSIG) error {
	k, err := r.key(t)
	if err != nil {
		return err
	}
	if size := len(t.MAC) / 2; size < k.newHash().Size() {
		return fmt.Errorf("%w: %d octets, for an output of %d", ErrTruncatedMAC, size, k.newHash().Size())
	}
	return nil
}

// MACSize returns the size of the MACs that Generate makes for a TSIG record,
// the full output of the algorithm of its key; 0 for a record that names an
// unknown key or another algorithm.
func (r *Keyring) MACSize(t *dns.TSIG) int {
	k, err := r.key(t)
	if err != nil {
		return 0
	}
	return k.newHash().Size()
}

// key returns the key of a TSIG record, provided the record names the
// algorithm of the key.
func (r *Keyring) key(t *dns.TSIG) (*key, error) {
	name := dns.CanonicalName(t.Hdr.Name)
	k, ok := r.keys[name]
	if !ok {
		return nil, fmt.Errorf("%w %s", ErrUnknownKey, name)
	}
	if algorithm := dns.CanonicalName(t.Algorithm); algorithm != k.algorithm {
		return nil, fmt.Errorf("%w: key %s uses %s, not %s", ErrAlgorithmMismatch, name, k.algorithm, algorithm)
	}
	return k, nil
}

func (k *key) sign(msg []byte) []byte {
	mac := hmac.New(k.newHash, k.secret)
	mac.Write(msg)
	return mac.Sum(nil)
}

// TSIGError returns the TSIG error that answers a verification error, as
// RFC 8945 5.2 defines them: BADKEY for an unknown key or algorithm, BADTIME
// for a signature outside its validity period, BADTRUNC for a MAC truncated
// beyond the local policy, BADSIG otherwise. A MAC size out of bounds, which
// gets FORMERR without a TSIG error, is the business of the caller.
func TSIGError(err error) uint16 {
	switch {
	case errors.Is(err, ErrUnknownKey), errors.Is(err, ErrAlgorithmMismatch):
		return dns.RcodeBadKey
	case errors.Is(err, dns.ErrTime):
		return dns.RcodeBadTime
	case errors.Is(err, ErrTruncatedMAC):
		return dns.RcodeBadTrunc
	default:
		return dns.RcodeBadSig
	}
}
