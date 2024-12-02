package tsig

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	miekgdns "github.com/miekg/dns"
)

type HmacAlgorithm int

const (
	HmacUnsupported HmacAlgorithm = iota
	HmacSHA1
	HmacSHA224
	HmacSHA256
	HmacSHA384
	HmacSHA512
)

func NewHmac(algorithm string) (HmacAlgorithm, error) {
	switch algorithm {
	case miekgdns.HmacSHA1:
		return HmacSHA1, nil
	case miekgdns.HmacSHA224:
		return HmacSHA224, nil
	case miekgdns.HmacSHA256:
		return HmacSHA256, nil
	case miekgdns.HmacSHA384:
		return HmacSHA384, nil
	case miekgdns.HmacSHA512:
		return HmacSHA512, nil
	default:
		return HmacUnsupported, fmt.Errorf("unsupported HMAC algorithm '%s'", algorithm)
	}
}

func (alg HmacAlgorithm) Sum(msg []byte, key []byte) ([]byte, error) {
	var h hash.Hash

	switch alg {
	case HmacSHA1:
		h = hmac.New(sha1.New, key)
	case HmacSHA224:
		h = hmac.New(sha256.New224, key)
	case HmacSHA256:
		h = hmac.New(sha256.New, key)
	case HmacSHA384:
		h = hmac.New(sha512.New384, key)
	case HmacSHA512:
		h = hmac.New(sha512.New, key)
	default:
		panic("unknown HMAC algorithm")
	}

	h.Write(msg)
	return h.Sum(nil), nil
}
