package auth_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/config"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func newKeyring(t *testing.T, keys ...config.Key) *auth.Keyring {
	t.Helper()
	ring, err := auth.NewKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func update(t *testing.T, keyName, algorithm string, signedAt time.Time) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate("example.test.")
	rr, err := dns.NewRR(`www.example.test. 60 IN TXT "hello"`)
	if err != nil {
		t.Fatal(err)
	}
	m.Insert([]dns.RR{rr})
	m.SetTsig(keyName, algorithm, 300, signedAt.Unix())
	return m
}

// signed returns a packed update signed through the provider.
func signed(t *testing.T, provider dns.TsigProvider, keyName, algorithm string, signedAt time.Time) []byte {
	t.Helper()
	data, _, err := dns.TsigGenerateWithProvider(update(t, keyName, algorithm, signedAt), provider, "", false)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestKeyringAlgorithms(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		algorithm config.Algorithm
		tsigName  string
		// builtin tells whether miekg/dns implements the algorithm, to check
		// interoperability.
		builtin bool
	}{
		{config.HMACSHA256, dns.HmacSHA256, true},
		{config.HMACSHA384, dns.HmacSHA384, true},
		{config.HMACSHA512, dns.HmacSHA512, true},
		{config.HMACSHA224, dns.HmacSHA224, true},
		{config.HMACSHA1, dns.HmacSHA1, true},
		{config.HMACMD5, "hmac-md5.sig-alg.reg.int.", false},
	} {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			t.Parallel()
			ring := newKeyring(t, config.Key{Name: "key.example.", Algorithm: tt.algorithm, Secret: secret})

			if got, ok := ring.Algorithm("KEY.example"); !ok || got != tt.tsigName {
				t.Errorf("Algorithm() = %q, %v, want %q", got, ok, tt.tsigName)
			}

			// Verifying rewrites the message: verify copies.
			data := signed(t, ring, "Key.Example.", tt.tsigName, time.Now())
			if err := dns.TsigVerifyWithProvider(bytes.Clone(data), ring, "", false); err != nil {
				t.Errorf("verifying its own signature: %v", err)
			}
			if !tt.builtin {
				return
			}
			encoded := base64.StdEncoding.EncodeToString(secret)
			if err := dns.TsigVerify(data, encoded, "", false); err != nil {
				t.Errorf("miekg/dns rejects the signature: %v", err)
			}
			data, _, err := dns.TsigGenerate(update(t, "key.example.", tt.tsigName, time.Now()), encoded, "", false)
			if err != nil {
				t.Fatal(err)
			}
			if err := dns.TsigVerifyWithProvider(data, ring, "", false); err != nil {
				t.Errorf("rejecting a signature of miekg/dns: %v", err)
			}
		})
	}
}

func TestKeyringErrors(t *testing.T) {
	t.Parallel()

	ring := newKeyring(t,
		config.Key{Name: "sha256.example.", Algorithm: config.HMACSHA256, Secret: secret},
		config.Key{Name: "md5.example.", Algorithm: config.HMACMD5, Secret: secret},
	)
	tests := []struct {
		name     string
		data     []byte
		target   error
		tsigCode uint16
	}{
		{
			name:     "unknown key",
			data:     signed(t, newKeyring(t, config.Key{Name: "unknown.example.", Algorithm: config.HMACSHA256, Secret: secret}), "unknown.example.", dns.HmacSHA256, time.Now()),
			target:   auth.ErrUnknownKey,
			tsigCode: dns.RcodeBadKey,
		},
		{
			name:     "algorithm of another key",
			data:     signed(t, newKeyring(t, config.Key{Name: "sha256.example.", Algorithm: config.HMACSHA512, Secret: secret}), "sha256.example.", dns.HmacSHA512, time.Now()),
			target:   auth.ErrAlgorithmMismatch,
			tsigCode: dns.RcodeBadKey,
		},
		{
			name:     "legacy algorithm refused when the key does not declare it",
			data:     signed(t, newKeyring(t, config.Key{Name: "sha256.example.", Algorithm: config.HMACMD5, Secret: secret}), "sha256.example.", "hmac-md5.sig-alg.reg.int.", time.Now()),
			target:   auth.ErrAlgorithmMismatch,
			tsigCode: dns.RcodeBadKey,
		},
		{
			name:     "wrong secret",
			data:     signed(t, newKeyring(t, config.Key{Name: "md5.example.", Algorithm: config.HMACMD5, Secret: []byte("another secret")}), "md5.example.", "hmac-md5.sig-alg.reg.int.", time.Now()),
			target:   dns.ErrSig,
			tsigCode: dns.RcodeBadSig,
		},
		{
			name:     "outside the validity period",
			data:     signed(t, ring, "sha256.example.", dns.HmacSHA256, time.Now().Add(-time.Hour)),
			target:   dns.ErrTime,
			tsigCode: dns.RcodeBadTime,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := dns.TsigVerifyWithProvider(tt.data, ring, "", false)
			if !errors.Is(err, tt.target) {
				t.Fatalf("error %v, want %v", err, tt.target)
			}
			if code := auth.TSIGError(err); code != tt.tsigCode {
				t.Errorf("TSIGError() = %s, want %s", dns.RcodeToString[int(code)], dns.RcodeToString[int(tt.tsigCode)])
			}
		})
	}
}

func TestNewKeyringErrors(t *testing.T) {
	t.Parallel()

	for name, keys := range map[string][]config.Key{
		"unknown algorithm": {{Name: "k.", Algorithm: "hmac-sha3", Secret: secret}},
		"empty secret":      {{Name: "k.", Algorithm: config.HMACSHA256}},
		"duplicate":         {{Name: "k.", Algorithm: config.HMACSHA256, Secret: secret}, {Name: "K", Algorithm: config.HMACSHA1, Secret: secret}},
	} {
		if _, err := auth.NewKeyring(keys); err == nil {
			t.Errorf("%s: NewKeyring() succeeded", name)
		}
	}
}
