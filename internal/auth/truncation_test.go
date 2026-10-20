package auth_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/config"
)

// withMAC returns a signed message whose MAC is replaced with mac, encoded
// again without signing it again.
func withMAC(t *testing.T, data []byte, mac func(full []byte) []byte) []byte {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(data); err != nil {
		t.Fatal(err)
	}
	tsig := m.IsTsig()
	full, err := hex.DecodeString(tsig.MAC)
	if err != nil {
		t.Fatal(err)
	}
	replaced := mac(full)
	tsig.MAC, tsig.MACSize = hex.EncodeToString(replaced), uint16(len(replaced))
	out, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// truncationCase is a MAC to verify, and the errors expected of the
// verification and of the truncation policy.
type truncationCase struct {
	name   string
	mac    func(full []byte) []byte
	verify error
	policy error
}

// truncationCases returns the cases of RFC 8945 5.2.2.1 for an algorithm whose
// output and shortest allowed MAC have the given sizes.
func truncationCases(output, shortest int) []truncationCase {
	truncate := func(size int) func([]byte) []byte {
		return func(full []byte) []byte { return full[:size] }
	}
	return []truncationCase{
		{name: "full", mac: truncate(output)},
		{name: "shortest allowed", mac: truncate(shortest), policy: auth.ErrTruncatedMAC},
		{name: "one octet shorter", mac: truncate(output - 1), policy: auth.ErrTruncatedMAC},
		{name: "below the shortest", mac: truncate(shortest - 1), verify: auth.ErrMACSize},
		{name: "empty", mac: truncate(0), verify: auth.ErrMACSize},
		{name: "longer than the output", mac: func(full []byte) []byte { return append(full, 0) }, verify: auth.ErrMACSize},
		{name: "truncated, wrong", mac: func(full []byte) []byte {
			wrong := bytes.Clone(full[:shortest])
			wrong[0] ^= 1
			return wrong
		}, verify: dns.ErrSig},
	}
}

// TestTruncatedMACs checks the rules of RFC 8945 5.2.2.1 for every algorithm:
// a MAC truncated to the larger of 10 octets and half the output verifies,
// and CheckTruncation turns it down; shorter or longer, the size is out of
// bounds; a truncated MAC that does not match is a bad signature.
func TestTruncatedMACs(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		algorithm config.Algorithm
		tsigName  string
		// output and shortest are the full and the shortest allowed sizes.
		output, shortest int
	}{
		{config.HMACSHA256, dns.HmacSHA256, 32, 16},
		{config.HMACSHA224, dns.HmacSHA224, 28, 14},
		{config.HMACSHA384, dns.HmacSHA384, 48, 24},
		{config.HMACSHA512, dns.HmacSHA512, 64, 32},
		{config.HMACSHA1, dns.HmacSHA1, 20, 10},
		{config.HMACMD5, "hmac-md5.sig-alg.reg.int.", 16, 10},
	} {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			t.Parallel()
			ring := newKeyring(t, config.Key{Name: "key.example.", Algorithm: tt.algorithm, Secret: secret})
			data := signed(t, ring, "key.example.", tt.tsigName, time.Now())
			for _, c := range truncationCases(tt.output, tt.shortest) {
				message := withMAC(t, bytes.Clone(data), c.mac)
				// Verifying rewrites the message: verify a copy.
				err := dns.TsigVerifyWithProvider(bytes.Clone(message), ring, "", false)
				if (c.verify == nil) != (err == nil) || (c.verify != nil && !errors.Is(err, c.verify)) {
					t.Errorf("%s: verifying = %v, want %v", c.name, err, c.verify)
					continue
				}
				if err != nil {
					continue
				}
				m := new(dns.Msg)
				if unpackErr := m.Unpack(message); unpackErr != nil {
					t.Fatal(unpackErr)
				}
				policy := ring.CheckTruncation(m.IsTsig())
				if (c.policy == nil) != (policy == nil) || (c.policy != nil && !errors.Is(policy, c.policy)) {
					t.Errorf("%s: CheckTruncation() = %v, want %v", c.name, policy, c.policy)
				}
				if policy != nil && auth.TSIGError(policy) != dns.RcodeBadTrunc {
					t.Errorf("%s: TSIGError() = %d, want BADTRUNC", c.name, auth.TSIGError(policy))
				}
			}
		})
	}
}
