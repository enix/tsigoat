package update

import "testing"

func TestSerialGreater(t *testing.T) {
	t.Parallel()

	const half = 1 << 31
	for _, tt := range []struct {
		a, b uint32
		want bool
	}{
		{a: 11, b: 10, want: true},
		{a: 10, b: 11, want: false},
		{a: 10, b: 10, want: false},
		// Wraparound: 1 follows 0xFFFFFFFF.
		{a: 1, b: 0xFFFFFFFF, want: true},
		{a: 0xFFFFFFFF, b: 1, want: false},
		// The largest increment allowed is half the space minus one.
		{a: half - 1, b: 0, want: true},
		{a: 0, b: half + 1, want: true},
		// At exactly half, RFC 1982 leaves the comparison undefined: neither
		// is greater.
		{a: half, b: 0, want: false},
		{a: 0, b: half, want: false},
	} {
		if got := serialGreater(tt.a, tt.b); got != tt.want {
			t.Errorf("serialGreater(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
