package common

import (
	"fmt"
	"strings"

	miekgdns "github.com/miekg/dns"
)

// FIXME refactor for any coumpounded rdata type
func TxtToString(rr *miekgdns.TXT) string {
	var s strings.Builder
	last := len(rr.Txt) - 1
	for idx, rrs := range rr.Txt {
		s.Grow(len(rrs) + 3)
		// add a double quote
		s.WriteByte(34)
		// quotes in rrs are escaped already
		s.WriteString(rrs)
		// add a double quote
		s.WriteByte(34)
		// when not the last string
		if idx < last {
			// add a space
			s.WriteByte(32)
		}
	}
	return s.String()
}

func StringToTxtStrings(input string) ([]string, error) {
	var result []string
	var currentString strings.Builder
	var startIdx int
	escaped := false
	inQuotes := false

loop:
	for startIdx = 0; startIdx < len(input); startIdx++ {
		switch input[startIdx] {
		case '"':
			break loop
		case ' ':
			continue
		default:
			return nil, fmt.Errorf("no starting quote")
		}
	}

	currentString.Grow(len(input))

	for idx := startIdx; idx < len(input); idx++ {
		char := input[idx]

		switch char {
		case '\\':
			if !escaped {
				escaped = true
			}
		case '"':
			if !escaped {
				if inQuotes {
					result = append(result, currentString.String())
					currentString.Reset()
					currentString.Grow(len(input) - idx)
					inQuotes = false
				} else {
					inQuotes = true
				}
				continue
			}
		case ' ':
			if !inQuotes {
				continue
			}
		}

		currentString.WriteByte(char)
		escaped = false
	}

	if inQuotes {
		return nil, fmt.Errorf("unmatched quote")
	}
	return result, nil
}
