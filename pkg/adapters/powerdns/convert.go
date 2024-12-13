package powerdns

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/enix/tsigoat/pkg/adapters/common"
	"github.com/joeig/go-powerdns/v3"
	miekgdns "github.com/miekg/dns"
)

func NativeContentOf(rr miekgdns.RR) (content string, retErr error) {
	switch value := rr.(type) {
	case *miekgdns.A:
		content = string(value.A)
	case *miekgdns.AAAA:
		content = string(value.AAAA)
	case *miekgdns.CNAME:
		content = value.Target
	case *miekgdns.NS:
		content = value.Ns
	case *miekgdns.PTR:
		content = value.Ptr
	case *miekgdns.SOA:
		// The stored format is:
		//   primary hostmaster serial refresh retry expire minimum
		content = fmt.Sprintf("%s %s %d %d %d %d %d",
			value.Ns, value.Mbox, value.Serial, value.Refresh, value.Retry, value.Expire, value.Minttl)
	case *miekgdns.TXT:
		content = common.TxtToString(value)
	default:
		// FIXME interface errors
		retErr = fmt.Errorf("resource record type not supported by the PowerDNS adapter: %s",
			miekgdns.TypeToString[rr.Header().Rrtype])
	}
	return
}

func NativeRRsetOf(rrSet []miekgdns.RR) (name string, nType powerdns.RRType, ttl uint32, content []string, retErr error) {
	var err error

	// It does check for len(rrSet)
	if miekgdns.IsRRset(rrSet) == false {
		retErr = fmt.Errorf("NativeRRset: invalid set")
		return
	}

	for idx, rr := range rrSet {
		if rr.Header().Class != miekgdns.ClassINET {
			retErr = fmt.Errorf("NativeRRsetOf: PowerDNS only support the INET class")
			return
		}

		if idx == 0 {
			name = NativeNameOf(rr)
			ttl = rr.Header().Ttl
			nType, err = NativeTypeOf(rr)
			if err != nil {
				retErr = fmt.Errorf("NativeRRsetOf: %w", err)
				return
			}
		}

		newContent, err := NativeContentOf(rr)
		if err != nil {
			retErr = err
			return
		}
		content = append(content, newContent)
	}
	return
}

func toRdataString(input string) (result []string) {
	const maxLength = 255
	for i := 0; i < len(input); i += maxLength {
		end := i + maxLength
		if end > len(input) {
			end = len(input)
		}
		result = append(result, input[i:end])
	}
	return
}

func MakeDnsRR(name string, nType powerdns.RRType, ttl uint32, rr powerdns.Record) (dnsRr miekgdns.RR, retErr error) {
	var (
		err     error
		dnsType uint16
	)

	if dnsType, err = ToDnsType(nType); err != nil {
		retErr = fmt.Errorf("DnsRR: %w", err)
		return
	}

	dnsRr = miekgdns.TypeToRR[dnsType]() // FIXME --^ use ok

	switch value := dnsRr.(type) {
	case *miekgdns.A:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		parsed := net.ParseIP(*rr.Content)
		if parsed != nil {
			// ensure it's true IPv4 notation
			parsed = parsed.To4()
		}
		if parsed != nil {
			value.A = parsed
		} else {
			retErr = fmt.Errorf("error parsing IPv4 address for A record: %s", *rr.Content)
		}
	case *miekgdns.AAAA:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		parsed := net.ParseIP(*rr.Content)
		if parsed != nil {
			// ensure it's true IPv6 notation
			parsed = parsed.To16()
		}
		if parsed != nil {
			value.AAAA = parsed
		} else {
			retErr = fmt.Errorf("error parsing IPv6 address for AAAA record: %s", *rr.Content)
		}
	case *miekgdns.CNAME:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		value.Target = *rr.Content
	case *miekgdns.NS:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		value.Ns = *rr.Content
	case *miekgdns.PTR:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		value.Ptr = *rr.Content
	case *miekgdns.SOA:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		// The stored format is:
		//   primary hostmaster serial refresh retry expire minimum
		// Besides the primary and the hostmaster, all fields are numerical.
		fields := strings.Split(*rr.Content, " ")
		if len(fields) == 7 {
			value.Ns = fields[0]
			value.Mbox = fields[1]
			for idx, ptr := range []*uint32{&value.Serial, &value.Refresh, &value.Retry, &value.Expire, &value.Minttl} {
				val, err := strconv.ParseUint(fields[2+idx], 10, 32)
				if err != nil {
					retErr = fmt.Errorf("fail to convert SOA field to integer: %w", err)
					return
				}
				*ptr = uint32(val)
			}
		} else {
			retErr = fmt.Errorf("invalid SOA format: %s", *rr.Content)
		}
	case *miekgdns.TXT:
		value.Hdr.Class = miekgdns.ClassINET
		value.Hdr.Name = name
		value.Hdr.Ttl = ttl
		value.Hdr.Rrtype = dnsType
		value.Txt, retErr = common.StringToTxtStrings(*rr.Content)
		if retErr != nil {
			return
		}
	default:
		// FIXME interface errors
		retErr = fmt.Errorf("resource record type not supported by the PowerDNS adapter: %s", nType)
	}
	return
}

func DnsRRsetOf(zone string, set powerdns.RRset) (rrSet []miekgdns.RR, retErr error) {
	if IsRRset(set) == false {
		retErr = fmt.Errorf("NativeRRset: invalid set")
		return
	}

	zone = miekgdns.Fqdn(zone)
	for _, nativeRr := range set.Records {
		rr, err := MakeDnsRR(*set.Name, *set.Type, *set.TTL, nativeRr)
		if err != nil {
			retErr = fmt.Errorf("DnsRRsetOf: %w", err)
			return
		}
		rrSet = append(rrSet, rr)
	}
	return
}
