package update

import (
	"fmt"

	miekgdns "github.com/miekg/dns"
)

// TODO: unoptimized and smelly
func RemoveFromSet(rr miekgdns.RR, set []miekgdns.RR) (newSet []miekgdns.RR, removed bool, err error) {
	for _, value := range set {
		var sameRdata bool
		sameRdata, err = EqualRdata(rr, value)
		if err != nil {
			return
		}

		if !(rr.Header().Name == value.Header().Name && rr.Header().Rrtype == value.Header().Rrtype && sameRdata) {

			newSet = append(newSet, value)
		} else {
			removed = true
		}
	}
	return
}

// TODO: unoptimized and smelly code
func EqualRdata(rr1 miekgdns.RR, rr2 miekgdns.RR) (bool, error) {
	var (
		rr1Ukn miekgdns.RFC3597
		rr2Ukn miekgdns.RFC3597
	)

	err1 := rr1Ukn.ToRFC3597(rr1)
	err2 := rr2Ukn.ToRFC3597(rr2)
	if err1 != nil || err2 != nil {
		return false, fmt.Errorf("error packing RRs to RFC3597")
	}

	// fmt.Printf("\nrd1 > %s\nrd2 > %s\n=== > %t\n", rr1Ukn.Rdata, rr2Ukn.Rdata, rr1Ukn.Rdata == rr2Ukn.Rdata)
	return rr1Ukn.Rdata == rr2Ukn.Rdata, nil
}
