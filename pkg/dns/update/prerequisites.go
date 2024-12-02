package update

import (
	"github.com/enix/tsigan/pkg/adapters/common"
	miekgdns "github.com/miekg/dns"
)

const (
	prereqNameExists = iota
	prereqNameAbsent
	prereqNameWithTypeExists
	prereqNameWithTypeAbsent
	prereqRRsetsEquality
)

type Prerequisites struct {
	tests []prereqTest
}

type prereqTest struct {
	kind      uint
	records   []miekgdns.RR
	failRcode int
}

func (p *Prerequisites) Count() int {
	return len(p.tests)
}

func (p *Prerequisites) AddNameMustExist(rr miekgdns.RR, failWithRcode int) {
	p.tests = append(p.tests, prereqTest{
		kind:      prereqNameExists,
		records:   []miekgdns.RR{rr},
		failRcode: failWithRcode,
	})
}

func (p *Prerequisites) AddNameMustBeAbsent(rr miekgdns.RR, failWithRcode int) {
	p.tests = append(p.tests, prereqTest{
		kind:      prereqNameAbsent,
		records:   []miekgdns.RR{rr},
		failRcode: failWithRcode,
	})
}

func (p *Prerequisites) AddNameWithTypeMustExist(rr miekgdns.RR, failWithRcode int) {
	p.tests = append(p.tests, prereqTest{
		kind:      prereqNameWithTypeExists,
		records:   []miekgdns.RR{rr},
		failRcode: failWithRcode,
	})
}

func (p *Prerequisites) AddNameWithTypeMustBeAbsent(rr miekgdns.RR, failWithRcode int) {
	p.tests = append(p.tests, prereqTest{
		kind:      prereqNameWithTypeAbsent,
		records:   []miekgdns.RR{rr},
		failRcode: failWithRcode,
	})
}

func (p *Prerequisites) AddSetEquality(rrset []miekgdns.RR, failWithRcode int) {
	p.tests = append(p.tests, prereqTest{
		kind:      prereqRRsetsEquality,
		records:   rrset,
		failRcode: failWithRcode,
	})
}

func (p *Prerequisites) Evaluate(transaction common.IAdapterTransaction) error {
	// FIXME not implemented
	return nil
}
