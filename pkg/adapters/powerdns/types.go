package powerdns

import (
	"fmt"

	"github.com/joeig/go-powerdns/v3"
	miekgdns "github.com/miekg/dns"
)

type rrTypePair struct {
	dnsType    uint16
	nativeType powerdns.RRType
}

var (
	rrTypeToNative     map[uint16]powerdns.RRType
	nativeTypeToRRType map[powerdns.RRType]uint16
	typePairs          = []rrTypePair{
		{miekgdns.TypeA, powerdns.RRTypeA},
		{miekgdns.TypeAAAA, powerdns.RRTypeAAAA},
		{miekgdns.TypeCAA, powerdns.RRTypeCAA},
		{miekgdns.TypeCDNSKEY, powerdns.RRTypeCDNSKEY},
		{miekgdns.TypeCDS, powerdns.RRTypeCDS},
		{miekgdns.TypeCERT, powerdns.RRTypeCERT},
		{miekgdns.TypeCNAME, powerdns.RRTypeCNAME},
		{miekgdns.TypeDHCID, powerdns.RRTypeDHCID},
		{miekgdns.TypeDLV, powerdns.RRTypeDLV},
		{miekgdns.TypeDNAME, powerdns.RRTypeDNAME},
		{miekgdns.TypeDNSKEY, powerdns.RRTypeDNSKEY},
		{miekgdns.TypeDS, powerdns.RRTypeDS},
		{miekgdns.TypeEUI48, powerdns.RRTypeEUI48},
		{miekgdns.TypeEUI64, powerdns.RRTypeEUI64},
		{miekgdns.TypeHINFO, powerdns.RRTypeHINFO},
		{miekgdns.TypeIPSECKEY, powerdns.RRTypeIPSECKEY},
		{miekgdns.TypeKEY, powerdns.RRTypeKEY},
		{miekgdns.TypeKX, powerdns.RRTypeKX},
		{miekgdns.TypeLOC, powerdns.RRTypeLOC},
		{miekgdns.TypeMX, powerdns.RRTypeMX},
		{miekgdns.TypeNAPTR, powerdns.RRTypeNAPTR},
		{miekgdns.TypeNS, powerdns.RRTypeNS},
		{miekgdns.TypeNSEC3, powerdns.RRTypeNSEC3},
		{miekgdns.TypeNSEC3PARAM, powerdns.RRTypeNSEC3PARAM},
		{miekgdns.TypeNSEC, powerdns.RRTypeNSEC},
		{miekgdns.TypeOPENPGPKEY, powerdns.RRTypeOPENPGPKEY},
		{miekgdns.TypePTR, powerdns.RRTypePTR},
		{miekgdns.TypeRP, powerdns.RRTypeRP},
		{miekgdns.TypeRRSIG, powerdns.RRTypeRRSIG},
		{miekgdns.TypeSIG, powerdns.RRTypeSIG},
		{miekgdns.TypeSMIMEA, powerdns.RRTypeSMIMEA},
		{miekgdns.TypeSOA, powerdns.RRTypeSOA},
		{miekgdns.TypeSPF, powerdns.RRTypeSPF},
		{miekgdns.TypeSRV, powerdns.RRTypeSRV},
		{miekgdns.TypeSSHFP, powerdns.RRTypeSSHFP},
		{miekgdns.TypeTKEY, powerdns.RRTypeTKEY},
		{miekgdns.TypeTLSA, powerdns.RRTypeTLSA},
		{miekgdns.TypeTSIG, powerdns.RRTypeTSIG},
		{miekgdns.TypeTXT, powerdns.RRTypeTXT},
		{miekgdns.TypeURI, powerdns.RRTypeURI},
	}
)

func init() {
	rrTypeToNative = make(map[uint16]powerdns.RRType)
	nativeTypeToRRType = make(map[powerdns.RRType]uint16)

	for _, pair := range typePairs {
		rrTypeToNative[pair.dnsType] = pair.nativeType
		nativeTypeToRRType[pair.nativeType] = pair.dnsType
	}
}

func ToNativeType(rrType uint16) (nType powerdns.RRType, err error) {
	nType, found := rrTypeToNative[rrType]
	if !found {
		err = fmt.Errorf("resource record type not supported by the PowerDNS adapter: %s", miekgdns.TypeToString[rrType])
	}
	return
}

func NativeTypeOf(rr miekgdns.RR) (powerdns.RRType, error) {
	return ToNativeType(rr.Header().Rrtype)
}

func NativeNameOf(rr miekgdns.RR) string {
	return rr.Header().Name
}

func ToDnsType(nType powerdns.RRType) (rrType uint16, err error) {
	rrType, found := nativeTypeToRRType[nType]
	if !found {
		err = fmt.Errorf("resource record type not supported by the PowerDNS adapter: %s", nType)
	}
	return
}

func DnsTypeOf(rr powerdns.RRset) (uint16, error) {
	return ToDnsType(*rr.Type)
}

func DnsNameOf(rr powerdns.RRset) string {
	return *rr.Name
}

// FIXME missing checks
func IsRRset(set powerdns.RRset) bool {
	if len(set.Records) == 0 {
		return false
	}
	return true
}
