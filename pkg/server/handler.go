package server

import (
	"slices"

	"github.com/enix/tsigoat/pkg/dns"
	"github.com/enix/tsigoat/pkg/dns/update"
	miekgdns "github.com/miekg/dns"
	"go.uber.org/zap/zapcore"
)

// Caution: This function utilizes goto statements. Be mindful when modifying the code flow.
func (s *Server) Handle(writer miekgdns.ResponseWriter, received *miekgdns.Msg) {
	var (
		err           error
		ok            bool
		zoneName      string
		zoneClass     uint16
		zone          *dns.Zone
		rrset         []miekgdns.RR
		prerequisites update.Prerequisites
		authorization update.Authorization
		task          update.Task
	)

	// Catch panic calls during query processing.
	// This error handler is not intended for regular use and should never be triggered under normal circumstances.
	// For this reason, we do not respond with SERVFAIL, partly to avoid potential abuse for DNS attacks.
	defer func() {
		if r := recover(); r != nil {
			text := "caught panic during query handling"
			err, ok = r.(error)
			if ok {
				Logger.Errorw(text, "error", err.Error())
			} else {
				Logger.Error(text)
			}
		}
	}()

	// if Logger.Level() == zapcore.DebugLevel {
	// 	Logger.Debugf("received message:\n%s", received.String())
	// }

	// Extract the signature status now, as it is used for logging and early validation checks
	tsig := received.IsTsig()
	tsigStatus := writer.TsigStatus()

	// The message we'll send back
	response := new(miekgdns.Msg)

	// Process only update requests
	// Note: msgAcceptAction is considered a library optimization, the actual check is performed here
	if received.Opcode != miekgdns.OpcodeUpdate {
		Logger.Debugw("query with unsupported opcode", "opcode", miekgdns.OpcodeToString[received.Opcode])
		response.SetRcodeFormatError(received)
		response.Rcode = miekgdns.RcodeNotImplemented
		goto reply
	}

	zoneName = miekgdns.Fqdn(miekgdns.CanonicalName(received.Question[0].Name))
	zoneClass = received.Question[0].Qclass

	// Early debug logging of extensive query parameters
	if Logger.Level() == zapcore.DebugLevel {
		var (
			mac       bool
			valid     bool
			keyName   string
			algorithm string
			macSize   uint16
			fudge     uint16
		)
		if tsig != nil {
			mac = true
			keyName = tsig.Hdr.Name
			algorithm = tsig.Algorithm
			macSize = tsig.MACSize
			fudge = tsig.Fudge
			if tsigStatus == nil {
				valid = true
			}
		}

		Logger.Debugw("processing query for a known zone",
			"name", zoneName, "class", miekgdns.ClassToString[zoneClass], "mac", mac, "valid", valid, "key", keyName,
			"algorithm", algorithm, "mac_size", macSize, "mac_error", tsigStatus, "fudge", fudge,
			"questions", len(received.Question), "answers", len(received.Answer), "nss", len(received.Ns),
			"extras", len(received.Extra))
	}

	// Early rejection of invalid TSIG signatures.
	// This check is performed again later; this instance is solely for optimization and logging purposes.
	if tsig != nil && tsigStatus != nil {
		Logger.Debug("early rejection of an invalid signature")
		response.SetRcode(received, miekgdns.RcodeRefused)
		goto reply
	}

	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.1 - Process Zone Section
	//
	// if (zcount != 1 || ztype != SOA)
	// 		return (FORMERR)
	// if (zone_type(zname, zclass) == SLAVE)
	// 		return forward()
	// if (zone_type(zname, zclass) == MASTER)
	//		return update()
	// return (NOTAUTH)

	if len(received.Question) != 1 || received.Question[0].Qtype != miekgdns.TypeSOA {
		Logger.Debug("query with invalid zone section")
		goto formerr
	}

	// TODO are we allowing for zone enumeration before authentication here?
	if zone, ok = s.zonesByFqdn[zoneName]; !ok {
		Logger.Debug("query for an unknown zone")
		response.SetRcode(received, miekgdns.RcodeNotAuth)
		goto reply
	}

	// Early rejection of unsigned updates to secured zones.
	// This check is performed again later; this instance is solely for optimization and logging purposes.
	if tsig == nil && zone.HasAuthenticationDisabled() == false {
		Logger.Debug("early rejection of an unauthenticated update to a secured zone")
		response.SetRcode(received, miekgdns.RcodeRefused)
		goto reply
	}

	authorization = update.Authorization{Zone: zone}

	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.2 - Process Prerequisite Section
	//
	// for rr in prerequisites
	//      if (rr.ttl != 0)
	//           return (FORMERR)
	//      if (zone_of(rr.name) != ZNAME)
	//           return (NOTZONE);
	//      if (rr.class == ANY)
	//           if (rr.rdlength != 0)
	//                return (FORMERR)
	//           if (rr.type == ANY)
	//                if (!zone_name<rr.name>)
	//                     return (NXDOMAIN)
	//           else
	//                if (!zone_rrset<rr.name, rr.type>)
	//                     return (NXRRSET)
	//      if (rr.class == NONE)
	//           if (rr.rdlength != 0)
	//                return (FORMERR)
	//           if (rr.type == ANY)
	//                if (zone_name<rr.name>)
	//                     return (YXDOMAIN)
	//           else
	//                if (zone_rrset<rr.name, rr.type>)
	//                     return (YXRRSET)
	//      if (rr.class == zclass)
	//           temp<rr.name, rr.type> += rr
	//      else
	//           return (FORMERR)
	//
	// for rrset in temp
	//      if (zone_rrset<rrset.name, rrset.type> != rrset)
	//           return (NXRRSET)

	// We are performing deferred checks, unlike the RFC approach, because
	// authorization checks will be conducted first, and adapter transactions
	// cannot be initiated at this point. Therefore, this code will only record
	// prerequisites for later evaluation.

	rrset = nil

	for _, rr := range received.Answer {
		if rr != nil {
			rrHeader := rr.Header()

			if rrHeader.Ttl != 0 {
				goto formerr
			}

			if !miekgdns.IsSubDomain(zoneName, rrHeader.Name) {
				response.SetRcode(received, miekgdns.RcodeNotZone)
				goto reply
			}

			if rrHeader.Class == miekgdns.ClassANY {
				if rrHeader.Rdlength != 0 {
					goto formerr
				}

				if rrHeader.Rrtype == miekgdns.TypeANY {
					prerequisites.AddNameMustExist(rr, miekgdns.RcodeNameError)
				} else {
					prerequisites.AddNameWithTypeMustExist(rr, miekgdns.RcodeNXRrset)
				}
			}

			if rrHeader.Class == miekgdns.ClassNONE {
				if rrHeader.Rdlength != 0 {
					goto formerr
				}

				if rrHeader.Rrtype == miekgdns.TypeANY {
					prerequisites.AddNameMustBeAbsent(rr, miekgdns.RcodeYXDomain)
				} else {
					prerequisites.AddNameWithTypeMustBeAbsent(rr, miekgdns.RcodeYXRrset)
				}
			}

			if rrHeader.Class == zoneClass {
				rrset = append(rrset, rr)
			} else {
				goto formerr
			}
		} else {
			goto formerr
		}
	}

	prerequisites.AddSetEquality(rrset, miekgdns.RcodeNXRrset)

	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.3 - Check Requestor's Permissions
	//
	// if (security policy exists)
	//        if (this update is not permitted)
	//             if (local option)
	//                  log a message about permission problem
	//             if (local option)
	//                  return (REFUSED)

	if tsig != nil {
		if tsigStatus == nil {
			authorization.VerifiedIssuer(tsig.Hdr.Name, miekgdns.CanonicalName(tsig.Algorithm))
		} else {
			// No need to log this, as it was already handled in the early check.
			// This code is unlikely to be executed but is retained for authoritative purposes.
			response.SetRcode(received, miekgdns.RcodeRefused)
			goto reply
		}
	} else {
		if zone.HasAuthenticationDisabled() == false {
			// No need to log this, as it was already handled in the early check.
			// This code is unlikely to be executed but is retained for authoritative purposes.
			response.SetRcode(received, miekgdns.RcodeRefused)
			goto reply
		}
	}

	//
	// TODO implement non crypto authorization schemes here
	//

	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.4 - Process Update Section
	// 3.4.1 - Prescan
	//
	// [rr] for rr in updates
	//      if (zone_of(rr.name) != ZNAME)
	//           return (NOTZONE);
	//      if (rr.class == zclass)
	//           if (rr.type & ANY|AXFR|MAILA|MAILB)
	//                return (FORMERR)
	//      elsif (rr.class == ANY)
	//           if (rr.ttl != 0 || rr.rdlength != 0
	//               || rr.type & AXFR|MAILA|MAILB)
	//                return (FORMERR)
	//      elsif (rr.class == NONE)
	//           if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB)
	//                return (FORMERR)
	//      else
	//           return (FORMERR)

	for _, rr := range received.Ns {
		if rr != nil {
			rrHeader := rr.Header()

			if !miekgdns.IsSubDomain(zoneName, rrHeader.Name) {
				response.SetRcode(received, miekgdns.RcodeNotZone)
				goto reply
			}

			invalidTypesAny := []uint16{miekgdns.TypeAXFR, miekgdns.TypeMAILA, miekgdns.TypeMAILB}
			invalidTypes := append(invalidTypesAny, miekgdns.TypeANY)

			switch rrHeader.Class {
			case zoneClass:
				if slices.Contains(invalidTypes, rrHeader.Rrtype) {
					goto formerr
				}
			case miekgdns.ClassANY:
				if rrHeader.Ttl != 0 || rrHeader.Rdlength != 0 || slices.Contains(invalidTypesAny, rrHeader.Rrtype) {
					goto formerr
				}
			case miekgdns.ClassNONE:
				if rrHeader.Ttl != 0 || slices.Contains(invalidTypes, rrHeader.Rrtype) {
					goto formerr
				}
			default:
				goto formerr
			}
		} else {
			goto formerr
		}
	}

	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.4 - Process Update Section
	// 3.4.2 - Update
	//
	// 3.4.2.1. If any system failure (such as an out of memory condition,
	// or a hardware error in persistent storage) occurs during the
	// processing of this section, signal SERVFAIL to the requestor and undo
	// all updates applied to the zone during this transaction.

	task = update.Task{
		Authorization:   &authorization,
		Prerequisites:   &prerequisites,
		UpdateZoneClass: zoneClass,
		UpdateRRset:     &received.Ns,
		Logger:          Logger,
	}

	if err := task.Execute(); err != nil {
		Logger.Errorw("zone update task failed", "error", err.Error())
		response.SetRcode(received, miekgdns.RcodeServerFailure)
		goto reply
	} else {
		response.SetRcode(received, miekgdns.RcodeSuccess)
		goto reply
	}

formerr:
	response.SetRcodeFormatError(received)
reply:
	// if Logger.Level() == zapcore.DebugLevel {
	// 	Logger.Debugf("sending reponse message:\n%s", response.String())
	// }
	writer.WriteMsg(response)
}
