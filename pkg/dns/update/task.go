package update

import (
	"fmt"

	"github.com/enix/tsigan/pkg/adapters/common"
	miekgdns "github.com/miekg/dns"
	"go.uber.org/zap"
)

const ()

type Task struct {
	Authorization   *Authorization
	Prerequisites   *Prerequisites
	UpdateZoneClass uint16
	UpdateRRset     *[]miekgdns.RR
	Logger          *zap.SugaredLogger
	transaction     common.IAdapterTransaction
}

func (t *Task) Execute() error {
	var err error

	// Validate authorizations
	t.Logger.Debugw("evaluating authorizations")
	if err := t.Authorization.Evaluate(); err != nil {
		return fmt.Errorf("authorization failed: %w", err)
	}

	zone := t.Authorization.Zone
	adapter := zone.Handler()

	// Start an adapter transaction
	t.Logger.Infow("starting a new transaction", "adapter", adapter.Name())
	t.transaction, err = adapter.NewTransaction(zone.Fqdn(), t.Logger)
	if err != nil {
		return fmt.Errorf("new transaction: %w", err)
	}

	// Validate all update prerequisites
	t.Logger.Debugw("validating update prerequisites", "count", t.Prerequisites.Count())
	t.Logger.Info("!!! NOT IMPLEMENTED !!!") // FIXME
	if err := t.Prerequisites.Evaluate(t.transaction); err != nil {
		return fmt.Errorf("prerequisites failed: %w", err)
	}

	// Proceed with the update
	t.Logger.Debugw("executing update section", "count", len(*t.UpdateRRset))
	if err := t.doUpdate(); err != nil {
		return err
	}

	if err := t.transaction.Commit(); err != nil {
		// return fmt.Errorf("transaction failure: %w", err)
		t.Logger.Info("!!! NOT IMPLEMENTED !!!") // FIXME
	}

	// FIXME add panic defer ?

	return nil
}

func (t *Task) doUpdate() error {
	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.4 - Process Update Section
	// 3.4.2 - Update
	//
	// 3.4.2.6 - Table Of Metavalues Used In Update Section
	//
	//  CLASS    TYPE     RDATA    Meaning
	//  ---------------------------------------------------------
	//  ANY      ANY      empty    Delete all RRsets from a name
	//  ANY      rrset    empty    Delete an RRset
	//  NONE     rrset    rr       Delete an RR from an RRset
	//  zone     rrset    rr       Add to an RRset
	//
	// 3.4.2.7 - Pseudocode For Update Section Processing
	//
	//  [rr] for rr in updates
	//       if (rr.class == zclass)
	//            if (rr.type == CNAME)
	//                 if (zone_rrset<rr.name, ~CNAME>)
	//                      next [rr]
	//            elsif (zone_rrset<rr.name, CNAME>)
	//                 next [rr]
	//            if (rr.type == SOA)
	//                 if (!zone_rrset<rr.name, SOA> ||
	//                     zone_rr<rr.name, SOA>.serial > rr.soa.serial)
	//                      next [rr]
	//            for zrr in zone_rrset<rr.name, rr.type>
	//                 if (rr.type == CNAME || rr.type == SOA ||
	//                     (rr.type == WKS && rr.proto == zrr.proto &&
	//                      rr.address == zrr.address) ||
	//                     rr.rdata == zrr.rdata)
	//                      zrr = rr
	//                      next [rr]
	//            zone_rrset<rr.name, rr.type> += rr
	//       elsif (rr.class == ANY)
	//            if (rr.type == ANY)
	//                 if (rr.name == zname)
	//                      zone_rrset<rr.name, ~(SOA|NS)> = Nil
	//                 else
	//                      zone_rrset<rr.name, *> = Nil
	//            elsif (rr.name == zname &&
	//                   (rr.type == SOA || rr.type == NS))
	//                 next [rr]
	//            else
	//                 zone_rrset<rr.name, rr.type> = Nil
	//       elsif (rr.class == NONE)
	//            if (rr.type == SOA)
	//                 next [rr]
	//            if (rr.type == NS && zone_rrset<rr.name, NS> == rr)
	//                 next [rr]
	//            zone_rr<rr.name, rr.type, rr.data> = Nil
	//  return (NOERROR)

	for _, rr := range *t.UpdateRRset {
		rrClass := rr.Header().Class
		t.Logger.Debugw("working on RR from the update section", "class", miekgdns.ClassToString[rrClass], "name", rr.Header().Name,
			"type", miekgdns.TypeToString[rr.Header().Rrtype], "zone", t.transaction.Zone())

		switch rrClass {
		case t.UpdateZoneClass:
			//  3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS [...]
			if err := t.doAddToRRset(rr); err != nil {
				return err
			}
		case miekgdns.ClassANY:
			// 3.4.2.3. For any Update RR whose CLASS is ANY [...]
			if err := t.doDeleteRRset(rr); err != nil {
				return err
			}
		case miekgdns.ClassNONE:
			// 3.4.2.4. For any Update RR whose class is NONE [...]
			if err := t.doDeleteFromRRset(rr); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid RR class: %s", miekgdns.ClassToString[rrClass])
		}
	}
	return nil
}

func (t *Task) doAddToRRset(rr miekgdns.RR) error {
	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.4 - Process Update Section
	// 3.4.2 - Update
	//
	// 3.4.2.2. Any Update RR whose CLASS is the same as ZCLASS is added to
	// the zone.  In case of duplicate RDATAs (which for SOA RRs is always
	// the case, and for WKS RRs is the case if the ADDRESS and PROTOCOL
	// fields both match), the Zone RR is replaced by Update RR.  If the
	// TYPE is SOA and there is no Zone SOA RR, or the new SOA.SERIAL is
	// lower (according to [RFC1982]) than or equal to the current Zone SOA
	// RR's SOA.SERIAL, the Update RR is ignored.  In the case of a CNAME
	// Update RR and a non-CNAME Zone RRset or vice versa, ignore the CNAME
	// Update RR, otherwise replace the CNAME Zone RR with the CNAME Update
	// RR.
	//
	//  if (rr.type == CNAME)
	//       if (zone_rrset<rr.name, ~CNAME>)
	//            next [rr]
	//  elsif (zone_rrset<rr.name, CNAME>)
	//       next [rr]
	//  if (rr.type == SOA)
	//       if (!zone_rrset<rr.name, SOA> ||
	//           zone_rr<rr.name, SOA>.serial > rr.soa.serial)
	//            next [rr]
	//  for zrr in zone_rrset<rr.name, rr.type>
	//       if (rr.type == CNAME || rr.type == SOA ||
	//           (rr.type == WKS && rr.proto == zrr.proto &&
	//            rr.address == zrr.address) ||
	//           rr.rdata == zrr.rdata)
	//            zrr = rr
	//            next [rr]
	//  zone_rrset<rr.name, rr.type> += rr

	rrName := rr.Header().Name
	rrType := rr.Header().Rrtype

	zoneSets, err := t.transaction.GetAll(rrName)
	if err != nil {
		t.Logger.Errorw("error getting zone RRsets", "name", rrName, "error", err.Error())
		return fmt.Errorf("failed to get all RRsets: %w", err)
	}

	if rrType == miekgdns.TypeCNAME {
		t.Logger.Debugw("checking for conflicts with non-CNAME RRset", "name", rrName)
		for setType := range zoneSets {
			if setType != miekgdns.TypeCNAME {
				t.Logger.Debugw("an existing RRset would conflict with CNAME", "name", rrName, "type", miekgdns.TypeToString[setType])
				return nil
			}
		}
	} else {
		t.Logger.Debugw("checking for conflicts with a CNAME RRset ", "name", rrName)
		for setType := range zoneSets {
			if setType == miekgdns.TypeCNAME {
				t.Logger.Debugw("an existing CNAME would conflict with this RR", "name", rrName, "type", miekgdns.TypeToString[rrType])
				return nil
			}
		}
	}

	zoneSet := zoneSets[rrType]

	if rrType == miekgdns.TypeSOA {
		// FIXME
		t.Logger.Info("!!! NOT IMPLEMENTED !!!")
		return fmt.Errorf("!!! NOT IMPLEMENTED !!!")
	}

	for idx, zoneRr := range zoneSet {
		// TODO refactor
		rdataEqual, err := EqualRdata(rr, zoneRr)
		if err != nil {
			t.Logger.Errorw("error comparing Rdata", "error", err.Error())
			return err
		}

		// WKS is dropped by the server
		if rrType == miekgdns.TypeCNAME || rrType == miekgdns.TypeSOA || rdataEqual {
			zoneSet[idx] = rr
			if err := t.transaction.ChangeSet(zoneSet); err != nil {
				t.Logger.Errorw("error changing zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
				return fmt.Errorf("failed to change RRset: %w", err)
			}
			return nil
		}
	}

	zoneSet = append(zoneSet, rr)
	if len(zoneSet) > 1 {
		if err := t.transaction.ChangeSet(zoneSet); err != nil {
			t.Logger.Errorw("error changing zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
			return fmt.Errorf("failed to change RRset: %w", err)
		}
	} else {
		if err := t.transaction.AddSet(zoneSet); err != nil {
			t.Logger.Errorw("error adding zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
			return fmt.Errorf("failed to add RRset: %w", err)
		}
	}
	return nil
}

func (t *Task) doDeleteRRset(rr miekgdns.RR) error {
	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.4 - Process Update Section
	// 3.4.2 - Update
	//
	// 3.4.2.3. For any Update RR whose CLASS is ANY and whose TYPE is ANY,
	// all Zone RRs with the same NAME are deleted, unless the NAME is the
	// same as ZNAME in which case only those RRs whose TYPE is other than
	// SOA or NS are deleted.  For any Update RR whose CLASS is ANY and
	// whose TYPE is not ANY all Zone RRs with the same NAME and TYPE are
	// deleted, unless the NAME is the same as ZNAME in which case neither
	// SOA or NS RRs will be deleted.
	//
	//  if (rr.type == ANY)
	//       if (rr.name == zname)
	//            zone_rrset<rr.name, ~(SOA|NS)> = Nil
	//       else
	//            zone_rrset<rr.name, *> = Nil
	//  elsif (rr.name == zname &&
	//         (rr.type == SOA || rr.type == NS))
	//       next [rr]
	//  else
	//       zone_rrset<rr.name, rr.type> = Nil

	rrName := rr.Header().Name
	rrType := rr.Header().Rrtype
	// FIXME not good
	isZoneName := (rrName == t.Authorization.Zone.Fqdn())

	if rrType == miekgdns.TypeANY {
		sets, err := t.transaction.GetAll(rrName)
		if err != nil {
			t.Logger.Errorw("error getting zone RRsets", "name", rrName, "error", err.Error())
			return fmt.Errorf("doDeleteRRset: failed to get all sets: %w", err)
		}
		for setType := range sets {
			if setType == miekgdns.TypeSOA || setType == miekgdns.TypeNS {
				continue
			}
			// TODO refactor
			t.Logger.Debugw("doDeleteRRset: doing a set deletion", "name", rrName, "type", miekgdns.TypeToString[setType])
			if err := t.transaction.DeleteSet(rrName, setType); err != nil {
				t.Logger.Errorw("error deleting zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
				return fmt.Errorf("doDeleteRRset: failed to delete set: %w", err)
			}
		}
	} else if isZoneName && (rrType == miekgdns.TypeSOA || rrType == miekgdns.TypeNS) {
		t.Logger.Debugw("doDeleteRRset: skipping SOA or NS record", "name", rrName, "type", miekgdns.TypeToString[rrType])
		return nil
	} else {
		// TODO refactor
		t.Logger.Debugw("doDeleteRRset: doing a set deletion", "name", rrName, "type", miekgdns.TypeToString[rrType])
		if err := t.transaction.DeleteSet(rrName, rrType); err != nil {
			t.Logger.Errorw("error deleting zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
			return fmt.Errorf("doDeleteRRset: failed to delete set: %w", err)
		}
	}

	return nil
}

func (t *Task) doDeleteFromRRset(rr miekgdns.RR) error {
	// -------------------------------------------------------
	// RFC 2136 - Server Behavior
	// https://datatracker.ietf.org/doc/html/rfc2136#section-3
	//
	// 3.4 - Process Update Section
	// 3.4.2 - Update
	//
	// 3.4.2.4. For any Update RR whose class is NONE, any Zone RR whose
	// NAME, TYPE, RDATA and RDLENGTH are equal to the Update RR is deleted,
	// unless the NAME is the same as ZNAME and either the TYPE is SOA or
	// the TYPE is NS and the matching Zone RR is the only NS remaining in
	// the RRset, in which case this Update RR is ignored.
	//
	//  if (rr.type == SOA)
	//       next [rr]
	//  if (rr.type == NS && zone_rrset<rr.name, NS> == rr)
	//       next [rr]
	//  zone_rr<rr.name, rr.type, rr.data> = Nil

	rrName := rr.Header().Name
	rrType := rr.Header().Rrtype

	// When not to delete the RR
	switch rr.(type) {
	case *miekgdns.SOA:
		t.Logger.Debug("doDeleteFromRRset: skipping SOA record")
		return nil
	case *miekgdns.NS:
		set, err := t.transaction.GetSet(rrName, miekgdns.TypeNS)
		if err != nil {
			t.Logger.Errorw("error getting zone RRset type NS", "name", rrName, "error", err.Error())
			return fmt.Errorf("doDeleteFromRRset: failed to get NS RRset: %w", err)
		}
		// We don't have to compare RRs
		if len(set) <= 1 {
			t.Logger.Debug("doDeleteFromRRset: skipping remaining NS record if any")
			return nil
		}
	}

	t.Logger.Debugw("doDeleteFromRRset: deleting an RR", "name", rrName, "type", miekgdns.TypeToString[rrType])

	set, err := t.transaction.GetSet(rrName, rrType)
	if err != nil {
		t.Logger.Errorw("error getting zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
		return fmt.Errorf("doDeleteFromRRset: failed to get set to change: %w", err)
	}

	t.Logger.Debugw("doDeleteFromRRset: got set to change", "name", rrName, "type", miekgdns.TypeToString[rrType],
		"count", len(set))

	newSet, removed, err := RemoveFromSet(rr, set)
	if err != nil {
		t.Logger.Debug("FIXME message")
		return fmt.Errorf("doDeleteFromRRset: %w", err)
	}
	if removed {
		if len(newSet) > 0 {
			t.Logger.Debugw("doDeleteFromRRset: doing a set change", "name", rrName, "type", miekgdns.TypeToString[rrType],
				"count", len(newSet))

			if err := t.transaction.ChangeSet(newSet); err != nil {
				t.Logger.Errorw("error changing zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
				return fmt.Errorf("doDeleteFromRRset: failed to change set: %w", err)
			}
		} else {
			t.Logger.Debugw("doDeleteFromRRset: doing a set deletion", "name", rrName, "type", miekgdns.TypeToString[rrType])

			if err := t.transaction.DeleteSet(rrName, rrType); err != nil {
				t.Logger.Errorw("error deleting zone RRset", "name", rrName, "type", miekgdns.TypeToString[rrType], "error", err.Error())
				return fmt.Errorf("doDeleteFromRRset: failed to delete set: %w", err)
			}
		}
	}

	return nil
}
