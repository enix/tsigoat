package powerdns

import (
	"context"
	"fmt"

	"github.com/enix/tsigoat/pkg/adapters/common"
	"github.com/joeig/go-powerdns/v3"
	miekgdns "github.com/miekg/dns"
	"go.uber.org/zap"
)

type PowerDNSAdapterTransaction struct {
	zone   string
	client *powerdns.Client
	logger *zap.SugaredLogger
}

func (a PowerDNSAdapter) NewTransaction(zone string, logger *zap.SugaredLogger) (common.IAdapterTransaction, error) {
	return &PowerDNSAdapterTransaction{
		zone,
		powerdns.New(a.config.Url, a.config.VHost, powerdns.WithAPIKey(a.config.decodedKey)),
		logger,
	}, nil
}

func (t PowerDNSAdapterTransaction) Zone() string {
	return t.zone
}

func (t PowerDNSAdapterTransaction) GetAll(rrName string) (RRsets map[uint16][]miekgdns.RR, retErr error) {
	t.logger.Debugw("querying API for all records with name", "name", rrName)
	ctx := context.Background()
	RRsets = make(map[uint16][]miekgdns.RR)

	resp, err := t.client.Records.Get(ctx, t.zone, rrName, nil)
	if err != nil {
		retErr = fmt.Errorf("PowerDNS.GetName: %w", err) // FIXME + logger
		return
	}

	t.logger.Debugw("got records from the API", "name", rrName, "count", len(resp))

	bugged := false
	for _, set := range resp {
		if rrName != *set.Name {
			bugged = true
			continue
		}

		dnsSet, err := DnsRRsetOf(t.zone, set)
		if err != nil {
			retErr = fmt.Errorf("PowerDNS.GetName: %w", err) // FIXME + logger
			return
		}
		if len(dnsSet) > 0 {
			RRsets[dnsSet[0].Header().Rrtype] = dnsSet
		}
	}
	if bugged {
		t.logger.Info("PowerDNS API returned too many records, fixed the response")
	}

	t.logger.Debugw("sorted records by type", "name", rrName, "types", len(RRsets))
	return
}

func (t PowerDNSAdapterTransaction) GetSet(rrName string, rrType uint16) (RRset []miekgdns.RR, retErr error) {
	t.logger.Debugw("querying API for records of name and type", "name", rrName, "type", miekgdns.TypeToString[rrType])
	ctx := context.Background()

	nType, err := ToNativeType(rrType)
	if err != nil {
		retErr = fmt.Errorf("PowerDNS.GetSet: %w", err) // FIXME + logger
		return
	}

	resp, err := t.client.Records.Get(ctx, t.zone, rrName, &nType)
	if err != nil {
		retErr = fmt.Errorf("PowerDNS.GetSet: %w", err) // FIXME + logger
		return
	}

	t.logger.Debugw("got records from the API", "name", rrName, "type", miekgdns.TypeToString[rrType], "count", len(resp))

	bugged := false
	for _, set := range resp {
		if rrName != *set.Name || nType != *set.Type {
			bugged = true
			continue
		}

		dnsSet, err := DnsRRsetOf(t.zone, set)
		if err != nil {
			retErr = fmt.Errorf("PowerDNS.GetSet: %w", err) // FIXME + logger
			return
		}
		RRset = append(RRset, dnsSet...)
	}
	if bugged {
		t.logger.Info("PowerDNS API returned too many records, fixed the response")
		t.logger.Debugw("fixed RRset records", "name", rrName, "count", len(RRset))
	}
	return
}

func (t PowerDNSAdapterTransaction) AddSet(RRset []miekgdns.RR) error {
	t.logger.Debugw("querying API to add a new RRset", "size", len(RRset))

	var err error
	ctx := context.Background()

	name, pType, ttl, content, err := NativeRRsetOf(RRset)
	if err != nil {
		return fmt.Errorf("PowerDNS.AddSet: NativeRRset: %w", err) // FIXME + logger
	}

	err = t.client.Records.Add(ctx, t.zone, name, pType, ttl, content)
	if err != nil {
		return fmt.Errorf("PowerDNS.AddSet: %w", err) // FIXME + logger
	}
	return nil
}

func (t PowerDNSAdapterTransaction) ChangeSet(RRset []miekgdns.RR) error {
	t.logger.Debugw("querying API to change a RRset", "size", len(RRset))

	var err error
	ctx := context.Background()

	name, pType, ttl, content, err := NativeRRsetOf(RRset)
	if err != nil {
		return fmt.Errorf("PowerDNS.ChangeSet: NativeRRset: %w", err) // FIXME + logger
	}

	err = t.client.Records.Change(ctx, t.zone, name, pType, ttl, content)
	if err != nil {
		return fmt.Errorf("PowerDNS.ChangeSet: %w", err) // FIXME + logger
	}
	return nil
}

func (t PowerDNSAdapterTransaction) DeleteSet(name string, recordType uint16) error {
	t.logger.Debugw("querying API to delete a RRset", "name", name, "type", miekgdns.TypeToString[recordType])

	var err error
	ctx := context.Background()

	pType, err := ToNativeType(recordType)
	if err != nil {
		return err // FIXME + logger
	}

	err = t.client.Records.Delete(ctx, t.zone, name, pType)
	if err != nil {
		return fmt.Errorf("PowerDNS.DeleteSet: %w", err) // FIXME + logger
	}
	return nil
}

func (t PowerDNSAdapterTransaction) Commit() error {
	return fmt.Errorf("!!! NOT IMPLEMENTED !!!")
}

func (t PowerDNSAdapterTransaction) Rollback() error {
	return fmt.Errorf("!!! NOT IMPLEMENTED !!!")
}
