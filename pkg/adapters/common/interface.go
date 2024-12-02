package common

import (
	miekgdns "github.com/miekg/dns"
	"go.uber.org/zap"
)

type IAdapterConfiguration interface{}

type IAdapter interface {
	Name() string
	NewTransaction(string, *zap.SugaredLogger) (IAdapterTransaction, error)
}

type IAdapterTransaction interface {
	Zone() string
	GetAll(string) (map[uint16][]miekgdns.RR, error)
	GetSet(string, uint16) ([]miekgdns.RR, error)
	AddSet([]miekgdns.RR) error
	ChangeSet([]miekgdns.RR) error
	DeleteSet(string, uint16) error
	Commit() error
	Rollback() error
}
