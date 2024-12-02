package tsig

import (
	"crypto/hmac"
	"encoding/hex"

	miekgdns "github.com/miekg/dns"
	"go.uber.org/zap"
)

type TsigProvider struct {
	keyring *TsigKeyring
	logger  *zap.SugaredLogger
}

func NewTsigProvider(keyring *TsigKeyring, logger *zap.SugaredLogger) *TsigProvider {
	return &TsigProvider{keyring, logger}
}

func (p *TsigProvider) generate(msg []byte, t *miekgdns.TSIG) ([]byte, error) {
	keyName := t.Hdr.Name

	key := p.keyring.Key(keyName)
	if key == nil {
		p.logger.Debugw("failed to compute MAC: unknown key", "key", keyName)
		return nil, miekgdns.ErrSecret
	}

	// TODO check if canonicalization of t.Algorithm is needed
	tsigHmac, err := NewHmac(t.Algorithm)
	if err != nil {
		p.logger.Debugw("failed to compute MAC: invalid algorithm", "key", keyName, "hmac", t.Algorithm,
			"error", err.Error())
		return nil, miekgdns.ErrKeyAlg
	}

	return tsigHmac.Sum(msg, key)
}

func (p *TsigProvider) Generate(msg []byte, t *miekgdns.TSIG) ([]byte, error) {
	keyName := t.Hdr.Name
	p.logger.Debugw("generation of a message MAC", "key", keyName)
	return p.generate(msg, t)
}

func (p *TsigProvider) Verify(msg []byte, t *miekgdns.TSIG) error {
	keyName := t.Hdr.Name
	p.logger.Debugw("verification of a message MAC", "key", keyName)

	computedMac, err := p.generate(msg, t)
	if err != nil {
		p.logger.Debugw("verification failed while computing expected hash", "key", keyName, "error", err.Error())
		return err
	}

	receivedMac, err := hex.DecodeString(t.MAC)
	if err != nil {
		p.logger.Debugw("verification failed while decoding received MAC", "key", keyName, "error", err.Error())
		return err
	}

	if !hmac.Equal(computedMac, receivedMac) {
		p.logger.Debugw("verification failed! MACs are not equal", "key", keyName)
		return miekgdns.ErrSig
	}
	return nil
}
