package ech

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"sync"
)

// Provider manages ECH keys and exposes them for use with tls.Config.
type Provider struct {
	cfg       Config
	mu        sync.RWMutex
	keys      []tls.EncryptedClientHelloKey // index 0 is always the current key
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewProvider creates a Provider and generates the first key immediately.
// If cfg.KeyFile exists, keys are loaded from disk instead.
func NewProvider(cfg Config) (*Provider, error) {
	cfg.fill()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	p := &Provider{
		cfg:  cfg,
		done: make(chan struct{}),
	}

	if cfg.KeyFile != "" {
		loaded, err := loadKeys(cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		if len(loaded) > 0 {
			p.keys = loaded
			p.startRotation()
			return p, nil
		}
	}

	key, err := generateKey(cfg.PublicName)
	if err != nil {
		return nil, err
	}
	p.keys = []tls.EncryptedClientHelloKey{key}

	if cfg.KeyFile != "" {
		if err := p.saveKeys(); err != nil {
			return nil, err
		}
	}

	p.startRotation()
	return p, nil
}

// Keys returns a deep copy of the current key list for use with tls.Config.EncryptedClientHelloKeys.
func (p *Provider) Keys() []tls.EncryptedClientHelloKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]tls.EncryptedClientHelloKey, len(p.keys))
	for i, k := range p.keys {
		out[i] = tls.EncryptedClientHelloKey{
			Config:      bytes.Clone(k.Config),
			PrivateKey:  bytes.Clone(k.PrivateKey),
			SendAsRetry: k.SendAsRetry,
		}
	}
	return out
}

// GetKeys implements the tls.Config.GetEncryptedClientHelloKeys callback (Go 1.25+).
func (p *Provider) GetKeys(_ *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
	return p.Keys(), nil
}

// ECHConfigList returns the raw serialized ECHConfigList for the current keys.
func (p *Provider) ECHConfigList() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return marshalECHConfigList(p.keys)
}

// ECHConfigListBase64 returns the standard base64-encoded ECHConfigList suitable
// for use in DNS HTTPS records.
func (p *Provider) ECHConfigListBase64() string {
	return base64.StdEncoding.EncodeToString(p.ECHConfigList())
}

// DNSRecord returns the full HTTPS DNS record value for this provider.
// Format: "1 . ech=<base64(ECHConfigList)>"
func (p *Provider) DNSRecord() string {
	return "1 . ech=" + p.ECHConfigListBase64()
}

// Close stops the rotation goroutine, waits for it to exit, zeroes all private
// key material in memory, and releases resources. Safe to call multiple times.
func (p *Provider) Close() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.wg.Wait()
		p.mu.Lock()
		for i := range p.keys {
			clear(p.keys[i].PrivateKey)
		}
		p.mu.Unlock()
	})
}
