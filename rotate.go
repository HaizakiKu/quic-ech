package ech

import (
	"crypto/tls"
	"time"
)

// startRotation launches a background goroutine that rotates keys on the configured interval.
func (p *Provider) startRotation() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.cfg.RotateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := p.rotate(); err != nil && p.cfg.OnRotateError != nil {
					p.cfg.OnRotateError(err)
				}
			case <-p.done:
				return
			}
		}
	}()
}

// rotate generates a new key, prepends it, trims to RetainCount+1, and persists if configured.
func (p *Provider) rotate() error {
	key, err := generateKey(p.cfg.PublicName)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.keys = append([]tls.EncryptedClientHelloKey{key}, p.keys...)
	max := p.cfg.RetainCount + 1
	if len(p.keys) > max {
		p.keys = p.keys[:max]
	}
	p.mu.Unlock()

	if p.cfg.KeyFile != "" {
		return p.saveKeys()
	}
	return nil
}
