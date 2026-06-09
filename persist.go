package ech

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

type keyFile struct {
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	Config     string `json:"config"`
	PrivateKey string `json:"private_key"`
}

// saveKeys writes the current key list to cfg.KeyFile as JSON via an atomic
// write (temp file + rename) to avoid corruption on crash.
func (p *Provider) saveKeys() error {
	p.mu.RLock()
	keys := make([]tls.EncryptedClientHelloKey, len(p.keys))
	for i, k := range p.keys {
		keys[i] = tls.EncryptedClientHelloKey{
			Config:     bytes.Clone(k.Config),
			PrivateKey: bytes.Clone(k.PrivateKey),
		}
	}
	p.mu.RUnlock()

	entries := make([]keyEntry, len(keys))
	for i, k := range keys {
		entries[i] = keyEntry{
			Config:     base64.StdEncoding.EncodeToString(k.Config),
			PrivateKey: base64.StdEncoding.EncodeToString(k.PrivateKey),
		}
	}

	data, err := json.MarshalIndent(keyFile{Keys: entries}, "", "  ")
	if err != nil {
		return err
	}

	tmp := p.cfg.KeyFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p.cfg.KeyFile)
}

// loadKeys reads keys from path.
// Returns nil, nil if the file does not exist.
func loadKeys(path string) ([]tls.EncryptedClientHelloKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, err
	}

	keys := make([]tls.EncryptedClientHelloKey, len(kf.Keys))
	for i, e := range kf.Keys {
		cfg, err := base64.StdEncoding.DecodeString(e.Config)
		if err != nil {
			return nil, err
		}
		priv, err := base64.StdEncoding.DecodeString(e.PrivateKey)
		if err != nil {
			return nil, err
		}
		keys[i] = tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: priv}
	}
	return keys, nil
}
