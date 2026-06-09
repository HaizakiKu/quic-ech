<div align="center">

# quic-ech

**Server-side ECH for QUIC — in 2 lines.**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![quic-go](https://img.shields.io/badge/quic--go-v0.48+-blueviolet?style=flat-square)](https://github.com/quic-go/quic-go)

<a href="README_zh.md">中文文档</a>
</div>

## What is this?

`quic-ech` adds [Encrypted Client Hello (ECH)](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/) support to any **quic-go**-based server. It handles key generation, ECHConfig serialization, automatic rotation, and DNS record output.

## Why ECH?

Without ECH, the server hostname (SNI) is sent in **plaintext** during the TLS handshake — visible to anyone on the network. ECH encrypts the entire ClientHello using a public key published in DNS, so observers only see a generic outer domain (e.g. `cloudflare.com`).

For QUIC-based proxies like [Hysteria2](https://github.com/apernet/hysteria), server-side ECH has been missing until now. This library bridges Go 1.24's native `EncryptedClientHelloKeys` API with quic-go's recently fixed ECH support.

## Requirements

- Go **1.24+**
- quic-go **v0.48+**

## Installation

```bash
go get github.com/HaizakiKu/quic-ech
```

## Quick Start

```go
provider, err := echgo.NewProvider(echgo.Config{
    PublicName: "cloudflare.com",
    KeyFile:    "/etc/myserver/ech.key",
})

tlsConfig.EncryptedClientHelloKeys = provider.Keys()
defer provider.Close()
```

Then add an `HTTPS` DNS record to your domain:

```
@ HTTPS 1 . ech=<value from provider.DNSRecord()>
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `PublicName` | `string` | — | Outer SNI shown to observers. **Required.** |
| `KeyFile` | `string` | `""` | Path to persist keys across restarts. |
| `RotateInterval` | `time.Duration` | `24h` | How often to rotate ECH keys. |
| `RetainCount` | `int` | `2` | Number of old keys to keep for cached clients. |

## Key API

```go
provider.Keys()                // → []tls.EncryptedClientHelloKey  (for tls.Config)
provider.GetKeys(...)          // → callback for GetEncryptedClientHelloKeys (Go 1.25+)
provider.ECHConfigList()       // → []byte  (raw ECHConfigList for clients)
provider.ECHConfigListBase64() // → string  (base64url, for DNS record)
provider.DNSRecord()           // → "1 . ech=AEn+DQ..."
provider.Close()               // stop rotation goroutine
```

## Dynamic Key Rotation (Go 1.25+)

```go
// Keys rotate automatically in the background.
// Use GetKeys for zero-downtime rotation:
tlsConfig.GetEncryptedClientHelloKeys = provider.GetKeys
```

---

## Related

- [quic-go](https://github.com/quic-go/quic-go) — QUIC implementation this library targets
- [c2FmZQ/ech](https://github.com/c2FmZQ/ech) — Client-side ECH for QUIC (complementary)
- [apernet/hysteria](https://github.com/apernet/hysteria) — Primary integration target

---

MIT License
