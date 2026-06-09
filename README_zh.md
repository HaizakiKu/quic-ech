<div align="center">

# quic-ech

**两行代码，为 QUIC 服务端开启 ECH 支持。**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![quic-go](https://img.shields.io/badge/quic--go-v0.48+-blueviolet?style=flat-square)](https://github.com/quic-go/quic-go)

</div>

## 这是什么？

`quic-ech` 为任何基于 **quic-go** 的服务端提供 [ECH（加密客户端握手）](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)支持。它封装了密钥生成、ECHConfig 序列化、自动轮换和 DNS 记录输出，开箱即用。

## 为什么需要 ECH？

没有 ECH 时，TLS 握手中的服务器域名（SNI）以**明文**传输，任何网络中间人都可以看到你在连接哪个服务器。ECH 通过 DNS 中发布的公钥对整个 ClientHello 加密，让外部观察者只能看到一个通用的外层域名（如 `cloudflare.com`）。

对于 [Hysteria2](https://github.com/apernet/hysteria) 等基于 QUIC 的代理协议，服务端 ECH 支持此前一直缺失。本库桥接了 Go 1.24 原生的 `EncryptedClientHelloKeys` API 与 quic-go 最新修复的 ECH 支持。

## 环境要求

- Go **1.24+**
- quic-go **v0.48+**

## 安装

```bash
go get github.com/HaizakiKu/quic-ech
```

## 快速上手

```go
provider, err := ech.NewProvider(ech.Config{
    PublicName: "cloudflare.com", // 外层 SNI，观察者看到的域名
    KeyFile:    "/etc/myserver/ech.key", // 重启后密钥持久化
})

tlsConfig.EncryptedClientHelloKeys = provider.Keys()
defer provider.Close()
```

然后在你的域名添加一条 `HTTPS` DNS 记录：

```
@ HTTPS 1 . ech=<provider.DNSRecord() 的输出值>
```

支持 ECH 的客户端（Chrome、Firefox）在连接时会自动加密 ClientHello。

## 配置项

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `PublicName` | `string` | — | 外层 SNI，外部可见的域名。**必填。** |
| `KeyFile` | `string` | `""` | 密钥持久化路径，重启后自动加载。 |
| `RotateInterval` | `time.Duration` | `24h` | 密钥轮换间隔。 |
| `RetainCount` | `int` | `2` | 保留的历史密钥数量，用于兼容缓存了旧配置的客户端。 |

## 主要 API

```go
provider.Keys()                // → []tls.EncryptedClientHelloKey  （写入 tls.Config）
provider.GetKeys(...)          // → 回调函数，用于 GetEncryptedClientHelloKeys（Go 1.25+）
provider.ECHConfigList()       // → []byte  （原始 ECHConfigList，分发给客户端）
provider.ECHConfigListBase64() // → string  （base64url 编码，用于 DNS 记录）
provider.DNSRecord()           // → "1 . ech=AEn+DQ..."
provider.Close()               // 停止密钥轮换 goroutine
```

## 动态密钥轮换（Go 1.25+）

```go
// 密钥在后台自动轮换，无需重启服务。
// 使用 GetKeys 实现零停机轮换：
tlsConfig.GetEncryptedClientHelloKeys = provider.GetKeys
```

---

## 相关项目

- [quic-go](https://github.com/quic-go/quic-go) — 本库适配的 QUIC 实现
- [c2FmZQ/ech](https://github.com/c2FmZQ/ech) — 客户端侧 ECH（与本库互补）
- [apernet/hysteria](https://github.com/apernet/hysteria) — 主要集成目标

---

<div align="center">
MIT License · <a href="README.md">English</a>
</div>
