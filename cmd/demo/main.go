// demo 在同一进程中启动 QUIC+ECH 服务端和客户端，演示完整的 ECH 握手流程
//
// 运行方式：
//
//	go run ./cmd/demo
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	ech "github.com/HaizakiKu/quic-ech"
	"github.com/quic-go/quic-go"
)

func main() {
	// 1. 创建 ECH Provider
	// PublicName 是公开可见的"掩护"域名（写入 DNS HTTPS 记录）
	// 真实部署时需换成你的实际域名，并把 provider.DNSRecord() 的值写到 DNS
	provider, err := ech.NewProvider(ech.Config{
		PublicName:     "public.example.com",
		RotateInterval: 24 * time.Hour,
		RetainCount:    2,
		OnRotateError: func(e error) {
			log.Printf("[ECH] 密钥轮换失败: %v", e)
		},
	})
	if err != nil {
		log.Fatalf("NewProvider: %v", err)
	}
	defer provider.Close()

	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("  quic-ech 真实场景演示")
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Printf("\n[1] ECH PublicName : %s\n", "public.example.com")
	fmt.Printf("[1] 将以下记录添加到你的 DNS（HTTPS 类型）:\n\n")
	fmt.Printf("    @ HTTPS %s\n\n", provider.DNSRecord())
	fmt.Printf("[1] ECHConfigList (base64) : %s\n\n", provider.ECHConfigListBase64())

	// 2. 生成自签名 TLS 证书（演示用，生产环境使用正式证书）
	tlsCert, certPool := mustSelfSignedCert("localhost")
	fmt.Println("[2] 已生成自签名 TLS 证书（演示用）")

	// 3. 启动 QUIC 服务端
	serverTLS := &tls.Config{
		Certificates:            []tls.Certificate{tlsCert},
		NextProtos:              []string{"demo"},
		EncryptedClientHelloKeys: provider.Keys(),
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		log.Fatalf("ListenAddr: %v", err)
	}
	defer ln.Close()
	fmt.Printf("[3] 服务端已启动: %s\n", ln.Addr())

	// 服务端 goroutine：接受连接 → 读一条消息 → 回显
	type serverResult struct {
		echAccepted bool
		msg         string
		err         error
	}
	serverCh := make(chan serverResult, 1)
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			serverCh <- serverResult{err: err}
			return
		}
		defer conn.CloseWithError(0, "bye")

		echAccepted := conn.ConnectionState().TLS.ECHAccepted

		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverCh <- serverResult{echAccepted: echAccepted, err: err}
			return
		}
		buf := make([]byte, 256)
		n, _ := stream.Read(buf)
		msg := string(buf[:n])

		// 回显
		stream.Write([]byte("echo: " + msg))
		stream.Close()

		serverCh <- serverResult{echAccepted: echAccepted, msg: msg}
	}()

	// 4. 客户端用 ECHConfigList 连接
	// 在真实场景中，客户端从 DNS 的 HTTPS 记录里拿到 ECHConfigList；
	// 这里直接从 provider 取，效果完全相同。
	clientTLS := &tls.Config{
		RootCAs:                        certPool,
		ServerName:                     "localhost",
		NextProtos:                     []string{"demo"},
		EncryptedClientHelloConfigList: provider.ECHConfigList(),
	}
	conn, err := quic.DialAddr(context.Background(), ln.Addr().String(), clientTLS, nil)
	if err != nil {
		log.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "bye")

	clientECH := conn.ConnectionState().TLS.ECHAccepted
	fmt.Printf("[4] 客户端已连接，ECHAccepted = %v\n", clientECH)

	// 发一条消息
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("OpenStreamSync: %v", err)
	}
	stream.Write([]byte("Hello, ECH!"))
	stream.Close()

	// 读回显
	buf := make([]byte, 256)
	n, _ := stream.Read(buf)
	fmt.Printf("[4] 客户端收到回显: %q\n", string(buf[:n]))

	// 5. 打印服务端结果
	res := <-serverCh
	if res.err != nil {
		log.Fatalf("服务端错误: %v", res.err)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Printf("  服务端 ECHAccepted : %v\n", res.echAccepted)
	fmt.Printf("  客户端 ECHAccepted : %v\n", clientECH)
	if res.echAccepted && clientECH {
		fmt.Println("  ✓ ECH 握手成功！ClientHello 已加密，SNI 对观察者不可见。")
	} else {
		fmt.Println("  ✗ ECH 握手未成功，请检查配置。")
	}
	fmt.Println("═══════════════════════════════════════════════════")
}

// mustSelfSignedCert 生成自签名证书，演示用。
func mustSelfSignedCert(domain string) (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(certDER)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, pool
}
