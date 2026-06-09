package main

import (
	"flag"
	"fmt"
	"log"

	ech "github.com/HaizakiKu/quic-ech"
)

func main() {
	publicName := flag.String("public-name", "", "Outer SNI visible to observers (required)")
	keyFile := flag.String("key-file", "", "Path to persist keys (optional)")
	flag.Parse()

	if *publicName == "" {
		flag.Usage()
		log.Fatal("--public-name is required")
	}

	cfg := ech.Config{
		PublicName: *publicName,
		KeyFile:    *keyFile,
	}

	provider, err := ech.NewProvider(cfg)
	if err != nil {
		log.Fatalf("failed to create provider: %v", err)
	}
	defer provider.Close()

	keyFileDisplay := "memory only"
	if *keyFile != "" {
		keyFileDisplay = *keyFile
	}

	fmt.Println("ECH key generated")
	fmt.Println()
	fmt.Printf("  Public name:  %s\n", *publicName)
	fmt.Printf("  Key file:     %s\n", keyFileDisplay)
	fmt.Println()
	fmt.Println("Add this DNS HTTPS record to your domain:")
	fmt.Println()
	fmt.Printf("  @ HTTPS %s\n", provider.DNSRecord())
	fmt.Println()
}
