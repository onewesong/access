package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/edgefn/auth-center/config"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "validate-config":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		if _, err := config.Load(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "invalid config:", err)
			os.Exit(1)
		}
		fmt.Println("configuration is valid")
	case "generate-key":
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() { fmt.Fprintln(os.Stderr, "usage: authctl validate-config <config.yaml> | generate-key") }
