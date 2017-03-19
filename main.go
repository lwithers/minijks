package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/lwithers/minijks/jks"
)

// just a test at the moment

func main() {
	if err := Main(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func Main() error {
	raw, err := ioutil.ReadFile("in.jks")
	if err != nil {
		return err
	}

	ks, err := jks.Parse(raw, nil)
	if err != nil {
		return err
	}

	for i, c := range ks.Certs {
		fmt.Printf("==== Certificate #%d ====\n", i+1)
		fmt.Printf("Alias:\t%s\n", c.Alias)
		fmt.Printf("Time:\t%v\n", c.Timestamp)
		fmt.Printf("Length:\t%d bytes\n", len(c.Raw))
		fmt.Printf("Parse error:\t%v\n", c.CertErr)
		fmt.Println("")
	}
	for i, k := range ks.Keypairs {
		fmt.Printf("==== Keypair #%d ====\n", i+1)
		fmt.Printf("Alias:\t%s\n", k.Alias)
		fmt.Printf("Time:\t%v\n", k.Timestamp)
		fmt.Printf("Key error:\t%v\n", k.PrivKeyErr)
		fmt.Printf("Ciphertext len:\t%d bytes\n", len(k.EncryptedKey))
		fmt.Printf("Private key len:\t%d bytes\n", len(k.RawKey))
		fmt.Printf("Private key type:\t%T\n", k.PrivateKey)
		for j, c := range k.CertChain {
			fmt.Printf("    ---- certificate #%d ----\n", j+1)
			fmt.Printf("    Length:\t%d\n", len(c.Raw))
			fmt.Printf("    Parse error:\t%v\n", c.CertErr)
		}
		fmt.Println("")
	}
	return nil
}
