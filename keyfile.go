package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/lwithers/minijks/jks"
	"github.com/urfave/cli/v2"
)

var KeyfileCommand = &cli.Command{
	Name:      "keyfile",
	Usage:     "pack a single keypair/cert chain into a keystore file",
	ArgsUsage: "out.jks in.pem [in2.pem ...]",
	Action:    Keyfile,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "password",
			Required: true,
			Usage:    "Password to encrypt .jks file",
		},
		&cli.StringFlag{
			Name:        "alias",
			DefaultText: "key",
			Usage:       "Alias of key within keystore file",
		},
	},
}

func Keyfile(c *cli.Context) error {
	switch c.NArg() {
	case 0, 1:
		cli.ShowSubcommandHelp(c)
		return errors.New("need output file name and at least one input filename")
	}

	outFn := c.Args().Get(0)
	opts := &jks.Options{
		Password: c.String("password"),
	}

	kp, err := keyfileKeypair(c.Args().Slice()[1:])
	if err != nil {
		return err
	}
	kp.Alias = c.String("alias")

	ks := &jks.Keystore{
		Keypairs: []*jks.Keypair{kp},
	}
	raw, err := ks.Pack(opts)
	if err != nil {
		return err
	}

	return os.WriteFile(outFn, raw, 0600)
}

func keyfileKeypair(infiles []string) (*jks.Keypair, error) {
	kp := &jks.Keypair{}
	for _, fn := range infiles {
		raw, err := os.ReadFile(fn)
		if err != nil {
			return nil, err
		}

		for {
			block, rest := pem.Decode(raw)
			if block == nil {
				break
			}
			raw = rest

			switch block.Type {
			case "PRIVATE KEY":
				if kp.PrivateKey != nil {
					return nil, errors.New("multiple private keys encountered")
				}
				kp.PrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)

			case "RSA PRIVATE KEY":
				if kp.PrivateKey != nil {
					return nil, errors.New("multiple private keys encountered")
				}
				kp.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)

			case "EC PRIVATE KEY":
				if kp.PrivateKey != nil {
					return nil, errors.New("multiple private keys encountered")
				}
				kp.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)

			case "CERTIFICATE":
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", fn, err)
				}
				kp.CertChain = append(kp.CertChain, &jks.KeypairCert{
					Raw:  block.Bytes,
					Cert: cert,
				})
			}
		}
	}

	if kp.PrivateKey == nil {
		return nil, errors.New("no private key found")
	}

	if len(kp.CertChain) > 0 {
		// TODO: match first cert against keypair
	}

	return kp, nil
}
