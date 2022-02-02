package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/lwithers/minijks/jks"
	"github.com/urfave/cli/v2"
)

func addJksOptsFlags(in []cli.Flag) []cli.Flag {
	return append(in,
		&cli.StringFlag{
			Name:  "password",
			Usage: "keystore password",
		},
		&cli.StringSliceFlag{
			Name:  "key-password",
			Usage: "password for a given key, as 'alias:password'",
		},
	)
}

func jksOptsFlags(c *cli.Context) (*jks.Options, error) {
	opts := &jks.Options{
		KeyPasswords: make(map[string]string),
	}
	if c.IsSet("password") {
		opts.Password = c.String("password")
	} else {
		opts.SkipVerifyDigest = true
	}
	for _, keypass := range c.StringSlice("key-password") {
		p := strings.Split(keypass, ":")
		if len(p) != 2 {
			return nil, errors.New("invalid --key-password argument")
		}
		opts.KeyPasswords[p[0]] = p[1]
	}
	return opts, nil
}

var InspectCommand = &cli.Command{
	Name:      "inspect",
	Usage:     "inspect the contents of a keystore file",
	ArgsUsage: "keystore.jks",
	Action:    Inspect,
}

func init() {
	InspectCommand.Flags = addJksOptsFlags(InspectCommand.Flags)
}

func Inspect(c *cli.Context) error {
	switch c.NArg() {
	case 0:
		cli.ShowSubcommandHelp(c)
		return errors.New("need name of file to inspect")

	case 1:
		// OK

	default:
		return errors.New("can only inspect one file")
	}

	opts, err := jksOptsFlags(c)
	if err != nil {
		return err
	}
	return inspect(opts, c.Args().Get(0))
}

func inspect(opts *jks.Options, filename string) error {
	fmt.Printf("======== %s ========\n", filename)

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	ks, err := jks.Parse(raw, opts)
	// any error will be returned below, after printing anything from ks

	if ks != nil {
		for i, cert := range ks.Certs {
			fmt.Printf("---- certificate #%d ----\n", i+1)
			inspectCert(cert)
			fmt.Println("")
		}

		for i, kp := range ks.Keypairs {
			fmt.Printf("---- keypair #%d ----\n", i+1)
			inspectKeypair(kp)
			fmt.Println("")
		}
	}

	return err // error from jks.Parse
}

func inspectCert(cert *jks.Cert) {
	c := cert.Cert
	fmt.Printf("Alias:\t\t%q\n", cert.Alias)
	fmt.Printf("Timestamp:\t%s\n", cert.Timestamp.Format(time.RFC3339Nano))
	if cert.CertErr != nil {
		fmt.Println("Unable to parse certificate:")
		fmt.Printf("    Error:\t%v\n", cert.CertErr)
		fmt.Printf("    Length:\t%d bytes\n", len(cert.Raw))
		return
	}

	fmt.Printf("Common name:\t%q\n", c.Subject.CommonName)
	if len(c.SubjectKeyId) != 0 {
		fmt.Printf("Subject key ID:\t%X\n", c.SubjectKeyId)
	}

	// in theory, we should only really have self-signed certs
	if err := c.CheckSignatureFrom(c); err != nil {
		fmt.Println("Not self-signed:")
		fmt.Printf("    Verify error:\t%v\n", err)
		fmt.Printf("    Issuer name:\t%q\n", c.Issuer.CommonName)
		if len(c.AuthorityKeyId) != 0 {
			fmt.Printf("    Issuer key ID:\t%X\n", c.AuthorityKeyId)
		}
	}

	fmt.Println("Validity:")
	fmt.Printf("    From:\t%s\n", c.NotBefore.Format(time.RFC3339Nano))
	fmt.Printf("    Until:\t%s\n", c.NotAfter.Format(time.RFC3339Nano))

	inspectPublicKey("", c.PublicKey)

	// because intended usage is that certs should be root CAs, we don't
	// print any extra info like key usage, basic constraints or SANs
}

func inspectPublicKey(pfx string, pub interface{}) {
	fmt.Printf("%sPublic key:\n", pfx)
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Printf("%s    Type:\tRSA\n", pfx)
		fmt.Printf("%s    Size:\t%d bits\n", pfx, pub.N.BitLen())

	case *ecdsa.PublicKey:
		fmt.Printf("%s    Type:\tEC\n", pfx)
		fmt.Printf("%s    Size:\t%d bits\n", pfx, pub.Params().BitSize)
		fmt.Printf("%s    Curve:\t%s\n", pfx, pub.Params().Name)

	default:
		fmt.Printf("%s    Unknown type:\t%T\n", pfx, pub)
	}
}

func inspectKeypair(kp *jks.Keypair) {
	fmt.Printf("Alias:\t\t%q\n", kp.Alias)
	fmt.Printf("Timestamp:\t%s\n", kp.Timestamp.Format(time.RFC3339Nano))
	if kp.PrivKeyErr != nil {
		fmt.Println("Unable to parse private key (wrong password?):")
		fmt.Printf("    Error:\t%v\n", kp.PrivKeyErr)
		fmt.Printf("    Ciphertext:\t%d bytes\n", len(kp.EncryptedKey))
		if len(kp.RawKey) == 0 {
			fmt.Println("    Failed to decrypt ciphertext")
		} else {
			fmt.Printf("    Plaintext:\t%d bytes\n", len(kp.RawKey))
		}
	} else {
		inspectPrivateKey(kp.PrivateKey)
	}

	if len(kp.CertChain) == 0 {
		fmt.Println("No certificates present!")
	}
	for i, cert := range kp.CertChain {
		fmt.Printf("    ---- certificate #%d ----\n", i+1)
		if cert.CertErr != nil {
			fmt.Printf("\tParse error:\t%v\n", cert.CertErr)
			fmt.Printf("\tRaw length:\t%d bytes\n", len(cert.Raw))
			continue
		}

		c := cert.Cert
		fmt.Printf("    Common name:\t%q\n", c.Subject.CommonName)
		if len(c.SubjectKeyId) != 0 {
			fmt.Printf("    Subject key ID:\t%X\n", c.SubjectKeyId)
		}
		fmt.Println("    Validity:")
		fmt.Printf("\tFrom:\t%s\n", c.NotBefore.Format(time.RFC3339Nano))
		fmt.Printf("\tUntil:\t%s\n", c.NotAfter.Format(time.RFC3339Nano))
		fmt.Println("    Subject alternate names:")
		for i, name := range c.DNSNames {
			fmt.Printf("\tDNS #%d:\t%s\n", i+1, name)
		}
		for i, ip := range c.IPAddresses {
			fmt.Printf("\tIP #%d:\t%s\n", i+1, ip)
		}
		inspectPublicKey("    ", c.PublicKey)
	}
}

func inspectPrivateKey(priv interface{}) {
	fmt.Println("Private key:")
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		fmt.Println("    Type:\tRSA")
		fmt.Printf("    Size:\t%d bits\n", priv.N.BitLen())

	case *ecdsa.PrivateKey:
		fmt.Println("    Type:\tEC")
		fmt.Printf("    Size:\t%d bits\n", priv.Params().BitSize)
		fmt.Printf("    Curve:\t%s\n", priv.Params().Name)

	default:
		fmt.Printf("    Unknown type:\t%T\n", priv)
	}
}
