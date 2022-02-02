package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/lwithers/minijks/jks"
	"github.com/urfave/cli/v2"
)

var PackCommand = &cli.Command{
	Name:      "pack",
	Usage:     "pack a directory into a keystore file",
	ArgsUsage: "in.d out.jks",
	Action:    Pack,
}

func Pack(c *cli.Context) error {
	switch c.NArg() {
	case 0:
		cli.ShowSubcommandHelp(c)
		return errors.New("need input directory and output file name")

	case 2:
		// OK

	default:
		return errors.New("need input directory and output file name")
	}

	inDir := c.Args().Get(0)
	outFn := c.Args().Get(1)

	st, err := os.Stat(inDir)
	if err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("%q must be a directory", inDir)
	}

	f, err := os.OpenFile(outFn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}

	if err = pack(f, inDir); err != nil {
		_ = f.Close()
		_ = os.Remove(outFn)
		return err
	}

	if err = f.Close(); err != nil {
		_ = os.Remove(outFn)
		return err
	}

	return nil
}

func pack(out io.Writer, inDir string) error {
	certDir := filepath.Join(inDir, "certs")
	keyDir := filepath.Join(inDir, "keys")

	var (
		err  error
		ks   jks.Keystore
		opts = jks.Options{
			KeyPasswords: make(map[string]string),
		}
	)
	opts.Password, err = packPassword(inDir)
	if err != nil {
		return err
	}

	if _, err = os.Stat(certDir); err == nil {
		if err = packCerts(&opts, &ks, certDir); err != nil {
			return err
		}
	}

	if _, err = os.Stat(keyDir); err == nil {
		var keyDirs []string
		f, err := ioutil.ReadDir(keyDir)
		if err != nil {
			return err
		}
		for _, fi := range f {
			if !fi.IsDir() {
				continue
			}
			if fi.Name()[0] == '.' {
				continue
			}
			keyDirs = append(keyDirs,
				filepath.Join(keyDir, fi.Name()))
		}
		for _, d := range keyDirs {
			kp, err := packKeypair(&opts, d)
			if err != nil {
				return err
			}
			ks.Keypairs = append(ks.Keypairs, kp)
		}
	}

	raw, err := ks.Pack(&opts)
	if err != nil {
		return err
	}

	_, err = out.Write(raw)
	return err
}

func packPassword(dirname string) (string, error) {
	fn := filepath.Join(dirname, "password")
	p, err := ioutil.ReadFile(fn)
	if err != nil {
		return "", err
	}

	// strip a possible trailing newline
	if len(p) > 0 && p[len(p)-1] == '\n' {
		p = p[:len(p)-1]
	}

	// ensure it's valid UTF-8
	if !utf8.Valid(p) {
		return "", fmt.Errorf("%s: not valid UTF-8", fn)
	}
	return string(p), nil
}

func packCerts(opts *jks.Options, ks *jks.Keystore, certDir string) error {
	f, err := ioutil.ReadDir(certDir)
	if err != nil {
		return err
	}

	for _, fi := range f {
		if fi.IsDir() || fi.Name()[0] == '.' ||
			filepath.Ext(fi.Name()) != ".pem" {
			fmt.Fprintf(os.Stderr, "ignoring %q (must be "+
				"non-dot-file ending .pem)\n", fi.Name())
			continue
		}

		cert, err := packLoadCert(filepath.Join(certDir, fi.Name()))
		if err != nil {
			return err
		}

		alias := filepath.Base(fi.Name())
		alias = alias[:len(alias)-4] // strip ".pem"
		ks.Certs = append(ks.Certs, &jks.Cert{
			Alias:     alias,
			Timestamp: fi.ModTime(),
			Cert:      cert,
		})
	}
	return nil
}

func packKeypair(opts *jks.Options, dir string) (*jks.Keypair, error) {
	kp := &jks.Keypair{
		Alias: filepath.Base(dir),
	}

	fname := filepath.Join(dir, "password")
	fi, err := os.Stat(fname)
	if err == nil {
		opts.KeyPasswords[kp.Alias], err = packPassword(dir)
		if err != nil {
			return nil, err
		}
	}

	fname = filepath.Join(dir, "privkey.pem")
	if fi, err = os.Stat(fname); err != nil {
		return nil, err
	}
	kp.Timestamp = fi.ModTime()

	block, err := packLoadPem(fname)
	switch block.Type {
	case "RSA PRIVATE KEY":
		kp.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		kp.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)

	default:
		err = fmt.Errorf("%q: unknown private key type %q",
			fname, block.Type)
	}
	if err != nil {
		return nil, err
	}

	f, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, fi := range f {
		if fi.Name()[0] == '.' || fi.IsDir() ||
			fi.Name() == "privkey.pem" ||
			filepath.Ext(fi.Name()) != ".pem" {
			continue
		}

		fname = filepath.Join(dir, fi.Name())
		if !strings.HasPrefix(fi.Name(), "cert-") {
			fmt.Fprintf(os.Stderr, "warning: ignoring %q", fname)
			continue
		}

		cert, err := packLoadCert(fname)
		if err != nil {
			return nil, err
		}

		kp.CertChain = append(kp.CertChain, &jks.KeypairCert{
			Cert: cert,
		})
	}

	return kp, nil
}

func packLoadPem(fname string) (*pem.Block, error) {
	pemraw, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(pemraw)
	if block == nil {
		return nil, fmt.Errorf("%q: not a PEM file", fname)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("%q: has data beyond first PEM block",
			fname)
	}
	return block, nil
}

func packLoadCert(fname string) (*x509.Certificate, error) {
	block, err := packLoadPem(fname)
	if err != nil {
		return nil, err
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%q: expected CERTIFICATE but found %q",
			fname, block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", fname, err)
	}
	return cert, nil
}
