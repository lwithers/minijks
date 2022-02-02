package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/lwithers/minijks/jks"
	"github.com/urfave/cli/v2"
)

var UnpackCommand = &cli.Command{
	Name:      "unpack",
	Usage:     "unpack a keystore file into a directory",
	ArgsUsage: "keystore.jks",
	Action:    Unpack,
}

func init() {
	UnpackCommand.Flags = addJksOptsFlags(UnpackCommand.Flags)
}

func Unpack(c *cli.Context) error {
	switch c.NArg() {
	case 0:
		cli.ShowSubcommandHelp(c)
		return errors.New("need name of file to unpack")

	case 1:
		// OK

	default:
		return errors.New("can only unpack one file")
	}

	out := c.String("out")
	if out == "" {
		out = c.Args().Get(0) + ".d"
	}

	opts, err := jksOptsFlags(c)
	if err != nil {
		return err
	}
	return unpack(opts, c.Args().Get(0), out)
}

func unpack(opts *jks.Options, filename, outdir string) error {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	ks, err := jks.Parse(raw, opts)
	// any error will be returned below, after unpacking ks

	if ks != nil {
		if err = os.MkdirAll(outdir, 0700); err != nil {
			return err
		}

		// the directory must be empty
		fi, err := ioutil.ReadDir(outdir)
		if err != nil {
			return err
		}
		if len(fi) != 0 {
			return errors.New("output directory not empty")
		}

		if err := unpackInto(opts, ks, outdir); err != nil {
			return err
		}
	}
	return err
}

func unpackInto(opts *jks.Options, ks *jks.Keystore, outdir string) error {
	var retErr error
	reportErr := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			retErr = errors.New("error(s) encountered")
		}
	}

	if opts == nil {
		opts = &jks.Options{
			SkipVerifyDigest: true,
		}
	}

	// if we have a password, then save it
	if !opts.SkipVerifyDigest {
		err := unpackPassword(opts.Password, outdir, "password")
		reportErr(err)
	}

	// save the certificates
	usedFilenames := make(map[string]int)
	for _, cert := range ks.Certs {
		if cert.CertErr != nil {
			reportErr(fmt.Errorf("certificate %q: %v",
				cert.Alias, cert.CertErr))
			continue
		}
		n := uniqueName(cert.Alias, usedFilenames)
		fn, err := unpackCertificate(cert.Raw,
			outdir, "certs", n+".pem")
		reportErr(err)
		_ = os.Chtimes(fn, time.Now(), cert.Timestamp) // errors ignored
	}

	// save the private keys
	usedFilenames = make(map[string]int)
	for _, kp := range ks.Keypairs {
		if kp.PrivKeyErr != nil {
			reportErr(fmt.Errorf("keypair %q: %v",
				kp.Alias, kp.PrivKeyErr))
			continue
		}

		// save the private key itself
		n := uniqueName(kp.Alias, usedFilenames)
		fn, err := unpackPrivateKey(kp.PrivateKey, outdir, "keys", n,
			"privkey.pem")
		reportErr(err)
		_ = os.Chtimes(fn, time.Now(), kp.Timestamp) // errors ignored

		// if there is a specific password for this key, save it
		passwd, ok := opts.KeyPasswords[kp.Alias]
		if ok {
			err = unpackPassword(passwd, outdir, "keys", n,
				"password")
			reportErr(err)
		}

		// save the certificate chain
		for i, cert := range kp.CertChain {
			_, err = unpackCertificate(cert.Raw, outdir, "keys", n,
				fmt.Sprintf("cert-%04d.pem", i+1))
			reportErr(err)
		}
	}

	return retErr
}

func unpackPassword(password string, pathParts ...string) error {
	fn, f, err := unpackOpen(0600, pathParts...)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(f, "%s\n", password); err != nil {
		_ = f.Close() // ignore errors; return orig err only
		_ = os.Remove(fn)
		return err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(fn)
		return err
	}
	return nil
}

func unpackCertificate(der []byte, pathParts ...string) (string, error) {
	fn, f, err := unpackOpen(0666, pathParts...)
	if err != nil {
		return "", err
	}
	if err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}); err != nil {
		_ = f.Close() // ignore errors; return orig err only
		_ = os.Remove(fn)
		return "", err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(fn)
		return "", err
	}
	return fn, nil
}

func unpackPrivateKey(key interface{}, pathParts ...string) (string, error) {
	var (
		err   error
		block pem.Block
	)
	switch key := key.(type) {
	case *rsa.PrivateKey:
		block.Type = "RSA PRIVATE KEY"
		block.Bytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		block.Type = "EC PRIVATE KEY"
		block.Bytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unknown private key type %T", key)
	}

	fn, f, err := unpackOpen(0600, pathParts...)
	if err != nil {
		return "", err
	}
	if err = pem.Encode(f, &block); err != nil {
		_ = f.Close() // ignore errors; return orig err only
		_ = os.Remove(fn)
		return "", err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(fn)
		return "", err
	}
	return fn, nil
}

func uniqueName(in string, used map[string]int) string {
	// only allow alphanumeric and a couple of specific punctuation chars
	var b bytes.Buffer
	for _, r := range in {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.' && b.Len() != 0,
			r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		b.WriteString("XXX")
	}

	out := b.String()
	if used[out] > 0 {
		out = fmt.Sprintf("%s.%d", out, used[out])
	}
	used[out] = used[out] + 1
	return out
}

func unpackOpen(mode os.FileMode, buildPath ...string,
) (filename string, f *os.File, err error) {
	filename = filepath.Join(buildPath...)
	dirname := filepath.Dir(filename)
	if err = os.MkdirAll(dirname, 0777); err != nil {
		return filename, nil, err
	}
	f, err = os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	return filename, f, err
}
