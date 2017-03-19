/*
Package jks provides routines for manipulating Java Keystore files.
*/
package jks

import (
	"crypto/x509"
	"time"
)

const (
	// MagicNumber is written at the start of each .jks file.
	MagicNumber = 0xFEEDFEED

	// DigestSeparator is used to build the file's verification digest. The
	// digest is over the keystore password encoded as UCS-2, then this
	// string (yes, really — check the OpenJDK source) encoded as UTF-8, and
	// then the actual file data.
	DigestSeparator = "Mighty Aphrodite"

	// CertType is the certificate type string that is encoded into each
	// certificate's header in the keystore.
	CertType = "X.509"
)

type Cert struct {
	Alias     string
	Timestamp time.Time
	Raw       []byte

	CertErr error
	Cert    *x509.Certificate
}

type Keypair struct {
	Alias     string
	Timestamp time.Time

	PrivKeyErr   error
	EncryptedKey []byte

	// RawKey is the raw marshalled private key, after it has been
	// decrypted. It will not have been set if decryption failed.
	RawKey []byte

	// PrivateKey is the unmarshalled private key. It will not have been
	// set if decryption failed or if unmarshalling failed.
	PrivateKey interface{}

	CertChain []*KeypairCert
}

type KeypairCert struct {
	Raw []byte

	Cert    *x509.Certificate
	CertErr error
}

type Keystore struct {
	Certs    []*Cert
	Keypairs []*Keypair
}

type Options struct {
	// Password is used as part of a SHA-1 digest over the .jks file.
	Password string

	// SkipVerifyDigest can be set to skip digest verification when loading
	// a keystore file. This will inhibit errors from Parse if you don't
	// know the password.
	SkipVerifyDigest bool

	// KeyPasswords are used to generate the "encryption" keys for stored
	// private keys. The map's key is the alias of the private key, and the
	// value is the password. If there is no entry in the map for a given
	// alias, then the top-level Password is inherited.
	KeyPasswords map[string]string
}

var defaultOptions = Options{
	SkipVerifyDigest: true,
}
