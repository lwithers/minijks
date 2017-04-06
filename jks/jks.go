/*
Package jks provides routines for manipulating Java Keystore files.
*/
package jks

import (
	"crypto/sha1"
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

// Keystore represents a single JKS file. It holds a list of certificates and a
// list of keypairs (private keys with associated certificate chains).
type Keystore struct {
	// Certs is a list of CA certificates to trust. It may contain either
	// root or intermediate CA certificates. It should not contain end-user
	// certificates.
	Certs []*Cert

	// Keypairs is a list of private keys. Each key may have a certificate
	// chain associated with it.
	Keypairs []*Keypair
}

// Options for manipulating a keystore. These allow the caller to specify the
// password(s) used, or to skip the digest verification if the password is
// unknown.
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

// Cert holds a certificate to trust.
type Cert struct {
	Alias     string
	Timestamp time.Time
	Raw       []byte

	CertErr error
	Cert    *x509.Certificate
}

// Keypair holds a private key and an associated certificate chain.
type Keypair struct {
	// Alias is a name used to refer to this keypair.
	Alias string

	// Timestamp records when this record was created.
	Timestamp time.Time

	// PrivKeyErr is set if an error is encountered during decryption or
	// unmarshalling of the decrypted key.
	PrivKeyErr error

	// EncryptedKey is the raw PKCS#8 marshalled EncryptedPrivateKeyInfo.
	EncryptedKey []byte

	// RawKey is the raw PKCS#8 marshalled PrivateKeyInfo, after it has
	// been decrypted. It will not have been set if decryption failed.
	RawKey []byte

	// PrivateKey is the unmarshalled private key. It will not have been
	// set if decryption failed or if unmarshalling failed.
	PrivateKey interface{}

	// CertChain is a chain of certificates associated with the private key.
	// The first entry in the chain (index 0) should correspond to
	// PrivateKey; there should then follow any intermediate CAs. In
	// general the root CA should not be part of the chain.
	CertChain []*KeypairCert
}

// KeypairCert is an entry in the certificate chain associated with a Keypair.
type KeypairCert struct {
	// Raw X.509 certificate data (in DER form).
	Raw []byte

	// Cert is the parsed X.509 certificate. It is nil if the certificate
	// could not be parsed.
	Cert *x509.Certificate

	// CertErr records any error encountered while parsing a certificate.
	CertErr error
}

var defaultOptions = Options{
	SkipVerifyDigest: true,
}

// ComputeDigest performs the custom hash function over the given file data.
// DO NOT RE-USE THIS CODE: this is an atrocious way to perform message
// authentication. Use the HMAC example from
// https://github.com/lwithers/go-crypto-examples instead. Note this construct
// is vulnerable to a length extension attack, which is actually exploitable if
// the JKS reader code does not properly check the "number of entries" value.
func ComputeDigest(raw []byte, password string) []byte {
	md := sha1.New()
	var ucs2 [2]byte
	for _, r := range password {
		ucs2[0] = byte((r >> 8) & 0xFF)
		ucs2[1] = byte(r & 0xFF)

		md.Write(ucs2[:])
	}

	md.Write([]byte(DigestSeparator))
	md.Write(raw)
	return md.Sum(nil)
}
