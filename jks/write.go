package jks

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Pack writes a JKS file. opts must be specified, and the SkipVerifyDigest
// option will be ignored. The password will always be taken from opts, and if
// it is an empty string then an empty string will be used for the password.
// This function requires that all certificates and private keys are present, so
// be sure to check this if you have obtained a Keystore using Parse(). Each
// record should have a unique alias (not checked). If a record's Timestamp is
// zero then the current system time will be queried and be used.
func (ks *Keystore) Pack(opts *Options) ([]byte, error) {
	var buf bytes.Buffer
	writeUint32(&buf, MagicNumber)
	writeUint32(&buf, 2) // version
	writeUint32(&buf, uint32(len(ks.Certs)+len(ks.Keypairs)))

	for _, cert := range ks.Certs {
		if err := writeCert(&buf, cert); err != nil {
			return nil, err
		}
	}
	for _, kp := range ks.Keypairs {
		if err := writeKeypair(&buf, kp, opts); err != nil {
			return nil, err
		}
	}

	digest := ComputeDigest(buf.Bytes(), opts.Password)
	buf.Write(digest)
	return buf.Bytes(), nil
}

// writeCert writes out a certificate record.
func writeCert(w io.Writer, cert *Cert) error {
	writeUint32(w, 2) // type = certificate
	if err := writeStr(w, cert.Alias); err != nil {
		return fmt.Errorf("failed to write alias (%v): %q",
			err, cert.Alias)
	}

	ts := cert.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	writeTimestamp(w, ts)

	if err := writeStr(w, CertType); err != nil {
		return fmt.Errorf("failed to write certificate type (%v)", err)
	}

	writeUint32(w, uint32(len(cert.Cert.Raw)))
	w.Write(cert.Cert.Raw)

	return nil
}

// writeKeypair writes out a private key and associated certificate chain.
func writeKeypair(w io.Writer, kp *Keypair, opts *Options) error {
	writeUint32(w, 1) // type = private key + cert chain
	if err := writeStr(w, kp.Alias); err != nil {
		return fmt.Errorf("failed to write alias (%v): %q",
			err, kp.Alias)
	}

	// use specific key password if present, fall back to global
	passwd, ok := opts.KeyPasswords[kp.Alias]
	if !ok {
		passwd = opts.Password
	}

	ts := kp.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	writeTimestamp(w, ts)

	// marshal the key into ‘raw’
	raw, err := MarshalPKCS8(kp.PrivateKey)
	if err != nil {
		return fmt.Errorf("key %q: %v", kp.Alias, err)
	}

	// encrypt the marshalled key, then wrap into a PKCS#8
	// EncryptedPrivateKeyInfo structure
	ciphertext, err := EncryptJavaKeyEncryption1(raw, passwd)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}
	keyInfo := EncryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  JavaKeyEncryptionOID1,
			Parameters: asn1NULL,
		},
		EncryptedData: ciphertext,
	}
	raw, err = asn1.Marshal(keyInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal PKCS#8 encrypted "+
			"private key info: %v", err)
	}
	writeUint32(w, uint32(len(raw)))
	w.Write(raw)

	// write out the certificate chain
	writeUint32(w, uint32(len(kp.CertChain)))
	for _, cert := range kp.CertChain {
		if err := writeStr(w, CertType); err != nil {
			return fmt.Errorf("failed to write certificate "+
				"type (%v)", err)
		}
		writeUint32(w, uint32(len(cert.Cert.Raw)))
		w.Write(cert.Cert.Raw)
	}

	return nil
}

// writeUint32 writes a 32-bit unsigned integer in big-endian format.
func writeUint32(w io.Writer, u uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], u)
	w.Write(raw[:])
}

// writeUint64 writes a 64-bit unsigned integer in big-endian format.
func writeUint64(w io.Writer, u uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], u)
	w.Write(raw[:])
}

// writeTimestamp converts the timestamp to a 64-bit unsigned number (ms elapsed
// since the Unix epoch) and writes it in big-endian format.
func writeTimestamp(w io.Writer, ts time.Time) {
	ms := ts.UnixNano() / 1e6
	writeUint64(w, uint64(ms))
}

// writeStr writes a UTF-8 string. The string is encoded as an octet length
// (16-bit unsigned big-endian integer) followed by the UTF-8 octets. This
// function will return an error if there are too many octets to fit into the
// 16-bit length field.
func writeStr(w io.Writer, s string) error {
	if len(s) > 0xFFFF {
		return errors.New("string too long")
	}

	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(len(s)))
	w.Write(raw[:])
	w.Write([]byte(s))
	return nil
}
