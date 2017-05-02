# minijks Java keytool replacement

This is a replacement for the Java `keytool` program that manipulates `.jks`
(Java keystore) files. Its purpose is to reduce the pain of DevOps burdened by
Java deployments.

## Usage

To install:

```
go get github.com/lwithers/minijks
```

Simply running the `minijks` command with no arguments produces a usage screen.

To inspect the content of a `.jks` file:

```
$ minijks inspect my.jks
# … shows certificates
$ minijks inspect --password foo my.jks
# … shows certificates, verifies the digest, shows keys encrypted with
    the common password
```

To unpack a `.jks` file:

```
$ minijks unpack --password foo --key-password server:bar my.jks
$ tree my.jks.d
my.jks.d/
├── certs
│   └── ca.pem
├── keys
│   └── server
│       ├── cert-0001.pem
│       ├── cert-0002.pem
│       └── privkey.pem
└── password

3 directories, 5 files
```

### Inspect

The `inspect` command will show details about the certificates and possibly the
private keys embedded in the `.jks` file.

Without a password, the tool is able to display all the certificates and can
show which private keys are in the file (alias, timestamp, and associated
certificate chain), but it cannot decrypt the private keys to inspect them or
verify the integrity digest over the file.

If the keystore password is given, then the integrity digest can be verified.
Furthermore, this password will be used to attempt to decrypt each private key
embedded in the file. It is possible that one or more keys were encrypted using
different passwords; in that case, the `--key-password <key_alias:password>`
option may be used.

### Unpack

The `unpack` command will unpack each certificate (and private key if the
password is given) into a directory tree. It could be considered similar to
a `tar x` operation.

The output directory name is derived by taking the source filename and adding a
`.d` onto the end. If the directory already exists the command will refuse to
run.

The directory tree format is suitable for use with the `pack` command.

### Pack

The `pack` command will pack a directory tree into a `.jks` file. It takes two
arguments: the name of the input directory, and the name of the output file. It
could be considered similar to a `tar c` operation.

TODO: explain directory format.

## TODO list

Pull requests accepted!

- OpenJDK appears to have a second key encryption algorithm available for private
  keys using 3DES. This needs to be implemented for decryption purposes.
- Validation hints:
  - Check that certificate entries are valid CA certificates (intermediate or
    otherwise).
  - Check private key certificate chains have correct corresponding public key,
    correct order, and do not include the final root CA.
- Write clear file format specifications in a document.
- Testcases! I have some internal ones but they're not data I can share, so it
  would be good to gather some real-world examples and check that we can
  process them correctly.
- Unit tests for the functions would be good.
- PKCS#8 library: either find an existing one and extend it with the algorithms
  we need for Java, or write a new one.
- Programmable mode? Auto-generate a new .jks file based on a set of
  instructions.

## References

### Keystore format

The `.jks` file format doesn't appear to be explicitly documented, but the
OpenJDK source is clear enough. It has a comment giving the file structure as
well as code for parsing and creating `.jks` files:
- http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/sun/security/provider/JavaKeyStore.java#l492

### PKCS#8

Private keys are wrapped in PKCS#8, which is actually incredibly simple. It's
an ASN.1 object that has an algorithm OID followed by a blob of encrypted data.
Details in RFC5208 §6:
- https://tools.ietf.org/html/rfc5208#section-6

### Key encryption type 1

There appear to be two types of encryption that can be used to encrypt the
private keys. One of them seems to be custom crypto (you should *never* do
this):
- identified by algorithm OID 1.3.6.1.4.1.42.2.17.1.1
- http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/com/sun/crypto/provider/KeyProtector.java#l192

### Key encryption type 2

Another type of encryption used to encrypt private keys. This might be specific
to OpenJDK. It appears to be a custom combination of existing algorithms:
- identified by algorithm OID 1.3.6.1.4.1.42.2.19.1
- http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/com/sun/crypto/provider/PBEWithMD5AndTripleDESCipher.java
