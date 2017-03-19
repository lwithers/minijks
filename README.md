# minijks Java keytool replacement

This is a replacement for the Java `keytool` program that manipulates `.jks`
(Java keystore) files. Its purpose is to reduce the pain of DevOps burdened by
Java deployments.

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
