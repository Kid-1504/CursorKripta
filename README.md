# CursorKripta

Maven project for generating an XMSSMT key pair, signing a message, and creating a
self-signed X.509 certificate with Bouncy Castle.

## Run

```bash
mvn -q compile exec:java -Dexec.mainClass=ru.isu.crypto.XmssmtAssignment
```

The program writes three files to `artifacts/`:

- `certificate.cer` - self-signed certificate in DER format.
- `message.txt` - signed ASCII message.
- `signature.hex` - message signature in hexadecimal format.

Certificate subject values can be overridden with Java system properties:

```bash
mvn -q compile exec:java \
  -Dexec.mainClass=ru.isu.crypto.XmssmtAssignment \
  -Dcert.cn="Student Name" \
  -Dcert.email="student@kais.isu.ru"
```
