package ru.isu.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

public final class XmssMtSignatureCertificateTask {
    private static final String PQC_PROVIDER = "BCPQC";
    private static final String CERT_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "XMSSMT";
    private static final String SIGNATURE_ALGORITHM = "SHA256withXMSSMT";

    private static final Path DEFAULT_OUTPUT_DIR = Path.of("outputs");
    private static final String DEFAULT_MESSAGE = "Post-quantum XMSSMT signature demo message";
    private static final String DEFAULT_COMMON_NAME = "Student Name";
    private static final String DEFAULT_EMAIL = "student@kais.isu.ru";

    private XmssMtSignatureCertificateTask() {
    }

    public static void main(String[] args) throws Exception {
        TaskOptions options = TaskOptions.fromArgs(args);

        registerProvider(new BouncyCastlePQCProvider());
        registerProvider(new BouncyCastleProvider());

        SecureRandom secureRandom = new SecureRandom();
        KeyPair keyPair = generateXmssMtKeyPair(secureRandom);

        byte[] messageBytes = options.message().getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = signMessage(keyPair.getPrivate(), messageBytes);
        verifyMessageSignature(keyPair.getPublic(), messageBytes, signatureBytes);

        X509Certificate certificate = createSelfSignedCertificate(
                keyPair,
                options.commonName(),
                options.email(),
                secureRandom
        );

        writeArtifacts(options.outputDir(), certificate, options.message(), signatureBytes);
        printResult(options.outputDir(), certificate, signatureBytes);
    }

    private static void registerProvider(Provider provider) {
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
    }

    private static KeyPair generateXmssMtKeyPair(SecureRandom secureRandom) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, PQC_PROVIDER);
        XMSSMTParameterSpec xmssmtParameterSpec = new XMSSMTParameterSpec(
                20,
                10,
                XMSSMTParameterSpec.SHA256
        );
        keyGenerator.initialize(xmssmtParameterSpec, secureRandom);
        return keyGenerator.generateKeyPair();
    }

    private static byte[] signMessage(PrivateKey privateKey, byte[] messageBytes) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, PQC_PROVIDER);
        signature.initSign(privateKey);
        signature.update(messageBytes);
        return signature.sign();
    }

    private static void verifyMessageSignature(
            PublicKey publicKey,
            byte[] messageBytes,
            byte[] signatureBytes
    ) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, PQC_PROVIDER);
        signature.initVerify(publicKey);
        signature.update(messageBytes);

        if (!signature.verify(signatureBytes)) {
            throw new IllegalStateException("Generated XMSSMT signature verification failed.");
        }
    }

    private static X509Certificate createSelfSignedCertificate(
            KeyPair keyPair,
            String commonName,
            String email,
            SecureRandom secureRandom
    ) throws Exception {
        X500Name subject = buildCertificateName(commonName, email);
        X500Name issuer = subject;

        BigInteger serialNumber = new BigInteger(64, secureRandom).abs();
        ZonedDateTime notBeforeDateTime = ZonedDateTime.now(ZoneOffset.UTC);
        Date notBefore = Date.from(notBeforeDateTime.toInstant());
        Date notAfter = Date.from(notBeforeDateTime.plusMonths(1).toInstant());

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );

        certificateBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false)
        );
        certificateBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature)
        );

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PQC_PROVIDER)
                .build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(signer);

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(CERT_PROVIDER)
                .getCertificate(certificateHolder);
        certificate.checkValidity(Date.from(Instant.now()));
        return certificate;
    }

    private static X500Name buildCertificateName(String commonName, String email) {
        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, commonName);
        subjectBuilder.addRDN(BCStyle.E, email);
        subjectBuilder.addRDN(BCStyle.O, "Irkutsk State University");
        subjectBuilder.addRDN(BCStyle.OU, "Cryptography Course");
        subjectBuilder.addRDN(BCStyle.C, "RU");
        return subjectBuilder.build();
    }

    private static void writeArtifacts(
            Path outputDir,
            X509Certificate certificate,
            String message,
            byte[] signatureBytes
    ) throws Exception {
        Files.createDirectories(outputDir);
        Files.write(outputDir.resolve("certificate.cer"), certificate.getEncoded());
        Files.writeString(outputDir.resolve("message.txt"), message, StandardCharsets.UTF_8);
        Files.writeString(outputDir.resolve("signature.hex"), toHex(signatureBytes), StandardCharsets.US_ASCII);
    }

    private static void printResult(
            Path outputDir,
            X509Certificate certificate,
            byte[] signatureBytes
    ) {
        System.out.println("Generated files:");
        System.out.println(" - " + outputDir.resolve("certificate.cer"));
        System.out.println(" - " + outputDir.resolve("message.txt"));
        System.out.println(" - " + outputDir.resolve("signature.hex"));
        System.out.println("Certificate subject: " + certificate.getSubjectX500Principal());
        System.out.println("Certificate issuer: " + certificate.getIssuerX500Principal());
        System.out.println("Certificate not before: " + certificate.getNotBefore());
        System.out.println("Certificate not after: " + certificate.getNotAfter());
        System.out.println("Signature length: " + signatureBytes.length + " bytes");
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(Character.forDigit((value >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(value & 0x0f, 16));
        }
        return result.toString();
    }

    private record TaskOptions(
            Path outputDir,
            String message,
            String commonName,
            String email
    ) {
        private static TaskOptions fromArgs(String[] args) {
            Map<String, String> parsedArgs = parseArgs(args);
            return new TaskOptions(
                    Path.of(parsedArgs.getOrDefault("--out", DEFAULT_OUTPUT_DIR.toString())),
                    parsedArgs.getOrDefault("--message", DEFAULT_MESSAGE),
                    parsedArgs.getOrDefault("--cn", DEFAULT_COMMON_NAME),
                    parsedArgs.getOrDefault("--email", DEFAULT_EMAIL)
            );
        }

        private static Map<String, String> parseArgs(String[] args) {
            Map<String, String> parsedArgs = new LinkedHashMap<>();
            for (int index = 0; index < args.length; index++) {
                String current = args[index];
                if (!current.startsWith("--")) {
                    throw new IllegalArgumentException("Unexpected argument: " + current);
                }
                if (index + 1 >= args.length || args[index + 1].startsWith("--")) {
                    throw new IllegalArgumentException("Missing value for argument: " + current);
                }
                parsedArgs.put(current, args[++index]);
            }
            return parsedArgs;
        }
    }
}
