package ru.isu.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;

public final class XmssmtAssignment {
    private static final String PQC_PROVIDER = "BCPQC";
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "XMSSMT";
    private static final String SIGNATURE_ALGORITHM = "SHA256withXMSSMT";

    private static final Path DEFAULT_OUTPUT_DIR = Path.of("artifacts");
    private static final String MESSAGE =
            "Post-quantum XMSSMT signature example for Java and Bouncy Castle.";

    private XmssmtAssignment() {
    }

    public static void main(String[] args) throws Exception {
        addProviders();

        Path outputDir = args.length > 0 ? Path.of(args[0]) : DEFAULT_OUTPUT_DIR;
        Files.createDirectories(outputDir);

        byte[] messageBytes = MESSAGE.getBytes(StandardCharsets.UTF_8);
        KeyPair keyPair = generateXmssmtKeyPair();

        byte[] signature = sign(messageBytes, keyPair.getPrivate());
        if (!verify(messageBytes, signature, keyPair.getPublic())) {
            throw new GeneralSecurityException("XMSSMT signature verification failed");
        }

        X509Certificate certificate = createSelfSignedCertificate(keyPair);
        certificate.verify(keyPair.getPublic(), PQC_PROVIDER);

        Path messageFile = outputDir.resolve("message.txt");
        Path signatureFile = outputDir.resolve("signature.hex");
        Path certificateFile = outputDir.resolve("certificate.cer");

        Files.writeString(messageFile, MESSAGE + System.lineSeparator(), StandardCharsets.UTF_8);
        Files.writeString(signatureFile, toHex(signature) + System.lineSeparator(), StandardCharsets.US_ASCII);
        Files.write(certificateFile, certificate.getEncoded());

        System.out.println("Message: " + messageFile.toAbsolutePath());
        System.out.println("Signature: " + signatureFile.toAbsolutePath());
        System.out.println("Certificate: " + certificateFile.toAbsolutePath());
        System.out.println("Certificate subject: " + certificate.getSubjectX500Principal());
        System.out.println("Certificate issuer: " + certificate.getIssuerX500Principal());
    }

    private static void addProviders() {
        if (Security.getProvider(PQC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static KeyPair generateXmssmtKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM, PQC_PROVIDER);
        XMSSMTParameterSpec parameterSpec = new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256);
        keyGen.initialize(parameterSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static byte[] sign(byte[] message, PrivateKey privateKey) throws GeneralSecurityException {
        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM, PQC_PROVIDER);
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    private static boolean verify(byte[] message, byte[] signature, PublicKey publicKey)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM, PQC_PROVIDER);
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }

    private static X509Certificate createSelfSignedCertificate(KeyPair keyPair)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        X500Name subject = certificateName();
        X500Name issuer = certificateName();
        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();

        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.MINUTES));
        Date notAfter = Date.from(now.plus(30, ChronoUnit.DAYS));

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PQC_PROVIDER)
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        return (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certHolder.getEncoded()));
    }

    private static X500Name certificateName() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, System.getProperty("cert.cn", "Student Name"));
        builder.addRDN(BCStyle.E, System.getProperty("cert.email", "student@kais.isu.ru"));
        builder.addRDN(BCStyle.O, System.getProperty("cert.organization", "ISU"));
        builder.addRDN(BCStyle.C, System.getProperty("cert.country", "RU"));
        return builder.build();
    }

    private static String toHex(byte[] data) {
        StringBuilder hex = new StringBuilder(data.length * 2);
        for (byte value : data) {
            hex.append(String.format("%02x", value & 0xff));
        }
        return hex.toString();
    }
}
