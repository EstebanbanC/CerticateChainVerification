import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Objects;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

public class ValidateCertChain {

    public static boolean verifyRSASignature(X509Certificate cert, X509Certificate issuerCert) {
        try {
            PublicKey publicKey = issuerCert.getPublicKey();
            if (publicKey instanceof RSAPublicKey rsaPublicKey) {

                BigInteger modulus = rsaPublicKey.getModulus();
                BigInteger exponent = rsaPublicKey.getPublicExponent();

                byte[] signatureBytes = cert.getSignature();
                BigInteger signature = new BigInteger(1, signatureBytes);

                // DÃ©chiffrement de la signature pour obtenir le hash
                BigInteger signatureCheck = signature.modPow(exponent, modulus);

                // Calcul du hash du TBSCertificate
                MessageDigest crypt = MessageDigest.getInstance("SHA-256");
                crypt.update(cert.getTBSCertificate());
                byte[] certHash = crypt.digest();

                byte[] signatureCheckBytes = signatureCheck.toByteArray();
                String sigAlg = cert.getSigAlgName();
                int hashLength = 0;

                // Determine the SHA type and set the hash length accordingly
                if (sigAlg.contains("SHA1")) {
                    hashLength = 20; // SHA-1 produces a 160-bit (20-byte) hash value
                } else if (sigAlg.contains("SHA256")) {
                    hashLength = 32; // SHA-256 produces a 256-bit (32-byte) hash value
                } else if (sigAlg.contains("SHA384")) {
                    hashLength = 48; // SHA-384 produces a 384-bit (48-byte) hash value
                } else if (sigAlg.contains("SHA512")) {
                    hashLength = 64; // SHA-512 produces a 512-bit (64-byte) hash value
                }

                // Take the last 'hashLength' bytes
                signatureCheckBytes = Arrays.copyOfRange(signatureCheckBytes, signatureCheckBytes.length - hashLength, signatureCheckBytes.length);

                return java.util.Arrays.equals(certHash, signatureCheckBytes);
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return false;
        }
        return false;
    }

    public static void main(String[] args) {
        if (args.length < 3 || !args[0].equals("-format")) { // Prise en compte des arguments
            System.out.println("Usage: java ValidateCert -format <DER|PEM> <RCAfile, ICAfile, ..., LCAfile>");
            return;
        }

        String[] certFiles = new String[args.length - 2];

        // Initialiser certFiles à partir des arguments à partir du 3ème
        for (int i = 2; i < args.length; i++) {
            certFiles[i - 2] = args[i];
        }

        X509Certificate previousCertificate = null;
        String[] keyUsageStr = {
            "digitalSignature",
            "nonRepudiation",
            "keyEncipherment",
            "dataEncipherment",
            "keyAgreement",
            "keyCertSign",
            "cRLSign",
            "encipherOnly",
            "decipherOnly"
        };

        for (String certFile : certFiles) {
            System.out.println("\nValidating " + certFile);
            try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);

                PublicKey publicKey = x509Certificate.getPublicKey();

                if (previousCertificate == null) { // Si on est en train de valider la RCA
                    // Verfiication de la signature
                    System.out.println(" Validating signature...");
                    String sigAlgName = x509Certificate.getSigAlgName();
                    System.out.println("  Signature algorithm: " + sigAlgName);

                    if (sigAlgName.contains("RSA")) {
                        if (!verifyRSASignature(x509Certificate, x509Certificate)) {
                            System.out.println("Error: RSA signature verification failed.");
                            return;
                        } else {
                            System.out.println("  RSA signature verification successful.");
                        }
                    } else {
                        x509Certificate.verify(publicKey);
                    }

                    // Verification de l'issuer
                    System.out.println(" Validating issuer...");
                    X500Principal subject = x509Certificate.getSubjectX500Principal();
                    X500Principal issuer = x509Certificate.getIssuerX500Principal();
                    System.out.println("  Subject: " + subject);
                    System.out.println("  Issuer: " + issuer);
                    if (!subject.equals(issuer)) {
                        System.out.println("Error: Subject and issuer are not the same for the RCA.");
                        return;
                    }
                    
                } else {
                    // Verification de la signature
                    System.out.println(" Validating signature...");
                    PublicKey previousPublicKey = previousCertificate.getPublicKey();
                    String sigAlgName = x509Certificate.getSigAlgName();
                    System.out.println("  Signature algorithm: " + sigAlgName);

                    if (sigAlgName.contains("RSA")) {
                        if (!verifyRSASignature(x509Certificate, previousCertificate)) {
                            System.out.println("Error: RSA signature verification failed.");
                            return;
                        } else {
                            System.out.println("  RSA signature verification successful.");
                        }
                    } else {
                        x509Certificate.verify(previousPublicKey);
                    }

                    // Verification de l'issuer
                    System.out.println(" Validating issuer...");
                    X500Principal issuer = x509Certificate.getIssuerX500Principal();
                    X500Principal previousIssuer = previousCertificate.getSubjectX500Principal();
                    System.out.println("  Issuer: " + issuer);
                    System.out.println("  Previous issuer: " + previousIssuer);
                    if (!issuer.equals(previousIssuer)) {
                        System.out.println("Error: Issuer and previous issuer are not the same.");
                        return;
                    }
                }

                // On vérifie l'extension KeyUsage
                System.out.println(" Validating KeyUsage...");
                boolean[] keyUsage = x509Certificate.getKeyUsage();
                if (keyUsage != null) {
                    for (int i = 0; i < keyUsage.length; i++) {
                        if (keyUsage[i]) {
                            System.out.println("  " + keyUsageStr[i]);
                        }
                    }
                } else {
                    System.out.println(" No key usage information available.");
                }
                if (Objects.requireNonNull(keyUsage)[0] || keyUsage[5] || keyUsage[6]) {
                    System.out.println("  KeyUsage: Valid (Digital Signature, Key Encipherment, or Data Encipherment)");
                } else {
                    System.out.println("KeyUsage: Invalid");
                    return;
                }

                // On vérifie la validité du certificat
                System.out.println(" Validating validity...");
                x509Certificate.checkValidity();

                previousCertificate = x509Certificate;

            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                System.out.println("\nCertificate chain is invalid :/");
                return;
            }
        }
        System.out.println("\nCertificate chain is valid :)");
    }
}
