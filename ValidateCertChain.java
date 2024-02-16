import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

public class ValidateCertChain {
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
                    x509Certificate.verify(publicKey);

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
                    x509Certificate.verify(previousPublicKey);

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
