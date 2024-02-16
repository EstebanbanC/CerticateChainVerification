import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class ValidateCert {
    public static void main(String[] args) {
        if (args.length != 3 || !args[0].equals("-format")) { // Prise en compte des arguments
            System.out.println("Usage: java ValidateCert -format <DER|PEM> <certFile>");
            return;
        }

        String format = args[1];
        String certFile = args[2];

        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate;

            if (format.equalsIgnoreCase("DER")) { // Prise en compte du format, mais inutile car le PEM est décodé automatiquement
                x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            } else if (format.equalsIgnoreCase("PEM")) {
                x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            } else {
                System.out.println("Error: Invalid format specified, use DER or PEM");
                return;
            }

            PublicKey publicKey = x509Certificate.getPublicKey(); // On récupère la clé publique du certificat
            x509Certificate.verify(publicKey); // On vérifie la signature du certificat avec sa clé publique

            // On affiche les informations du certificat
            System.out.println("Subject: " + x509Certificate.getSubjectX500Principal());
            System.out.println("Issuer: " + x509Certificate.getIssuerX500Principal());

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

            boolean[] keyUsage = x509Certificate.getKeyUsage();
            if (keyUsage != null) {
                for (int i = 0; i < keyUsage.length; i++) {
                    if (keyUsage[i]) {
                        System.out.println(keyUsageStr[i]);
                    }
                }
            } else {
                System.out.println("No key usage information available.");
            }
            
            // On vérifie l'extension KeyUsage
            if (Objects.requireNonNull(keyUsage)[0] || keyUsage[5] || keyUsage[6]) {
                System.out.println("KeyUsage: Valid (Digital Signature, Key Encipherment, or Data Encipherment)");
            } else {
                System.out.println("KeyUsage: Invalid");
                
            }

            // On vérifie la validité du certificat
            x509Certificate.checkValidity();
            System.out.println("Certificate is valid");

            // On vérifie la signature du certificat
            String sigAlgName = x509Certificate.getSigAlgName();
            System.out.println("Signature algorithm: " + sigAlgName);

            // On extrait la signature
            byte[] signature = x509Certificate.getSignature();

            // On vérifie la signature avec l'API cryptographique
            Signature sig = Signature.getInstance(sigAlgName);
            sig.initVerify(publicKey);
            sig.update(x509Certificate.getTBSCertificate()); // TBSCertificate is the part of the certificate that is signed

            if (sig.verify(signature)) {
                System.out.println("Signature verification successful");
            } else {
                System.out.println("Signature verification failed");
            }


        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
