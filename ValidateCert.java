import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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

            PublicKey publicKey = x509Certificate.getPublicKey();
            x509Certificate.verify(publicKey);

            System.out.println("Certificate is valid");
            System.out.println("Subject: " + x509Certificate.getSubjectX500Principal());
            System.out.println("Issuer: " + x509Certificate.getIssuerX500Principal());

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
