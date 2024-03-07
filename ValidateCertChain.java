import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

public class ValidateCertChain {

    static String[] keyUsageStr;


    public static void main(String[] args) {
        // Vérification des arguments
//        if (args.length < 3 || !args[0].equals("-format") || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
//            System.out.println("[i] Usage: java ValidateCert -format <DER|PEM> <RCAfile, ICAfile, ..., LCAfile>");
//            return;
//        }
//
//        String[] certFilesLocation = getCertsFilesLocationFromArgs(args);

//        ArrayList<String> argsList = new ArrayList<>();
//        argsList.add(0, "-format");
//        argsList.add(1, "DER");
//        int index = 1;
//        argsList.add(++index, "certs/1_System_Trust_USERTrust_ECC_Certification_Authority.pem");
//        argsList.add(++index, "certs/2_Sectigo_ECC_Extended_Validation Secure_Server_CA.pem");
//        argsList.add(++index, "certs/3_www.tbs-certificates.co.pem");

//        String[] certFilesLocation = listFiles("certs/expired");
        String[] certFilesLocation = listFiles("certs/tbs");


        X509Certificate previousCertificate = null;
        keyUsageStr = new String[]{
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
        Boolean[] checksResult = new Boolean[certFilesLocation.length];

        int i = 0;
        for (String certFile : certFilesLocation) {
            try (FileInputStream fileInputStream = new FileInputStream(certFile)) {

                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);

                printCertInfo(x509Certificate, certFile);

                System.out.println("Checks :");


                boolean isSignatureValid = isSignatureValid(x509Certificate, previousCertificate);
                boolean isIssuerValid = isIssuerValid(x509Certificate, previousCertificate);
                boolean isKeyUsageValid = isKeyUsageValid(x509Certificate);

                if (isSignatureValid && isIssuerValid && isKeyUsageValid) {
                    // Return an exception if the certificate is not valid
                    x509Certificate.checkValidity();
                    ConsoleColors.printlnInColor("Certificate is valid.", ConsoleColors.Color.GREEN, null);
                    checksResult[i] = true;
                } else {
                    checksResult[i] = false;
                }


                previousCertificate = x509Certificate;


            } catch (Exception e) {
                printlnError("Error: " + e.getMessage());
                checksResult[i] = false;
            }
            System.out.println();
        }

        ConsoleColors.printInColor("Result :", ConsoleColors.Color.PURPLE, ConsoleColors.BackgroundColor.BLACK);
        if (Arrays.asList(checksResult).contains(false)) {
            ConsoleColors.printlnBlinkInColor(" Certificate chain is not valid :(", ConsoleColors.Color.RED, null);
        } else {
            ConsoleColors.printlnBlinkInColor(" Certificate chain is valid :)", ConsoleColors.Color.GREEN, null);
        }
    }

    // =================================================================================
    // Utilitaires
    public static String[] listFiles(String directoryPath) {
        File directory = new File(directoryPath);
        File[] files = directory.listFiles();
        List<String> fileNames = new ArrayList<>();
        if (files != null) {
            Arrays.sort(files); // Sort the files in alphabetical order
            for (File file : files) {
                if (file.isFile()) {
                    fileNames.add(file.getPath());
                }
            }
        }
        return fileNames.toArray(new String[0]);
    }

    private static String[] getCertsFilesLocationFromArgs(String[] _args) {
        String[] certFiles = new String[_args.length - 2];

        System.arraycopy(_args, 2, certFiles, 0, _args.length - 2);

        return certFiles;
    }

    private static void printlnError(String message) {
        ConsoleColors.printInColor("\t❌ ", ConsoleColors.Color.RED, null);
        System.out.println(message);
    }

    private static void printlnSuccess(String message) {
        ConsoleColors.printInColor("\t✅ ", ConsoleColors.Color.GREEN, null);
        System.out.println(message);
    }

    // =================================================================================
    private static void printCertInfo(X509Certificate _cert, String _certFileLocation) {
        String certFileName = _certFileLocation.substring(_certFileLocation.lastIndexOf('/') + 1);

        ConsoleColors.printInColor("Certificate information for ", ConsoleColors.Color.WHITE, ConsoleColors.BackgroundColor.BLACK);
        ConsoleColors.printInColor(certFileName, ConsoleColors.Color.YELLOW, ConsoleColors.BackgroundColor.BLACK);
        ConsoleColors.printlnInColor(" :", ConsoleColors.Color.WHITE, ConsoleColors.BackgroundColor.BLACK);

        System.out.println("\t  Issuer : " + _cert.getIssuerX500Principal());
        System.out.println("\t Subject : " + _cert.getSubjectX500Principal());
        System.out.println("\tValidity : From " + _cert.getNotBefore() + " to " + _cert.getNotAfter());
    }

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

    private static boolean isSignatureValid(X509Certificate _cert, X509Certificate _issuerCert) {
        if (_issuerCert == null) {
            _issuerCert = _cert;
        }
        try {
            String sigAlgName = _cert.getSigAlgName();
            PublicKey issuerCertPublicKey = _issuerCert.getPublicKey();

            if (sigAlgName.contains("RSA")) {
                System.out.println("RSA signature verification");
                if (!verifyRSASignature(_cert, _issuerCert)) {
                    printlnError("Error: RSA signature verification failed.");
                    return false;
                } else {
                    printlnSuccess("Signature verified successfully.");
                    return true;
                }
            } else {
                _cert.verify(issuerCertPublicKey);
                printlnSuccess("Signature verified successfully.");
                return true;
            }

        } catch (Exception e) {
            printlnError("Error: " + e.getMessage());
            return false;
        }
    }

    private static boolean isIssuerValid(X509Certificate _cert, X509Certificate previousCertificate) {
        if (previousCertificate == null) {
            previousCertificate = _cert;
        }
        try {
            X500Principal issuer = _cert.getIssuerX500Principal();
            X500Principal previousIssuer = previousCertificate.getSubjectX500Principal();
            if (!issuer.equals(previousIssuer)) {
                printlnError("Error: Issuer and previous issuer are not the same.");
                return false;
            }
        } catch (Exception e) {
            printlnError("Error : " + e.getMessage());
            return false;
        }
        printlnSuccess("Issuer verified successfully.");
        return true;
    }

    private static Boolean isKeyUsageValid(X509Certificate _cert) {
        boolean[] keyUsage;
        try {
            keyUsage = _cert.getKeyUsage();
        } catch (Exception e) {
            printlnError("Error: " + e.getMessage());
            return false;
        }

        if (keyUsage == null) {
            printlnError(" No key usage information available.");
            return false;
        }

        try {
            if (Objects.requireNonNull(keyUsage)[0] || keyUsage[5] || keyUsage[6]) {
                printlnSuccess("KeyUsage verified successfully.");
                return true;
            } else {
                printlnError("KeyUsage is not valid.");
                return false;
            }
        } catch (NullPointerException e) {
            printlnError("Error: " + e.getMessage());
            return false;
        }
    }


}
