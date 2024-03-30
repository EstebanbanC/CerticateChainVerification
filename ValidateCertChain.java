import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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

        String[] certFilesLocation = listFiles("certs/expired");
//        String[] certFilesLocation = listFiles("certs/tbs");
//        String[] certFilesLocation = listFiles("certs/amazon");
//        String[] certFilesLocation = listFiles("certs/facebook");
        X509Certificate previousCertificate = null;
        keyUsageStr = new String[]{
                "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
                "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
        };
        Boolean[] checksResult = new Boolean[certFilesLocation.length];
        int i = 0;
        for (String certFile : certFilesLocation) {
            try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
                printCertInfo(x509Certificate, certFile);
                System.out.println("Checks :");

                var isLast = i == certFilesLocation.length - 1;

                boolean isKeyUsageValid = isKeyUsageValid(x509Certificate);
                boolean isSignatureValid = isSignatureValid(x509Certificate, previousCertificate);
                boolean isIssuerValid = isIssuerValid(x509Certificate, previousCertificate);
                boolean isBasicConstraintsValid = isBasicConstraintsValid(x509Certificate, isLast);
                boolean isRevocationStatusValid = isRevocationStatusValid(x509Certificate);

                if (isSignatureValid && isIssuerValid && isKeyUsageValid && isBasicConstraintsValid && isRevocationStatusValid) {
                    // Return an exception if the certificate is not valid
                    x509Certificate.checkValidity();
                    ConsoleColors.printlnInColor("Certificate is valid.", ConsoleColors.Color.GREEN, null);
                    checksResult[i] = true;
                } else {
                    checksResult[i] = false;
                }
                i++;
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

    private static boolean verifyECDSASignature(X509Certificate cert, X509Certificate issuerCert) {
        try {
            // Conversion des certificats en X509CertificateHolder de BouncyCastle
            X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());
            X509CertificateHolder issuerCertHolder = new X509CertificateHolder(issuerCert.getEncoded());

            // Extraction de la clé publique de l'émetteur
            SubjectPublicKeyInfo publicKeyInfo = issuerCertHolder.getSubjectPublicKeyInfo();
            ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) PublicKeyFactory.createKey(publicKeyInfo);

            // Création du fournisseur de vérification de contenu
            ContentVerifierProvider verifierProvider = new BcECContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder())
                    .build(publicKeyParams);

            // Vérification de la signature du certificat
            return certHolder.isSignatureValid(verifierProvider);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return false;
        }
    }

    private static boolean isSignatureValid(X509Certificate _cert, X509Certificate _issuerCert) {
        if (_issuerCert == null) {
            _issuerCert = _cert;
        }
        try {
            String sigAlgName = _cert.getSigAlgName();
            PublicKey issuerCertPublicKey = _issuerCert.getPublicKey();
            if (sigAlgName.contains("RSA")) {
                if (!verifyRSASignature(_cert, _issuerCert)) {
                    printlnError("Error: RSA signature verification failed.");
                    return false;
                } else {
                    printlnSuccess("Signature verified successfully.");
                    return true;
                }
            } else if (sigAlgName.contains("ECDSA")) {
                System.out.println("ECDSA signature verification");
                if (!verifyECDSASignature(_cert, _issuerCert)) {
                    printlnError("Error: ECDSA signature verification failed.");
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

    private static boolean isBasicConstraintsValid(X509Certificate _cert, Boolean isLast) {
        try {
            boolean isCA = _cert.getBasicConstraints() != -1;
            if (isCA || isLast) {
                printlnSuccess("BasicConstraints verified successfully.");
                return true;
            } else {
                printlnError("BasicConstraints is not valid.");
                return false;
            }
        } catch (Exception e) {
            printlnError("Error: " + e.getMessage());
            return false;
        }
    }

    private static boolean isRevocationStatusValid(X509Certificate cert) {
        try {
            // Vérification du statut de révocation en téléchargeant la CRL
            X509CRL crl = downloadCRL(cert);
            if (crl != null && crl.isRevoked(cert)) {
                printlnError("Certificate is revoked in CRL.");
                return false;
            }

            // Vérification du statut de révocation en utilisant le protocole OCSP (si disponible)
            if (isOCSPAvailable(cert)) {
                OCSPResp ocspResp = performOCSPRequest(cert);
                if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                    printlnError("OCSP response status is not successful.");
                    return false;
                }
                BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
                if (basicOCSPResp.getResponses()[0].getCertStatus() != CertificateStatus.GOOD) {
                    printlnError("Certificate is revoked in OCSP response.");
                    return false;
                }
            }

            // Mécanisme de cache pour éviter de télécharger une CRL si elle n'a pas été mise à jour
            if (isCRLCacheValid(cert, crl)) {
                printlnSuccess("CRL is up-to-date in cache.");
            } else {
                updateCRLCache(cert, crl);
            }

            printlnSuccess("Revocation status verified successfully.");
            return true;
        } catch (Exception e) {
            printlnError("Error: " + e.getMessage());
            return false;
        }
    }

    private static X509CRL downloadCRL(X509Certificate cert) throws Exception {
        // TODO: Implémenter le téléchargement de la CRL à partir de l'URL spécifiée dans le certificat
        // Retourner l'objet X509CRL téléchargé
        return null;
    }

    private static boolean isOCSPAvailable(X509Certificate cert) {
        // TODO: Vérifier si le certificat contient une extension OCSP
        // Retourner true si l'extension OCSP est présente, false sinon
        return false;
    }

    private static OCSPResp performOCSPRequest(X509Certificate cert) throws Exception {
        // TODO: Implémenter la requête OCSP en utilisant l'URL OCSP spécifiée dans le certificat
        // Retourner l'objet OCSPResp obtenu
        return null;
    }

    private static boolean isCRLCacheValid(X509Certificate cert, X509CRL crl) {
        // TODO: Vérifier si la CRL en cache est toujours valide pour le certificat donné
        // Retourner true si la CRL en cache est valide, false sinon
        return false;
    }

    private static void updateCRLCache(X509Certificate cert, X509CRL crl) {
        // TODO: Mettre à jour le cache de CRL avec la nouvelle CRL téléchargée pour le certificat donné
    }


}

