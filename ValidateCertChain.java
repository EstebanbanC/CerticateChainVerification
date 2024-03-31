import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class ValidateCertChain {

    static String[] keyUsageStr;


    public static void main(String[] args) {
        // Vérification des arguments
        if (args.length < 3 || !args[0].equals("-format") || (!args[1].equals("DER") && !args[1].equals("PEM"))) {
            System.out.println("[i] Usage: java ValidateCert -format <DER|PEM> <RCAfile, ICAfile, ..., LCAfile>");
            return;
        }

        String[] certFilesLocation = getCertsFilesLocationFromArgs(args);

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

                boolean isSignatureValid = isSignatureValid(x509Certificate, previousCertificate);
                boolean isKeyUsageValid = isKeyUsageValid(x509Certificate);
                boolean isIssuerValid = isIssuerValid(x509Certificate, previousCertificate);
                boolean isBasicConstraintsValid = isBasicConstraintsValid(x509Certificate, isLast);

                // Problème de avec la librarie BouncyCastle
                // On ne prends pas en compte ce paramètre vu que le code ne fonctionne pas
                boolean isRevocationStatusValid = isRevocationStatusValid(x509Certificate);

                if (isSignatureValid && isIssuerValid && isKeyUsageValid && isBasicConstraintsValid) {
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

                // Déchiffrement de la signature pour obtenir le hash
                BigInteger signatureCheck = signature.modPow(exponent, modulus);

                // Calcul du hash du TBSCertificate
                String sigAlg = cert.getSigAlgName();
                String hashAlgorithm = getHashAlgorithm(sigAlg);
                if (hashAlgorithm == null) {
                    System.out.println("Algorithme de hachage non pris en charge : " + sigAlg);
                    return false;
                }

                MessageDigest crypt = MessageDigest.getInstance(hashAlgorithm);
                crypt.update(cert.getTBSCertificate());
                byte[] certHash = crypt.digest();

                byte[] signatureCheckBytes = signatureCheck.toByteArray();
                int hashLength = certHash.length;

                // Prendre les 'hashLength' derniers octets
                signatureCheckBytes = Arrays.copyOfRange(signatureCheckBytes, signatureCheckBytes.length - hashLength, signatureCheckBytes.length);

                return java.util.Arrays.equals(certHash, signatureCheckBytes);
            }
        } catch (Exception e) {
            System.out.println("Erreur : " + e.getMessage());
            return false;
        }
        return false;
    }

    private static String getHashAlgorithm(String sigAlg) {
        if (sigAlg.contains("SHA1")) {
            return "SHA-1";
        } else if (sigAlg.contains("SHA256")) {
            return "SHA-256";
        } else if (sigAlg.contains("SHA384")) {
            return "SHA-384";
        } else if (sigAlg.contains("SHA512")) {
            return "SHA-512";
        }
        return null;
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

    private static X509CRL downloadCRL(X509Certificate cert) {
        try {
            String crlURL = null;
            byte[] crlDistributionPointsExtensionValue = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (crlDistributionPointsExtensionValue != null) {
                ASN1Primitive asn1Primitive = ASN1Primitive.fromByteArray(crlDistributionPointsExtensionValue);
                if (asn1Primitive instanceof ASN1OctetString octetString) {
                    asn1Primitive = ASN1Primitive.fromByteArray(octetString.getOctets());
                }
                CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asn1Primitive);
                DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();
                if (distributionPoints != null && distributionPoints.length > 0) {
                    DistributionPointName dpn = distributionPoints[0].getDistributionPoint();
                    if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralNames generalNames = (GeneralNames) dpn.getName();
                        GeneralName[] names = generalNames.getNames();
                        for (GeneralName generalName : names) {
                            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                crlURL = generalName.getName().toString();
                                break;
                            }
                        }
                    }
                }
            }
            if (crlURL != null) {
                URL url = new URL(crlURL);
                InputStream crlStream = url.openStream();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
                crlStream.close();
                return crl;
            }
            return null;
        } catch (Exception e) {
            printlnError("Error: " + e.getMessage());
            return null;
        }
    }

    private static boolean isOCSPAvailable(X509Certificate cert) {
        try {
            byte[] ocspExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (ocspExtensionValue != null) {
                AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ASN1Primitive.fromByteArray(ocspExtensionValue));
                AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
                for (AccessDescription accessDescription : accessDescriptions) {
                    if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            printlnError("Error: " + e.getMessage());
        }
        return false;
    }

    private static OCSPResp performOCSPRequest(X509Certificate cert) {
        try {
            String ocspURL = null;
            byte[] ocspExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (ocspExtensionValue != null) {
                AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ASN1Primitive.fromByteArray(ocspExtensionValue));
                AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
                for (AccessDescription accessDescription : accessDescriptions) {
                    if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                        GeneralName generalName = accessDescription.getAccessLocation();
                        if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            ocspURL = generalName.getName().toString();
                            break;
                        }
                    }
                }
            }
            if (ocspURL != null) {
                OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();

                // Convertir X500Principal en X500Name
                X500Principal x500Principal = cert.getIssuerX500Principal();
                X500Name x500Name = new X500Name(x500Principal.getName());

                // Créer un X509CertificateHolder à partir du X500Name
                X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x500Name.getEncoded());

                CertificateID certId = new CertificateID((DigestCalculator) CertificateID.HASH_SHA1, x509CertificateHolder, cert.getSerialNumber());
                ocspReqBuilder.addRequest(certId);
                OCSPReq ocspReq = ocspReqBuilder.build();
                byte[] ocspReqBytes = ocspReq.getEncoded();
                URL url = new URL(ocspURL);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod("POST");
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream os = con.getOutputStream();
                os.write(ocspReqBytes);
                os.flush();
                os.close();
                InputStream in = con.getInputStream();
                OCSPResp ocspResp = new OCSPResp(in);
                in.close();
                return ocspResp;
            }
        } catch (Exception e) {
            printlnError("Error (PerformOCSPRequest): " + e.getMessage());
        }
        return null;
    }

    private static boolean isCRLCacheValid(X509Certificate cert, X509CRL crl) {
        if (crl != null) {
            Date now = new Date();
            Date nextUpdate = crl.getNextUpdate();
            if (nextUpdate != null && now.before(nextUpdate)) {
                return true;
            }
        }
        return false;
    }

    private static void updateCRLCache(X509Certificate cert, X509CRL crl) {
        // Implémenter la logique de mise à jour du cache de CRL
        // Par exemple, stocker la CRL dans une map avec le certificat comme clé
        // Vous pouvez également gérer l'expiration du cache et le supprimer si nécessaire
    }


}

