# Vérification de la Chaîne de Certificats

## Auteurs

- [CRISPEL Esteban](https://github.com/EstebanbanC)
- [DEVAUX Baptiste](https://github.com/Brazok)

## Attention

Une erreur survient lors de la vérification de l'OCSP. Nous n'avons pas réussi à résoudre cette erreur, donc nous ne la prenons pas en compte, mais nous l'affichons quand même.

## Exécution

### ValidateCert

```bash
java ValidateCert -format <DER|PEM> <certFile>
```

### ValidateCertChain

```bash
javac ConsoleColors.java
java -classpath ".:libs/bcpkix-jdk15on-1.70.jar:libs/bcprov-jdk15on-1.70.jar:libs/bcutil-jdk15on-1.70.jar" ValidateCertChain.java -format <DER|PEM> <RCAfile, ICAfile, ..., LCAfile>
```

Ou

```bash
chmod +x validate.sh
./validate.sh -format <DER|PEM> <RCAfile, ICAfile, ..., LCAfile>
```

## Remarques

Dans le dossier `certs` se trouvent les certificats utilisés pour les tests : 
- Amazon 
- Facebook
- TBS
- un certificat expiré

### Exemple

```bash
./validate.sh -format DER "certs/tbs/1_Authority.pem" "certs/tbs/2_Server_CA.pem" "certs/tbs/3_www.tbs-certificates.co.pem"
```