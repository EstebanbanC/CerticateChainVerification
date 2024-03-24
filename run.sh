#!/bin/bash
javac ConsoleColors.java
java -cp ".:libs/bcprov-jdk15to18-177.jar:libs/bcpkix-jdk15to18-177.jar" ValidateCertChain.java

# Path: run.sh
rm -f *.class