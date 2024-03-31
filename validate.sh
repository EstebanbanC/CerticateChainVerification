#!/bin/bash
javac ConsoleColors.java
java -classpath ".:libs/bcpkix-jdk15on-1.70.jar:libs/bcprov-jdk15on-1.70.jar:libs/bcutil-jdk15on-1.70.jar" ValidateCertChain.java $1 $2 $3 $4 $5

# Path: validate.sh
rm -f *.class