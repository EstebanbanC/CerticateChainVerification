#!/bin/bash

javac ConsoleColors.java

# Step 1: Compile your Java files into bytecode
javac -cp ".:libs/bcprov-jdk15to18-177.jar:libs/bcpkix-jdk15to18-177.jar" ValidateCertChain.java

# Step 2: Create a manifest file
echo "Main-Class: ValidateCertChain" > manifest.txt

# Step 3: Package your compiled classes and the manifest file into a JAR file
jar cvfm ValidateCertChain.jar manifest.txt .

# Clean up the manifest file
rm manifest.txt

java -jar ValidateCertChain.jar