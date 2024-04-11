#!/bin/bash

# Pauses the script if there is an error
set -e

echo "Verifying and installing the dependencies..."

# Verifies if g++ is installed
if ! command -v g++ &> /dev/null; then
    echo "g++ is not installed. Installing it..."
    sudo apt-get update
    sudo apt-get install g++ -y
else
    echo "g++ already installed"
fi

# Verifies is cryptopp is installed
if ! ldconfig -p | grep -q libcryptopp; then
    echo "crypto++ is not installed. Installing it..."
    sudo apt-get update
    sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils -y
else
    echo "crypto++ already installed"
fi

# Verifies if figlet is installed
if ! command -v figlet &> /dev/null; then
    echo "figlet is not installed. Installing it..."
    sudo apt-get update
    sudo apt-get install figlet -y
else
    echo "figlet already installed"
fi

echo
echo "All dependencies installed"
echo

echo "Compiling the program..."
# Make sure to put the proper names of files and compiling flags 
g++ -o AWPasswordManager main.cpp PasswordManager.cpp -lcryptopp
echo "Compilation finished"
echo

echo "Executing AW Password Manager..."
./AWPasswordManager
