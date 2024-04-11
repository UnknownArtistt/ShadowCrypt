#include <iostream>
#include <vector>
#include <string>
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <limits>
#include <string.h>
#include "PasswordManager.h"
#include <cstdlib>
#include <random>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>

using namespace std;
using namespace CryptoPP;

namespace CryptoPP {
    typedef unsigned char byte;
}

/* This function receives a constant reference of the password that is going to be encrypted and the encryption key.
Then uses the CryptoPP library to encrypt the password using a CBC Mode filter. To make the encryption
a text, a key and the iv is needed. The first two parameters are being send in the calling and the iv is being
generate considering the blocksize of encryption. 
*/
std::string encryptPassword(const std::string& password, const std::string& key) {

    std::string cypherText;
    std::string iv;

    try {

        CryptoPP::AutoSeededRandomPool prng; // generate a random seed

        iv.resize(CryptoPP::AES::BLOCKSIZE); // we fix the iv to the blocksize
        prng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(iv.data()), iv.size()); // generates the block

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption; // we set the encryption mode CBC Mode in this case
        encryption.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data())); // we pass the arguments

        // Encoding
        CryptoPP::StringSource(password, true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(cypherText)
                )
            )
        );

        cypherText = iv + cypherText;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error encrypting: " << e.what() << std::endl;
    }

    return cypherText;
}

/* This function makes the opposite operation and decrypts a password. It gets two constant references to the password to decrypt and the key. */
std::string decryptPassword(const std::string& cypherWithIV, const std::string& key) {

    std::string decryptedText;
    std::string iv = cypherWithIV.substr(0, CryptoPP::AES::BLOCKSIZE); // we get the iv from the encrypted password
    std::string cypherText = cypherWithIV.substr(CryptoPP::AES::BLOCKSIZE); // we get the password itself (encrypted)

    try {

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption; // we set the decryption mode
        decryption.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data())); // we pass the arguments

        // Decoding
        CryptoPP::StringSource(cypherText, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StreamTransformationFilter(decryption,
                    new CryptoPP::StringSink(decryptedText)
                )
            )
        );

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error decrypting: " << e.what() << std::endl;
    }

    return decryptedText;

}

/* This function receives the length of the salt that is going to be generate . This salt will be the half part 
of the encryption/decryption passphrase. 
*/
std::string generateSalt(size_t length) {
    // we set the charset to generate the salt
    const char charset[] = 
        "1234567890"
        "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
        "abcdefghijklmnñopqrstuvwxyz";

    std::string result;
    result.reserve(length);

    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    for (size_t i = 0; i < length; i++) {
        result += charset[dist(rng)];
    }

    return result;
}

/*
This function receives the master password that has enter the user and creates a file for the password library.
It also writes the master password in the first line to verify in the future that the user has access to the passwords.
Before the master password is written in the library it generate a salt and encrypts the master password.
*/
void createNewPasswordLibrary(const std::string& masterPassword) {

    std::string filePath; // variable for the password library

    std::cout << "Enter the file path to store the password library: ";
    std::getline(std::cin, filePath); // we ask for the path where we are going to create the library

    std::string salt = generateSalt(16); // we call the function to generate a salt

    std::string key = salt + masterPassword; // we generate the key for the encryption

    std::string encryptedMPassword = encryptPassword(masterPassword, key); // we encrypt the master password

    std::ofstream file(filePath); // creates an output stream in write mode to write the content
    if (file.is_open()) { // we check if the file has been opened correctly
        file << encryptedMPassword << std::endl; // we write the master password
        file << salt << std::endl; // we write the salt
        file.close(); // we close the file
        std::cout << "New library created successfully!" << std::endl; 
    } else { // error handler
        std::cout << "Failed to create the new library, please check the path and try again..." << std::endl;
    }
}

/*
This function receives a reference to PasswordManager object and a constant reference of a string that would be the 
path of the password library. The function verifies if the master password is correct and it prints all the 
passwords of the library. Before the passwords are shown each password (including the master password in the verification) 
is being decrypted to be readable.
*/
void listPasswords(PasswordManager& passwordManager, const std::string& filePath) {

    std::ifstream file(filePath); // we open the password library
    if (!file.is_open()) { // we verify if the library has been opened correctly
        std::cout << "Failed to open the password library file." << std::endl; // error handler
        return;
    }

    std::string encryptedMasterPassword, salt;
    std::getline(file, encryptedMasterPassword); // We read the encrypted master password
    std::getline(file, salt); // We read the salt

    std::string userMasterPassword;
    std::cout << "Enter the master password: ";
    std::getline(std::cin, userMasterPassword); // We ask for the master password to the user
    
    std::string key = salt + userMasterPassword; // We build the key for encryption/decryption

    // We decrypt the master password calling the decrypt function, we pass the encrypted master password and the key
    std::string decryptedMasterPassword = decryptPassword(encryptedMasterPassword, key);

    // We verify if the user choice of the master password if correct to give the access
    if (userMasterPassword != decryptedMasterPassword) { 
        std::cout << "Invalid master password. Access denied." << std::endl; // Access denied
        return;
    }

    // We read each password of the library
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            size_t delimiterPos = line.find(":"); // We chop the account name and password
            if (delimiterPos != std::string::npos) {
                std::string accountName = line.substr(0, delimiterPos); // We set the account name
                std::string encryptedPassword = line.substr(delimiterPos + 1); // We set the password

                // Decryption of the password
                std::string decryptedPassword = decryptPassword(encryptedPassword, key);
                // We show the account names and the passwords
                std::cout << "Account: " << accountName << ", Password: " << decryptedPassword << std::endl;
            }
        }
    }

    file.close(); // We close the file
}

/* This function generates a secure and random password, encrypts it and writes in the password library. 
The function receives a constant reference to a PasswordManager object and the filepath of the library. */
void addNewPassword(PasswordManager& passwordManager, const std::string& filePath) {

    std::string encryptedMasterPassword, salt; // Variable declarations
    
    // We open the library to read the master password and the salt
    std::ifstream file(filePath);
    if (file.is_open()) {
        std::getline(file, encryptedMasterPassword); // We read the encrypted master password 
        std::getline(file, salt); // We read the salt
        file.close(); // We close the file
    } else {
        std::cout << "Failed to open the password library file." << std::endl; // error handler
        return;
    }
    
    std::string userMasterPassword;
    std::cout << "Enter the master password: ";
    std::getline(std::cin, userMasterPassword); // We read the users guess for the master password
    
    // We build the encryption/decryption key
    std::string key = salt + userMasterPassword;
    
    // We decrypt the master password to compare it and give access
    std::string decryptedMasterPassword = decryptPassword(encryptedMasterPassword, key);
    
    // We compare the master password and if it is correct we give access
    if (userMasterPassword == decryptedMasterPassword) {
        std::string accountName, newPassword;

        std::cout << "Enter the account name: ";
        std::getline(std::cin, accountName); // We ask for the account name for the new password

        newPassword = passwordManager.generateSecurePassword(12); // We generate a secure and random password

        // We encrypt the new password
        std::string encryptedPassword = encryptPassword(newPassword, key);

        // We open the password library to write the encrypted new password
        std::ofstream file(filePath, std::ios::app);
        if (file.is_open()) {
            file << std::endl << accountName << ":" << encryptedPassword; // We write the content (account name and encrypted password)
            file.close();
            std::cout << "Password added successfully!" << std::endl;
        } else {
            std::cout << "Failed to open the password library file." << std::endl; // Error handler
        }

    } else {
        std::cout << "Invalid master password. Access denied." << std::endl; // Access denied
    }
}

/* This function executes a figlet command to generate a ascii art, this ascii art is the respective banner of the program. */
void generateBanner() {
    std::cout << "\n--------------------------------------------------------------------------------\n";
    system("figlet -f slant -c aw password manager\n"); // Execution of the figlet command
    std::cout << "\n                        [+] Coded By AbyssWatcher [+]\n";
    std::cout << "--------------------------------------------------------------------------------\n";
}

int main() {

    // variable declarations
    std::string filePath;
    int option;
    bool repeat = true;
    std::string masterPassword;
    PasswordManager passwordManager;

    while (repeat) {

        generateBanner(); // we print the banner of the program using figlet
        // we print the options
        std::cout << "\nWelcome to AW Password Manager" << std::endl;
        std::cout << "----------------------------------";
        std::cout << "\n1) Create a new Password Library" << std::endl;
        std::cout << "2) See your passwords" << std::endl;
        std::cout << "3) Create a new password" << std::endl;
        std::cout << "4) Exit\n" << std::endl;
        std::cout << "----------------------------------\n";
        std::cout << "Enter your option: ";
        std::cin >> option;                                                 // read the user's option
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // clear the input buffer after reading a numerical value with std::cin, ignore the content after the newline \n

        // a switch to manage each option
        switch (option) {

        case 1:
            std::cout << "Enter a master password for your new password library: "; // We ask for a master password for the new library
            std::getline(std::cin, masterPassword); // we get the master password from the user
            createNewPasswordLibrary(masterPassword); // we call to the function
            break;

        case 2:
            passwordManager.clearPasswordList();
            std::cout << "Enter the path of the password library: "; // we ask for the path of the password library
            std::getline(std::cin, filePath); // we get the file path from the user
            listPasswords(passwordManager, filePath); // we call to the function
            break;

        case 3:
            passwordManager.clearPasswordList();
            std::cout << "Enter the path of the password library: "; // we ask for the path of the password library
            std::getline(std::cin, filePath); // we get the file path from the user
            addNewPassword(passwordManager, filePath); // we call to the function
            break;

        case 4:
            std::cout << "Thank you for using AW Password Manager! See you later!" << std::endl; // goodbye message
            repeat = false;                                                                // break the while loop to end execution
            return 0;
        
        default: // default case
            break;
        }
    }
}