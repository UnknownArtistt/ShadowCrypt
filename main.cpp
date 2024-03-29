#include <iostream>
#include <vector>
#include <string>
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <limits>
#include <string.h>
#include "PasswordManager.h"

using namespace std;

/*
This function receives the master password that has enter the user and creates a file for the password library.
It also writes the master password in the first line to verify in the future that the user has access to the passwords.
*/
void createNewPasswordLibrary(const std::string& masterPassword) {

    std::string filePath; // variable for the password library

    std::cout << "Enter the file path to store the password library: ";
    std::getline(std::cin, filePath); // we ask for the path where we are going to create the library

    std::ofstream file(filePath); // creates an output stream in write mode to write the content
    if (file.is_open()) { // we check if the file has been opened correctly
        file << masterPassword << std::endl; // we write the master password
        file.close(); // we close the file
        std::cout << "New library created successfully!" << std::endl; 
    } else { // error handler
        std::cout << "Failed to create the new library, please check the path and try again..." << std::endl;
    }
}

/*
This function receives a reference to PasswordManager object and a constant reference of a string that would be the 
path of the password library. The function verifies if the master password is correct and it prints all the 
passwords of the library.
*/
void listPasswords(PasswordManager& passwordManager, const std::string& filePath) {

    std::string masterPassword;
    
    std::ifstream file(filePath); // creates an intput stream in lecture mode to read the content
    if (file.is_open()) {
        std::getline(file, masterPassword); // we read the master password
        passwordManager.setMasterPassword(masterPassword); // we set the master password

        std::string line;
        while (std::getline(file, line)) { // we read one line
            if (!line.empty()) { // we verify is the current line is empty
                size_t delimiterPos = line.find(":"); // we delimit the : to read between the account name and password
                if (delimiterPos != std::string::npos) {
                    std::string accountName = line.substr(0, delimiterPos); // we read the account name
                    std::string password = line.substr(delimiterPos + 1); // we read the password
                    passwordManager.addPassword(Password(accountName, password)); // we add the password to the list
                }
            }
        }

        file.close(); // we close the file
        
    } else {
        std::cout << "Failed to open the password library file." << std::endl; // error handler
        return;
    }
    
    std::string userMasterPassword;
    std::cout << "Enter the master password: ";
    std::getline(std::cin, userMasterPassword); // we read the guess of the master password from the user

    if (passwordManager.authenticateUser(userMasterPassword)) { // we verify if the master password is correct

        std::vector<Password> passwordList = passwordManager.getPasswordList(); // we get the password list 
        if (passwordList.empty()) { // we verify if the list is empty
            std::cout << "No passwords found in the library." << std::endl; 
        } else {
            std::cout << "\nPasswords in the library:\n" << std::endl;
            for (const auto& password : passwordList) { // we iterate the password list
                std::cout << "Account: " << password.getName() << ", Password: " << password.getPassword() << std::endl; // we print the password
            }
        }

    } else {
        std::cout << "Invalid master password. Access denied." << std::endl; // error handler
    }
}

void addNewPassword(PasswordManager& passwordManager, const std::string& filePath) {

    std::string masterPassword;
    
    std::ifstream file(filePath); // creates an intput stream in lecture mode to read the content
    if (file.is_open()) { // verifies if the file was opened correctly
        std::getline(file, masterPassword); // we read the master password
        file.close(); // we close the file
        passwordManager.setMasterPassword(masterPassword); // we set the master password
    } else {
        std::cout << "Failed to open the password library file." << std::endl; // error handler
        return;
    }
    
    std::string userMasterPassword;
    std::cout << "Enter the master password: ";
    std::getline(std::cin, userMasterPassword); // we read the guess of the master password from the user

    if (passwordManager.authenticateUser(userMasterPassword)) { // we verify if the guess is correct
        std::string accountName, newPassword;

        std::cout << "Enter the account name: ";
        std::getline(std::cin, accountName); // we ask for the account name

        newPassword = passwordManager.generateSecurePassword(12); // we generate a safe password, always with a length of 12 characters

        Password password(accountName, newPassword); // we create a Password object setting both parameters

        passwordManager.addPassword(password); // we add the password to the list

        std::ofstream file(filePath, std::ios::app); // creates an output stream in write mode to write the content
        if (file.is_open()) { // we verify if the file has been opened correctly
            file << std::endl << accountName << ":" << newPassword; // we write the account name and new password to the library
            file.close(); // we close the file
            std::cout << "Password added successfully!" << std::endl; // success message
        } else {
            std::cout << "Failed to open the password library file." << std::endl; // error handler
        }

    } else {
        std::cout << "Invalid master password. Access denied." << std::endl; // invalid access handler
    }

}

int main() {

    // variable declarations
    std::string filePath;
    int option;
    bool repeat = true;
    std::string masterPassword;
    PasswordManager passwordManager;

    while (repeat) {

        // we print the main menu
        std::cout << "----------------------------------------------------------------------------------------------------------------------------------------------\n";
        std::string asciiArt = 
        "                                                                               .___ \n"                            
        "_____   __  _  __ ______  _____     ______  ________  _  __  ____  _______   __| _/   _____  _____     ____  _____      ____    ____  _______\n"
        "\\__  \\  \\ \\/ \\/ / \\____ \\ \\__  \\   /  ___/ /  ___/\\ \\/ \\/ / /  _ \\ \\_  __ \\ / __ |   /     \\ \\__  \\   /    \\ \\__  \\    / ___\\ _/ __ \\ \\_  __ \\ \n"
        " / __ \\_ \\     /  |  |_> > / __ \\_ \\___ \\  \\___ \\  \\     / (  <_> ) |  | \\// /_/ |  |  Y Y  \\ / __ \\_|   |  \\ / __ \\_ / /_/  >\\  ___/  |  | \\/\n"
        "(____  /  \\/\\_/   |   __/ (____  //____  >/____  >  \\/\\_/   \\____/  |__|   \\____ |  |__|_|  /(____  /|___|  /(____  / \\___  /  \\___  > |__|\n"   
        "     \\/           |__|         \\/      \\/      \\/                               \\/        \\/      \\/      \\/      \\/ /_____/       \\/\n\n";
        std::cout << asciiArt;
        std::cout << "Terminal Based Password Manager                                                                                                By AbyssWatcher\n";
        std::cout << "----------------------------------------------------------------------------------------------------------------------------------------------\n";
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