#include "PasswordManager.h"
#include <random>

Password::Password(const std::string& name, const std::string& password)
    : name(name), password(password) {}

std::string Password::getName() const {
    return name;
}

std::string Password::getPassword() const {
    return password;
}

PasswordManager::PasswordManager() : masterPassword(""), passwordList() {}

bool PasswordManager::authenticateUser(const std::string& password) {
    return password == masterPassword;
}

std::string PasswordManager::generateSecurePassword(int length) {
    static const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+,.;:[]{}\\|/<>?¿-'~\"";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, static_cast<int>(characters.size() - 1));

    std::string password;
    password.reserve(length);
    for (int i = 0; i < length; ++i) {
        password.push_back(characters[dis(gen)]);
    }
    return password;
}

void PasswordManager::addPassword(const Password& password) {
    passwordList.push_back(password);
}

std::vector<Password> PasswordManager::getPasswordList() const {
    return passwordList;
}

std::string PasswordManager::getMasterPassword() const {
    return masterPassword;
}

void PasswordManager::setMasterPassword(const std::string& password) {
    masterPassword = password;
}

void PasswordManager::clearPasswordList() {
    passwordList.clear();
}