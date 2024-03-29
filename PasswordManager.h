#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <iostream>
#include <string>
#include <vector>

class Password {
private:
    std::string name;
    std::string password;

public:
    Password(const std::string& name, const std::string& password);
    std::string getName() const;
    std::string getPassword() const;
};

class PasswordManager {
private:
    std::string masterPassword;
    std::vector<Password> passwordList;

public:
    PasswordManager();
    bool authenticateUser(const std::string& password);
    std::string generateSecurePassword(int length);
    void addPassword(const Password& password);
    std::vector<Password> getPasswordList() const;
    std::string getMasterPassword() const;
    void setMasterPassword(const std::string& password);
    void clearPasswordList();  
};

#endif // PASSWORD_MANAGER_H