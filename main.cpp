#include "rsa.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <limits>
#include <sstream>

void printMenu() {
    std::cout << "\n=== RSA Encryption System ===\n"
              << "1. Register new user\n"
              << "2. List registered users\n"
              << "3. Encrypt a message\n"
              << "4. Decrypt a message\n"
              << "5. Exit\n"
              << "Choose an option: ";
}

void displayKeys(const std::pair<long long, long long>& publicKey, 
                const std::pair<long long, long long>& privateKey) {
    std::cout << "\nPublic Key (e,n): (" << publicKey.first << "," << publicKey.second << ")\n"
              << "Private Key (d,n): (" << privateKey.first << "," << privateKey.second << ")\n";
}

void displayEncrypted(const std::vector<long long>& ciphertext) {
    std::cout << "\nEncrypted message (numeric values):\n";
    for (const auto& num : ciphertext) {
        std::cout << num << " ";
    }
    std::cout << "\n";
}

int main() {
    RSA rsa;

    while (true) {
        printMenu();
        int choice;
        std::cin >> choice;
        std::cin.ignore();

        try {
            switch (choice) {
                case 1: {
                    std::cout << "\nEnter username to register: ";
                    std::string username;
                    std::getline(std::cin, username);
                    
                    rsa.registerUser(username);
                    std::cout << "\nUser \"" << username << "\" registered successfully.\n";
                    break;
                }
                case 2: {
                    std::cout << "\nRegistered Users and Their Keys:\n";
                    auto users = rsa.getUsers();
                    if (users.empty()) {
                        std::cout << "No users registered yet.\n";
                    } else {
                        for (const auto& user : users) {
                            std::cout << "\nUser: " << user.name << "\n";
                            std::cout << "Public Key (e,n): (" 
                                    << user.publicKey.first << "," 
                                    << user.publicKey.second << ")\n";
                            std::cout << "Private Key (d,n): (" 
                                    << user.privateKey.first << "," 
                                    << user.privateKey.second << ")\n";
                            std::cout << "----------------------------------------\n";
                        }
                    }
                    break;
                }
                case 3: {
                    std::cout << "\nEnter public key for encryption (e n): ";
                    long long e, n;
                    std::cin >> e >> n;
                    std::cin.ignore();
                    
                    std::cout << "Enter message to encrypt: ";
                    std::string message;
                    std::getline(std::cin, message);
                    
                    std::vector<long long> encrypted = rsa.encrypt(message, std::make_pair(e, n));
                    displayEncrypted(encrypted);
                    break;
                }
                case 4: {
                    std::cout << "\nEnter private key for decryption (d n): ";
                    long long d, n;
                    std::cin >> d >> n;
                    std::cin.ignore();
                    
                    std::cout << "Enter encrypted message (space-separated numbers):\n";
                    std::string input;
                    std::getline(std::cin, input);
                    
                    std::vector<long long> encrypted;
                    std::istringstream iss(input);
                    long long num;
                    while (iss >> num) {
                        encrypted.push_back(num);
                    }
                    
                    std::string decrypted = rsa.decrypt(encrypted, std::make_pair(d, n));
                    std::cout << "\nDecrypted message: " << decrypted << "\n";
                    break;
                }
                case 5: {
                    std::cout << "\nExiting program. Goodbye!\n";
                    return 0;
                }
                default: {
                    std::cout << "\nInvalid option. Please try again.\n";
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::cout << "\nError: " << e.what() << "\n";
        }
    }

    return 0;
}
