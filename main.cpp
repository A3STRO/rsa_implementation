#include "rsa.hpp"
#include "dh.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <limits>
#include <sstream>
#include <vector>

void printMenu() {
    std::cout << "\n=== RSA Encryption System ===\n"
              << "1. Register new user\n"
              << "2. List registered users\n"
              << "3. Encrypt a message\n"
              << "4. Decrypt a message\n"
              << "5. Perform Diffie-Hellman Key Exchange\n"
              << "6. Sign a message\n"
              << "7. Verify a digital signature (manual input)\n"
              << "8. Exit\n"
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
    DiffieHellman dh;

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
                    dh.generateKeys();
                    std::cout << "\nDiffie-Hellman keys generated.\n";
                    std::cout << "Public Key: " << dh.getPublicKey() << "\n";

                    std::cout << "Enter other party's public key: ";
                    uint64_t otherPublicKey;
                    std::cin >> otherPublicKey;
                    std::cin.ignore();

                    uint64_t sharedSecret = dh.computeSharedSecret(otherPublicKey);
                    std::cout << "Computed shared secret: " << sharedSecret << "\n";
                    break;
                }
                case 6: {
                    std::cout << "\nEnter private key for signing (d n): ";
                    long long d, n;
                    std::cin >> d >> n;
                    std::cin.ignore();

                    std::cout << "Enter message to sign: ";
                    std::string message;
                    std::getline(std::cin, message);

                    std::vector<long long> signature = rsa.sign(message, std::make_pair(d, n));
                    std::cout << "Signature (numeric values): ";
                    for (auto val : signature) {
                        std::cout << val << " ";
                    }
                    std::cout << "\n";
                    break;
                }
                case 7: {
                    std::cout << "\nManual Digital Signature Verification\n";

                    std::cout << "Enter message: ";
                    std::string message;
                    std::getline(std::cin, message);

                    std::cout << "Enter signature (space-separated numbers): ";
                    std::string sigInput;
                    std::getline(std::cin, sigInput);
                    std::vector<long long> signature;
                    std::istringstream sigStream(sigInput);
                    long long val;
                    while (sigStream >> val) {
                        signature.push_back(val);
                    }

                    std::cout << "Enter sender's public key (e n): ";
                    long long e, n;
                    std::cin >> e >> n;
                    std::cin.ignore();

                    bool verified = rsa.verify(message, signature, std::make_pair(e, n));
                    if (verified) {
                        std::cout << "Signature verification SUCCESSFUL.\n";
                    } else {
                        std::cout << "Signature verification FAILED.\n";
                    }
                    break;
                }
                case 8: {
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
