#ifndef RSA_HPP
#define RSA_HPP

#include <string>
#include <vector>

struct User {
    std::string name;
    std::pair<long long, long long> publicKey;
    std::pair<long long, long long> privateKey;
};

class RSA {
private:
    long long p;
    long long q;
    long long n;
    long long phi;
    long long d;
    long long e;
    
    std::vector<User> users;

    bool isPrime(long long num);
    long long generatePrime();
    long long modInverse(long long a, long long m);
    long long gcd(long long a, long long b);
    long long modPow(long long base, long long exponent, long long modulus);

public:
    RSA();
    void generateKeys();
    std::pair<long long, long long> getPublicKey() const;
    std::pair<long long, long long> getPrivateKey() const;
    void registerUser(const std::string& username);
    User* findUser(const std::string& username);
    const std::vector<User>& getUsers() const { return users; }
    std::vector<long long> encrypt(const std::string& message, const std::pair<long long, long long>& publicKey);
    std::string decrypt(const std::vector<long long>& ciphertext, const std::pair<long long, long long>& privateKey);

    // New methods for digital signature
    std::vector<long long> sign(const std::string& message, const std::pair<long long, long long>& privateKey);
    bool verify(const std::string& message, const std::vector<long long>& signature, const std::pair<long long, long long>& publicKey);
};

#endif
