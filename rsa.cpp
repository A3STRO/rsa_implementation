#include "rsa.hpp"
#include <random>
#include <ctime>
#include <stdexcept>
#include <algorithm>
#include <numeric> // for std::accumulate
#include <functional> // for std::hash

RSA::RSA() : p(0), q(0), n(0), phi(0), d(0), e(0) {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
}

bool RSA::isPrime(long long num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;

    for (long long i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0)
            return false;
    }
    return true;
}

long long RSA::generatePrime() {
    long long num;
    do {
        num = std::rand() % 100 + 50;
    } while (!isPrime(num));
    return num;
}

long long RSA::gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

long long RSA::modInverse(long long a, long long m) {
    long long m0 = m;
    long long y = 0, x = 1;

    if (m == 1) return 0;

    while (a > 1) {
        long long q = a / m;
        long long t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0)
        x += m0;

    return x;
}

long long RSA::modPow(long long base, long long exponent, long long modulus) {
    if (modulus == 1) return 0;
    
    long long result = 1;
    base = base % modulus;
    
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;
        
        base = (base * base) % modulus;
        exponent = exponent >> 1;
    }
    return result;
}

void RSA::generateKeys() {
    p = generatePrime();
    do {
        q = generatePrime();
    } while (q == p);

    n = p * q;
    phi = (p - 1) * (q - 1);

    e = 65537;
    while (gcd(e, phi) != 1) {
        e++;
    }

    d = modInverse(e, phi);
}

std::pair<long long, long long> RSA::getPublicKey() const {
    return std::make_pair(e, n);
}

std::pair<long long, long long> RSA::getPrivateKey() const {
    return std::make_pair(d, n);
}

std::vector<long long> RSA::encrypt(const std::string& message, const std::pair<long long, long long>& publicKey) {
    std::vector<long long> ciphertext;
    long long e = publicKey.first;
    long long n = publicKey.second;

    for (char c : message) {
        long long encrypted = modPow(static_cast<long long>(c), e, n);
        ciphertext.push_back(encrypted);
    }

    return ciphertext;
}

std::string RSA::decrypt(const std::vector<long long>& ciphertext, const std::pair<long long, long long>& privateKey) {
    std::string message;
    long long d = privateKey.first;
    long long n = privateKey.second;

    for (long long c : ciphertext) {
        long long decrypted = modPow(c, d, n);
        message += static_cast<char>(decrypted);
    }

    return message;
}

void RSA::registerUser(const std::string& username) {
    if (findUser(username) != nullptr) {
        throw std::runtime_error("User already exists");
    }

    generateKeys();
    
    User newUser;
    newUser.name = username;
    newUser.publicKey = getPublicKey();
    newUser.privateKey = getPrivateKey();
    
    users.push_back(newUser);
}

User* RSA::findUser(const std::string& username) {
    auto it = std::find_if(users.begin(), users.end(),
        [&username](const User& user) { return user.name == username; });
    
    if (it != users.end()) {
        return &(*it);
    }
    return nullptr;
}

// New method to sign a message using private key
std::vector<long long> RSA::sign(const std::string& message, const std::pair<long long, long long>& privateKey) {
    // Simple hash: sum of chars mod 256 (for demonstration)
    unsigned long long hash = 0;
    for (char c : message) {
        hash = (hash + static_cast<unsigned char>(c)) % 256;
    }
    // Convert hash to string
    std::string hashStr = std::to_string(hash);
    // Encrypt hash string with private key
    return encrypt(hashStr, privateKey);
}

// New method to verify a signature using public key
bool RSA::verify(const std::string& message, const std::vector<long long>& signature, const std::pair<long long, long long>& publicKey) {
    // Decrypt signature to get hash string
    std::string decryptedHashStr = decrypt(signature, publicKey);
    // Compute hash of message
    unsigned long long hash = 0;
    for (char c : message) {
        hash = (hash + static_cast<unsigned char>(c)) % 256;
    }
    std::string computedHashStr = std::to_string(hash);
    // Compare
    return decryptedHashStr == computedHashStr;
}
