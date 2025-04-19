#include "dh.hpp"
#include <random>
#include <ctime>

DiffieHellman::DiffieHellman() : prime(0), base(0), privateKey(0), publicKey(0) {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
}

uint64_t DiffieHellman::modExp(uint64_t base, uint64_t exponent, uint64_t modulus) const {
    uint64_t result = 1;
    base = base % modulus;

    while (exponent > 0) {
        if (exponent & 1)
            result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}

void DiffieHellman::generateKeys() {
    // Use a fixed prime and base for simplicity (could be improved)
    prime = 23;  // small prime for demonstration, replace with large prime in real use
    base = 5;

    privateKey = std::rand() % (prime - 2) + 1;  // private key in [1, prime-2]
    publicKey = modExp(base, privateKey, prime);
}

uint64_t DiffieHellman::getPublicKey() const {
    return publicKey;
}

uint64_t DiffieHellman::computeSharedSecret(uint64_t otherPublicKey) const {
    return modExp(otherPublicKey, privateKey, prime);
}
