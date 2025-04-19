#ifndef DH_HPP
#define DH_HPP

#include <cstdint>

class DiffieHellman {
private:
    uint64_t prime;
    uint64_t base;
    uint64_t privateKey;
    uint64_t publicKey;

    uint64_t modExp(uint64_t base, uint64_t exponent, uint64_t modulus) const;

public:
    DiffieHellman();
    void generateKeys();
    uint64_t getPublicKey() const;
    uint64_t computeSharedSecret(uint64_t otherPublicKey) const;
};

#endif
