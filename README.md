# RSA Encryption Implementation

A simple implementation of RSA encryption in C++ for educational purposes. This project demonstrates the basic concepts of RSA encryption, including key generation, message encryption, and decryption using public-private key pairs.

## Features

- User registration with automatic RSA key pair generation
- Direct encryption using public key components
- Direct decryption using private key components
- User management system with key display
- Simple command-line interface
- Diffie-Hellman key exchange for secure shared secret generation
- Digital signature creation and manual verification using RSA keys

## Building the Project

### Prerequisites
- C++ compiler with C++17 support
- CMake (version 3.10 or higher)

### Build Instructions

You can build the project directly using g++ without CMake:

```bash
g++ main.cpp rsa.cpp dh.cpp -o rsa_app
```

Then run the program:

```bash
./rsa_app
```

## Usage

After building, run the program:
```bash
./rsa_demo
```

The program provides a menu-driven interface with the following options:

1. Register new user
   - Creates a new user with automatically generated RSA key pair
   - Displays the generated public and private keys
   - Keys are stored for future reference

2. List registered users
   - Displays all registered users
   - Shows each users public key (e,n) and private key (d,n)
   - Useful for copying keys for encryption/decryption

3. Encrypt a message
   - Enter the public key components (e n)
   - Enter the message to encrypt
   - Displays the encrypted message as space-separated numbers

4. Decrypt a message
   - Enter the private key components (d n)
   - Enter the encrypted message as space-separated numbers
   - Displays the decrypted original message

5. Perform Diffie-Hellman Key Exchange
   - Generates Diffie-Hellman keys
   - Displays your public key
   - Prompts for the other party's public key
   - Computes and displays the shared secret

6. Sign a message
   - Enter your private key components (d n)
   - Enter the message to sign
   - Displays the digital signature as space-separated numbers

7. Verify a digital signature (manual input)
   - Enter the original message
   - Enter the signature as space-separated numbers
   - Enter the sender's public key components (e n)
   - Displays whether the signature verification was successful or failed

8. Exit
   - Exits the program

## Implementation Details

This implementation uses:
- Small prime numbers for demonstration purposes
- Basic modular arithmetic operations
- Simple random number generation
- Direct key component input for encryption/decryption
- Diffie-Hellman key exchange with fixed small prime and base (for demonstration)
- RSA digital signature creation by signing a simple hash of the message
- Manual signature verification by comparing decrypted signature hash with computed hash

Note: This is a basic implementation for educational purposes and should not be used for actual secure communications. Production systems should use:
- Larger prime numbers
- Secure random number generation
- Proper padding schemes
- Established cryptographic libraries

## Example Usage

```
=== RSA Encryption System ===
1. Register new user
2. List registered users
3. Encrypt a message
4. Decrypt a message
5. Perform Diffie-Hellman Key Exchange
6. Sign a message
7. Verify a digital signature (manual input)
8. Exit
Choose an option: 1

Enter username to register: Alice
User "Alice" registered successfully.

Choose an option: 2
Registered Users and Their Keys:

User: Alice
Public Key (e,n): (65537,12091)
Private Key (d,n): (1601,12091)
----------------------------------------

Choose an option: 3
Enter public key for encryption (e n): 65537 12091
Enter message to encrypt: Hello

Encrypted message (numeric values):
4768 2005 4709 4709 3285

Choose an option: 4
Enter private key for decryption (d n): 1601 12091
Enter encrypted message (space-separated numbers):
4768 2005 4709 4709 3285

Decrypted message: Hello
```

## Security Note

This implementation is for educational purposes only. For real-world applications, use established cryptographic libraries that:
- Use cryptographically secure random number generation
- Implement proper padding schemes
- Use appropriate key sizes
- Handle edge cases and security concerns

## License

This project is open source and available for educational purposes.
