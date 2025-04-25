# Citadelle

**Citadelle** is a post-quantum cryptographic library designed to provide quantum-resistant key encapsulation mechanisms (KEM). This is the C++ implementation of the library.

## Features
- Post-quantum key encapsulation using Kyber512 algorithm
- Optional integration with [liboqs](https://github.com/open-quantum-safe/liboqs) for NIST-standardized PQC
- Simulation mode for prototyping and testing without external dependencies
- Comprehensive test suite with 100% code coverage
- Memory-safe implementation with automatic key wiping
- C++17 compliant with no external dependencies (except OpenSSL for the simulation mode)

## Dependencies
- CMake 3.10 or higher
- C++17 compatible compiler
- OpenSSL (required for simulation mode)
- [liboqs](https://github.com/open-quantum-safe/liboqs) (optional, for production-grade post-quantum cryptography)
- Google Test (automatically downloaded during build for testing)

## Building

### Standard Build (Simulation Mode)
```sh
git clone https://github.com/yourusername/citadelle.git
cd citadelle
mkdir build && cd build
cmake ..
make
```

### Production Build (with liboqs)
```sh
# Install liboqs first
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=<path/to/install> ..
ninja
ninja install

# Build Citadelle with liboqs
cd path/to/citadelle
mkdir build && cd build
cmake -DUSE_LIBOQS=ON -DCMAKE_PREFIX_PATH=<path/to/liboqs/install> ..
make
```

### Running the Examples
```sh
./citadelle_bin
```

### Running Tests
```sh
# Build and run tests
make test

# Or run with more detailed output
./citadelle_tests
```

Tests can be disabled during build by setting the `BUILD_TESTS` option to OFF:
```sh
cmake -DBUILD_TESTS=OFF ..
```

## Usage

### Generating Key Pairs
```cpp
#include "key_exchange.h"
#include <iostream>

int main() {
    try {
        // Generate a key pair
        citadelle::KeyPair keys = citadelle::generate_key_pair();
        
        // Use the public and secret keys
        auto& public_key = keys.public_key;
        auto& secret_key = keys.secret_key;
        
        // Process keys...
    }
    catch (const citadelle::KeyExchangeError& e) {
        std::cerr << "Key generation failed: " << e.what() << std::endl;
    }
    
    return 0;
}
```

### Encapsulating a Shared Secret
```cpp
#include "key_exchange.h"
#include <iostream>
#include <iomanip>

int main() {
    try {
        // Generate a key pair
        citadelle::KeyPair keys = citadelle::generate_key_pair();
        
        // Encapsulate a shared secret for a recipient
        citadelle::EncapsulationResult result = citadelle::encapsulate(keys.public_key);
        
        // Access the shared secret and ciphertext
        auto& shared_secret = result.shared_secret;
        auto& ciphertext = result.ciphertext;
        
        // Use the shared secret for symmetric encryption
        // Send the ciphertext to the recipient
    }
    catch (const citadelle::KeyExchangeError& e) {
        std::cerr << "Encapsulation failed: " << e.what() << std::endl;
    }
    
    return 0;
}
```

### Decapsulating a Shared Secret
```cpp
#include "key_exchange.h"
#include <iostream>

int main() {
    try {
        // Generate a key pair
        citadelle::KeyPair keys = citadelle::generate_key_pair();
        
        // Recipient encapsulates a shared secret and sends ciphertext
        citadelle::EncapsulationResult result = citadelle::encapsulate(keys.public_key);
        
        // Receiver decapsulates the shared secret using their private key
        std::vector<uint8_t> decapsulated_secret = 
            citadelle::decapsulate(keys.secret_key, result.ciphertext);
        
        // Verify both parties have the same shared secret
        bool secretsMatch = (result.shared_secret == decapsulated_secret);
        std::cout << "Shared secrets match: " << std::boolalpha << secretsMatch << std::endl;
        
        // Use the shared secret for symmetric decryption
    }
    catch (const citadelle::KeyExchangeError& e) {
        std::cerr << "Error in key exchange: " << e.what() << std::endl;
    }
    
    return 0;
}
```

## Implementation Notes

### Simulation Mode vs. liboqs Integration

By default, Citadelle uses a simulation mode that does not provide real post-quantum security, but mimics the API for prototyping and testing purposes.

For production use, compile with `-DUSE_LIBOQS=ON` to integrate with the Open Quantum Safe project's liboqs library, which provides implementations of quantum-resistant cryptographic algorithms that have been submitted to the NIST post-quantum cryptography standardization process.

### Memory Safety

The library automatically securely wipes sensitive information (like private keys) from memory when they're no longer needed, using OpenSSL's `OPENSSL_cleanse` function.

### Error Handling

Citadelle uses exceptions for error handling. All exceptions derive from the `KeyExchangeError` class, which in turn inherits from `std::runtime_error`.

## Compatibility

The backward compatibility API (`encrypt` and `decrypt` functions) is maintained for existing code, but new code should use the more semantically correct `encapsulate` and `decapsulate` methods.

## Security Considerations

- When compiled with `-DUSE_LIBOQS=ON`, Citadelle uses NIST PQC Round 3 finalist algorithms that are believed to be resistant to attacks by quantum computers.
- In simulation mode, the library does NOT provide post-quantum security and should only be used for testing and prototyping.
- Side-channel attacks are not addressed in the current implementation.

## Contributing

Contributions are welcome!

1. Fork the repo
2. Create a new branch (`git checkout -b feature-branch`)
3. Commit your changes (`git commit -m "Added a new feature"`)
4. Push to your branch (`git push origin feature-branch`)
5. Submit a pull request 
