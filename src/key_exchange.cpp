#include "key_exchange.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <memory>
#include <iostream>

#ifdef CITADELLE_USE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace citadelle {

// Constants for Kyber512 (for post-quantum security)
constexpr size_t KYBER_PUBLIC_KEY_SIZE = 800;
constexpr size_t KYBER_SECRET_KEY_SIZE = 1632;
constexpr size_t KYBER_CIPHERTEXT_SIZE = 768;
constexpr size_t KYBER_SHARED_SECRET_SIZE = 32;

// Custom deleters for OpenSSL objects
struct OsslDeleter {
    void operator()(EVP_PKEY* ptr) { EVP_PKEY_free(ptr); }
    void operator()(EVP_PKEY_CTX* ptr) { EVP_PKEY_CTX_free(ptr); }
    void operator()(EVP_MD_CTX* ptr) { EVP_MD_CTX_free(ptr); }
};

#ifdef CITADELLE_USE_LIBOQS
// Custom deleter for OQS objects
struct OqsDeleter {
    void operator()(OQS_KEM* ptr) { OQS_KEM_free(ptr); }
};
using OqsKemPtr = std::unique_ptr<OQS_KEM, OqsDeleter>;
#endif

// Smart pointer types for OpenSSL resources
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, OsslDeleter>;

// Helper to get OpenSSL error message
std::string get_openssl_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "Unknown error";
    return ERR_error_string(err, nullptr);
}

// Securely wipe memory containing sensitive information
void secure_wipe(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
    }
}

// This is a placeholder function that would be replaced by liboqs implementation
// In a real implementation, this would be:
// KeyPair generate_key_pair() {
//     OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
//     if (kem == nullptr) {
//         throw KeyExchangeError("Failed to initialize Kyber-512 KEM");
//     }
//
//     KeyPair keys;
//     keys.public_key.resize(kem->length_public_key);
//     keys.secret_key.resize(kem->length_secret_key);
//
//     OQS_STATUS rc = OQS_KEM_keypair(kem, keys.public_key.data(), keys.secret_key.data());
//     if (rc != OQS_SUCCESS) {
//         OQS_KEM_free(kem);
//         throw KeyExchangeError("Failed to generate Kyber key pair: " + std::to_string(rc));
//     }
//
//     OQS_KEM_free(kem);
//     return keys;
// }

KeyPair generate_key_pair() {
#ifdef CITADELLE_USE_LIBOQS
    // Initialize the OQS KEM for Kyber512
    OqsKemPtr kem(OQS_KEM_new(OQS_KEM_alg_kyber_512), &OqsDeleter::operator());
    if (!kem) {
        throw KeyExchangeError("Failed to initialize Kyber-512 KEM");
    }

    KeyPair keys;
    keys.public_key.resize(kem->length_public_key);
    keys.secret_key.resize(kem->length_secret_key);

    OQS_STATUS rc = OQS_KEM_keypair(kem.get(), keys.public_key.data(), keys.secret_key.data());
    if (rc != OQS_SUCCESS) {
        secure_wipe(keys.public_key);
        secure_wipe(keys.secret_key);
        throw KeyExchangeError("Failed to generate Kyber key pair: " + std::to_string(rc));
    }

    return keys;
#else
    // This is a simulation only - would be replaced with real PQC implementation
    KeyPair keys;
    keys.public_key.resize(kyber::PUBLIC_KEY_SIZE);
    keys.secret_key.resize(kyber::SECRET_KEY_SIZE);
    
    if (RAND_bytes(keys.public_key.data(), kyber::PUBLIC_KEY_SIZE) != 1) {
        std::string err_msg = "Failed to generate random public key: " + get_openssl_error();
        throw KeyExchangeError(err_msg);
    }
    
    if (RAND_bytes(keys.secret_key.data(), kyber::SECRET_KEY_SIZE) != 1) {
        secure_wipe(keys.public_key);
        std::string err_msg = "Failed to generate random secret key: " + get_openssl_error();
        throw KeyExchangeError(err_msg);
    }
    
    return keys;
#endif
}

// This is a placeholder function that would be replaced by liboqs implementation
// In a real implementation, this would be:
// EncapsulationResult encapsulate(const std::vector<uint8_t>& public_key) {
//     // Validate input
//     if (public_key.empty()) {
//         throw KeyExchangeError("Public key cannot be empty");
//     }
//
//     OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
//     if (kem == nullptr) {
//         throw KeyExchangeError("Failed to initialize Kyber-512 KEM");
//     }
//
//     if (public_key.size() != kem->length_public_key) {
//         OQS_KEM_free(kem);
//         throw KeyExchangeError("Invalid public key size: expected " + 
//                               std::to_string(kem->length_public_key) + 
//                               " bytes, got " + 
//                               std::to_string(public_key.size()) + 
//                               " bytes");
//     }
//
//     EncapsulationResult result;
//     result.shared_secret.resize(kem->length_shared_secret);
//     result.ciphertext.resize(kem->length_ciphertext);
//
//     OQS_STATUS rc = OQS_KEM_encaps(kem, 
//                                   result.ciphertext.data(), 
//                                   result.shared_secret.data(), 
//                                   public_key.data());
//     if (rc != OQS_SUCCESS) {
//         OQS_KEM_free(kem);
//         throw KeyExchangeError("Failed to encapsulate shared secret: " + std::to_string(rc));
//     }
//
//     OQS_KEM_free(kem);
//     return result;
// }

EncapsulationResult encapsulate(const std::vector<uint8_t>& public_key) {
    // Check for empty keys
    if (public_key.empty()) {
        throw KeyExchangeError("Public key cannot be empty");
    }
    
#ifdef CITADELLE_USE_LIBOQS
    // Initialize the OQS KEM for Kyber512
    OqsKemPtr kem(OQS_KEM_new(OQS_KEM_alg_kyber_512), &OqsDeleter::operator());
    if (!kem) {
        throw KeyExchangeError("Failed to initialize Kyber-512 KEM");
    }
    
    // Check for exact size match
    if (public_key.size() != kem->length_public_key) {
        throw KeyExchangeError("Invalid public key size: expected " + 
                              std::to_string(kem->length_public_key) + 
                              " bytes, got " + 
                              std::to_string(public_key.size()) + 
                              " bytes");
    }
    
    EncapsulationResult result;
    result.shared_secret.resize(kem->length_shared_secret);
    result.ciphertext.resize(kem->length_ciphertext);
    
    OQS_STATUS rc = OQS_KEM_encaps(kem.get(), 
                                 result.ciphertext.data(), 
                                 result.shared_secret.data(), 
                                 public_key.data());
    if (rc != OQS_SUCCESS) {
        secure_wipe(result.shared_secret);
        throw KeyExchangeError("Failed to encapsulate shared secret: " + std::to_string(rc));
    }
    
    return result;
#else
    // Check for exact size match
    if (public_key.size() != kyber::PUBLIC_KEY_SIZE) {
        throw KeyExchangeError("Invalid public key size: expected " + 
                               std::to_string(kyber::PUBLIC_KEY_SIZE) + 
                               " bytes, got " + 
                               std::to_string(public_key.size()) + 
                               " bytes");
    }
    
    // In a real implementation, this would use actual Kyber encapsulation
    EncapsulationResult result;
    result.shared_secret.resize(kyber::SHARED_SECRET_SIZE);
    result.ciphertext.resize(kyber::CIPHERTEXT_SIZE);
    
    // Generate a random shared secret and ciphertext
    if (RAND_bytes(result.shared_secret.data(), kyber::SHARED_SECRET_SIZE) != 1) {
        std::string err_msg = "Failed to generate shared secret: " + get_openssl_error();
        throw KeyExchangeError(err_msg);
    }
    
    if (RAND_bytes(result.ciphertext.data(), kyber::CIPHERTEXT_SIZE) != 1) {
        secure_wipe(result.shared_secret);
        std::string err_msg = "Failed to generate ciphertext: " + get_openssl_error();
        throw KeyExchangeError(err_msg);
    }
    
    return result;
#endif
}

// This is a placeholder function that would be replaced by liboqs implementation
// In a real implementation, this would be:
// std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& ciphertext) {
//     // Check for empty inputs
//     if (secret_key.empty()) {
//         throw KeyExchangeError("Secret key cannot be empty");
//     }
//     
//     if (ciphertext.empty()) {
//         throw KeyExchangeError("Ciphertext cannot be empty");
//     }
//     
//     OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
//     if (kem == nullptr) {
//         throw KeyExchangeError("Failed to initialize Kyber-512 KEM");
//     }
//     
//     // Check for exact size match
//     if (secret_key.size() != kem->length_secret_key) {
//         OQS_KEM_free(kem);
//         throw KeyExchangeError("Invalid secret key size: expected " + 
//                               std::to_string(kem->length_secret_key) + 
//                               " bytes, got " + 
//                               std::to_string(secret_key.size()) + 
//                               " bytes");
//     }
//     
//     if (ciphertext.size() != kem->length_ciphertext) {
//         OQS_KEM_free(kem);
//         throw KeyExchangeError("Invalid ciphertext size: expected " + 
//                               std::to_string(kem->length_ciphertext) + 
//                               " bytes, got " + 
//                               std::to_string(ciphertext.size()) + 
//                               " bytes");
//     }
//     
//     std::vector<uint8_t> shared_secret(kem->length_shared_secret);
//     
//     OQS_STATUS rc = OQS_KEM_decaps(kem, 
//                                   shared_secret.data(), 
//                                   ciphertext.data(), 
//                                   secret_key.data());
//     
//     if (rc != OQS_SUCCESS) {
//         secure_wipe(shared_secret);
//         OQS_KEM_free(kem);
//         throw KeyExchangeError("Failed to decapsulate shared secret: " + std::to_string(rc));
//     }
//     
//     OQS_KEM_free(kem);
//     return shared_secret;
// }

std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& ciphertext) {
    // Check for empty keys or ciphertext
    if (secret_key.empty()) {
        throw KeyExchangeError("Secret key cannot be empty");
    }
    
    if (ciphertext.empty()) {
        throw KeyExchangeError("Ciphertext cannot be empty");
    }
    
#ifdef CITADELLE_USE_LIBOQS
    // Initialize the OQS KEM for Kyber512
    OqsKemPtr kem(OQS_KEM_new(OQS_KEM_alg_kyber_512), &OqsDeleter::operator());
    if (!kem) {
        throw KeyExchangeError("Failed to initialize Kyber-512 KEM");
    }
    
    // Check for exact size match
    if (secret_key.size() != kem->length_secret_key) {
        throw KeyExchangeError("Invalid secret key size: expected " + 
                              std::to_string(kem->length_secret_key) + 
                              " bytes, got " + 
                              std::to_string(secret_key.size()) + 
                              " bytes");
    }
    
    if (ciphertext.size() != kem->length_ciphertext) {
        throw KeyExchangeError("Invalid ciphertext size: expected " + 
                              std::to_string(kem->length_ciphertext) + 
                              " bytes, got " + 
                              std::to_string(ciphertext.size()) + 
                              " bytes");
    }
    
    std::vector<uint8_t> shared_secret(kem->length_shared_secret);
    
    OQS_STATUS rc = OQS_KEM_decaps(kem.get(), 
                                 shared_secret.data(), 
                                 ciphertext.data(), 
                                 secret_key.data());
    
    if (rc != OQS_SUCCESS) {
        secure_wipe(shared_secret);
        throw KeyExchangeError("Failed to decapsulate shared secret: " + std::to_string(rc));
    }
    
    return shared_secret;
#else
    // Check for exact size match
    if (secret_key.size() != kyber::SECRET_KEY_SIZE) {
        throw KeyExchangeError("Invalid secret key size: expected " + 
                               std::to_string(kyber::SECRET_KEY_SIZE) + 
                               " bytes, got " + 
                               std::to_string(secret_key.size()) + 
                               " bytes");
    }
    
    if (ciphertext.size() != kyber::CIPHERTEXT_SIZE) {
        throw KeyExchangeError("Invalid ciphertext size: expected " + 
                               std::to_string(kyber::CIPHERTEXT_SIZE) + 
                               " bytes, got " + 
                               std::to_string(ciphertext.size()) + 
                               " bytes");
    }
    
    // In a simulation, we'll generate a shared secret based on inputs
    // This is NOT what real Kyber does, but is used for demonstration
    
    std::vector<uint8_t> shared_secret(kyber::SHARED_SECRET_SIZE);
    
    // Create and initialize message digest context with proper error handling
    MdCtxPtr md_ctx(EVP_MD_CTX_new(), &OsslDeleter::operator());
    if (!md_ctx) {
        throw KeyExchangeError("Failed to create message digest context: " + get_openssl_error());
    }
    
    if (EVP_DigestInit_ex(md_ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw KeyExchangeError("Failed to initialize digest: " + get_openssl_error());
    }
    
    if (EVP_DigestUpdate(md_ctx.get(), secret_key.data(), secret_key.size()) != 1) {
        throw KeyExchangeError("Failed to update digest with secret key: " + get_openssl_error());
    }
    
    if (EVP_DigestUpdate(md_ctx.get(), ciphertext.data(), ciphertext.size()) != 1) {
        throw KeyExchangeError("Failed to update digest with ciphertext: " + get_openssl_error());
    }
    
    unsigned int digest_len = kyber::SHARED_SECRET_SIZE;
    if (EVP_DigestFinal_ex(md_ctx.get(), shared_secret.data(), &digest_len) != 1) {
        secure_wipe(shared_secret);
        throw KeyExchangeError("Failed to finalize digest: " + get_openssl_error());
    }
    
    return shared_secret;
#endif
}

} // namespace citadelle 