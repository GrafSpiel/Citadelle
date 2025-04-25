#ifndef CITADELLE_KEY_EXCHANGE_H
#define CITADELLE_KEY_EXCHANGE_H

#include <vector>
#include <string>
#include <stdexcept>
#include <array>

namespace citadelle {

/**
 * @brief Exception class for key exchange errors
 */
class KeyExchangeError : public std::runtime_error {
public:
    explicit KeyExchangeError(const std::string& message) : std::runtime_error(message) {}
};

/**
 * @brief Constants for Kyber512 key sizes
 * These values match the official NIST Kyber specification
 */
namespace kyber {
    constexpr size_t PUBLIC_KEY_SIZE = 800;
    constexpr size_t SECRET_KEY_SIZE = 1632;
    constexpr size_t CIPHERTEXT_SIZE = 768;
    constexpr size_t SHARED_SECRET_SIZE = 32;
}

/**
 * @brief Struct representing a Kyber key pair
 */
struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

/**
 * @brief Struct representing a Kyber encapsulation result
 */
struct EncapsulationResult {
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> ciphertext;
};

/**
 * @brief Generates a Kyber512-equivalent key pair (public key, secret key).
 * 
 * @return A KeyPair containing public_key and secret_key as byte vectors
 * @throws KeyExchangeError if key generation fails
 */
KeyPair generate_key_pair();

/**
 * @brief Encapsulates a shared secret using the given public key.
 * 
 * @param public_key The public key bytes
 * @return An EncapsulationResult containing shared_secret and ciphertext
 * @throws KeyExchangeError if encapsulation fails
 */
EncapsulationResult encapsulate(const std::vector<uint8_t>& public_key);

/**
 * @brief Decapsulates a shared secret using the given secret key and ciphertext.
 * 
 * @param secret_key The secret key bytes
 * @param ciphertext The ciphertext bytes
 * @return The shared secret as bytes
 * @throws KeyExchangeError if decapsulation fails
 */
std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& ciphertext);

// For backward compatibility
/**
 * @deprecated Use encapsulate() instead
 */
inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encrypt(const std::vector<uint8_t>& public_key) {
    auto result = encapsulate(public_key);
    return {result.shared_secret, result.ciphertext};
}

/**
 * @deprecated Use decapsulate() instead
 */
inline std::vector<uint8_t> decrypt(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& ciphertext) {
    return decapsulate(secret_key, ciphertext);
}

} // namespace citadelle

#endif // CITADELLE_KEY_EXCHANGE_H 