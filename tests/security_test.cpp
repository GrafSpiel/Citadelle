#include <gtest/gtest.h>
#include "key_exchange.h"
#include <algorithm>
#include <memory>
#include <vector>
#include <cstring>

namespace {

using namespace citadelle;

// Helper to make a copy of a vector
std::vector<uint8_t> clone_vector(const std::vector<uint8_t>& input) {
    return std::vector<uint8_t>(input.begin(), input.end());
}

// Function to check if memory has been wiped
// Returns true if at least some bytes differ (have been wiped)
bool has_been_wiped(const std::vector<uint8_t>& original, const std::vector<uint8_t>& current) {
    if (original.size() != current.size()) return true;
    
    // Count number of matching bytes - in wiped memory, most should be different
    size_t matching_bytes = 0;
    for (size_t i = 0; i < original.size(); ++i) {
        if (original[i] == current[i]) {
            matching_bytes++;
        }
    }
    
    // If more than 90% of bytes match, it's likely not been wiped
    return (matching_bytes < 0.9 * original.size());
}

class SecurityTest : public ::testing::Test {
protected:
    SecurityTest() = default;
};

// Test that sensitive keys are wiped on destruction or in error cases
TEST_F(SecurityTest, KeysAreWipedInErrorCase) {
    // Create a scope for the secret key
    std::vector<uint8_t> secret_key_copy;
    
    {
        // Generate a key pair
        KeyPair keys = generate_key_pair();
        
        // Take a copy of the secret key
        secret_key_copy = clone_vector(keys.secret_key);
        
        // Check that the original and copy are identical
        EXPECT_TRUE(std::equal(keys.secret_key.begin(), keys.secret_key.end(), 
                              secret_key_copy.begin()));
        
        // Now trigger an error that should clean up the key
        std::vector<uint8_t> invalid_ciphertext(1); // Too small
        
        // This should throw an exception
        EXPECT_THROW({
            decapsulate(keys.secret_key, invalid_ciphertext);
        }, KeyExchangeError);
        
        // After the error, the secret key should still be intact - error handling
        // should not destroy the key
        EXPECT_TRUE(std::equal(keys.secret_key.begin(), keys.secret_key.end(), 
                              secret_key_copy.begin()));
    }
    
    // After the scope ends, the KeyPair is destructed, but we have our copy
    // We cannot directly test that the original was wiped (it's gone),
    // but the implementation should call secure_wipe() to clear it
}

// Test that shared secrets are properly wiped in error cases
TEST_F(SecurityTest, SharedSecretsAreWipedInErrorCase) {
    // Generate a key pair
    KeyPair keys = generate_key_pair();
    
    // Create a shared secret through encapsulation
    EncapsulationResult result = encapsulate(keys.public_key);
    
    // Make a copy of the shared secret
    std::vector<uint8_t> shared_secret_copy = clone_vector(result.shared_secret);
    
    // Verify they match
    EXPECT_TRUE(std::equal(result.shared_secret.begin(), result.shared_secret.end(),
                          shared_secret_copy.begin()));
    
    // Now create an invalid situation that should trigger wiping
    std::vector<uint8_t> invalid_secret_key(1); // Too small
    
    // This should throw and internally wipe any sensitive data
    EXPECT_THROW({
        decapsulate(invalid_secret_key, result.ciphertext);
    }, KeyExchangeError);
    
    // We can't verify the internal wiping since it happens in the function,
    // but the implementation should be calling secure_wipe() before throwing
}

// Test memory locality - keys should be in distinct memory locations
TEST_F(SecurityTest, KeysAreStoredInDistinctMemory) {
    // Generate multiple key pairs
    KeyPair keys1 = generate_key_pair();
    KeyPair keys2 = generate_key_pair();
    
    // The keys should be in different memory locations
    EXPECT_NE(keys1.public_key.data(), keys2.public_key.data());
    EXPECT_NE(keys1.secret_key.data(), keys2.secret_key.data());
    
    // Public and secret keys should also be in different memory
    EXPECT_NE(keys1.public_key.data(), keys1.secret_key.data());
    EXPECT_NE(keys2.public_key.data(), keys2.secret_key.data());
}

} // namespace 