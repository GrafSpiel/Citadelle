#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "key_exchange.h"
#include <vector>
#include <algorithm>
#include <chrono>

namespace {

using namespace citadelle;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Throws;

// Constants for key sizes (matching those in key_exchange.cpp)
constexpr size_t KYBER_PUBLIC_KEY_SIZE = 800;
constexpr size_t KYBER_SECRET_KEY_SIZE = 1632;
constexpr size_t KYBER_CIPHERTEXT_SIZE = 768;
constexpr size_t KYBER_SHARED_SECRET_SIZE = 32;

class KeyExchangeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate a fresh key pair for each test
        keys = generate_key_pair();
    }

    KeyPair keys;
};

// Test that key generation produces keys of the correct size
TEST_F(KeyExchangeTest, KeyGenerationProducesCorrectSizes) {
    EXPECT_EQ(keys.public_key.size(), kyber::PUBLIC_KEY_SIZE);
    EXPECT_EQ(keys.secret_key.size(), kyber::SECRET_KEY_SIZE);
}

// Test that key generation produces different keys each time
TEST_F(KeyExchangeTest, KeyGenerationProducesDifferentKeys) {
    KeyPair keys2 = generate_key_pair();
    
    // Check that the keys are different
    EXPECT_FALSE(std::equal(keys.public_key.begin(), keys.public_key.end(), keys2.public_key.begin()));
    EXPECT_FALSE(std::equal(keys.secret_key.begin(), keys.secret_key.end(), keys2.secret_key.begin()));
}

// Test basic encapsulation functionality
TEST_F(KeyExchangeTest, EncapsulationProducesCorrectSizes) {
    EncapsulationResult result = encapsulate(keys.public_key);
    
    EXPECT_EQ(result.shared_secret.size(), kyber::SHARED_SECRET_SIZE);
    EXPECT_EQ(result.ciphertext.size(), kyber::CIPHERTEXT_SIZE);
}

// Test basic decapsulation functionality
TEST_F(KeyExchangeTest, DecapsulationProducesCorrectSize) {
    EncapsulationResult result = encapsulate(keys.public_key);
    std::vector<uint8_t> decapsulated_secret = decapsulate(keys.secret_key, result.ciphertext);
    
    EXPECT_EQ(decapsulated_secret.size(), kyber::SHARED_SECRET_SIZE);
}

// Test that encapsulation with the same public key produces different results
TEST_F(KeyExchangeTest, EncapsulationProducesDifferentResults) {
    EncapsulationResult result1 = encapsulate(keys.public_key);
    EncapsulationResult result2 = encapsulate(keys.public_key);
    
    // The shared secrets and ciphertexts should be different for proper security
    EXPECT_FALSE(std::equal(result1.shared_secret.begin(), result1.shared_secret.end(), 
                            result2.shared_secret.begin()));
    EXPECT_FALSE(std::equal(result1.ciphertext.begin(), result1.ciphertext.end(), 
                            result2.ciphertext.begin()));
}

// Test that decapsulation works with matching key pairs
TEST_F(KeyExchangeTest, DecapsulationMatchesSharedSecret) {
    EncapsulationResult result = encapsulate(keys.public_key);
    std::vector<uint8_t> decapsulated_secret = decapsulate(keys.secret_key, result.ciphertext);
    
    // For simulation, secrets should match. With real Kyber they should also match.
    EXPECT_TRUE(std::equal(result.shared_secret.begin(), result.shared_secret.end(), 
                           decapsulated_secret.begin()));
}

// Test error handling for invalid inputs
TEST_F(KeyExchangeTest, InvalidPublicKeyThrowsException) {
    std::vector<uint8_t> invalid_public_key(kyber::PUBLIC_KEY_SIZE - 1); // Wrong size
    
    EXPECT_THROW({
        encapsulate(invalid_public_key);
    }, KeyExchangeError);
}

// Test error handling for invalid secret key
TEST_F(KeyExchangeTest, InvalidSecretKeyThrowsException) {
    EncapsulationResult result = encapsulate(keys.public_key);
    
    std::vector<uint8_t> invalid_secret_key(kyber::SECRET_KEY_SIZE - 1); // Wrong size
    
    EXPECT_THROW({
        decapsulate(invalid_secret_key, result.ciphertext);
    }, KeyExchangeError);
}

// Test error handling for invalid ciphertext
TEST_F(KeyExchangeTest, InvalidCiphertextThrowsException) {
    std::vector<uint8_t> invalid_ciphertext(kyber::CIPHERTEXT_SIZE - 1); // Wrong size
    
    EXPECT_THROW({
        decapsulate(keys.secret_key, invalid_ciphertext);
    }, KeyExchangeError);
}

// Test that different key pairs produce different encapsulation results
TEST_F(KeyExchangeTest, DifferentKeysProduceDifferentResults) {
    KeyPair keys2 = generate_key_pair();
    
    EncapsulationResult result1 = encapsulate(keys.public_key);
    EncapsulationResult result2 = encapsulate(keys2.public_key);
    
    // Results should be different for different keys
    EXPECT_FALSE(std::equal(result1.shared_secret.begin(), result1.shared_secret.end(), 
                            result2.shared_secret.begin()));
    EXPECT_FALSE(std::equal(result1.ciphertext.begin(), result1.ciphertext.end(), 
                            result2.ciphertext.begin()));
}

// Test empty key handling
TEST_F(KeyExchangeTest, EmptyInputsThrowException) {
    std::vector<uint8_t> empty_key;
    std::vector<uint8_t> empty_ciphertext;
    
    EXPECT_THROW({
        encapsulate(empty_key);
    }, KeyExchangeError);
    
    EXPECT_THROW({
        decapsulate(empty_key, keys.public_key);
    }, KeyExchangeError);
    
    EXPECT_THROW({
        decapsulate(keys.secret_key, empty_ciphertext);
    }, KeyExchangeError);
}

// Stress test to ensure robustness
TEST_F(KeyExchangeTest, StressTest) {
    constexpr int NUM_ITERATIONS = 100;
    
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        KeyPair test_keys = generate_key_pair();
        ASSERT_EQ(test_keys.public_key.size(), kyber::PUBLIC_KEY_SIZE);
        ASSERT_EQ(test_keys.secret_key.size(), kyber::SECRET_KEY_SIZE);
        
        EncapsulationResult result = encapsulate(test_keys.public_key);
        ASSERT_EQ(result.shared_secret.size(), kyber::SHARED_SECRET_SIZE);
        ASSERT_EQ(result.ciphertext.size(), kyber::CIPHERTEXT_SIZE);
        
        std::vector<uint8_t> decapsulated_secret = decapsulate(test_keys.secret_key, result.ciphertext);
        ASSERT_EQ(decapsulated_secret.size(), kyber::SHARED_SECRET_SIZE);
        
        // Verify the shared secret matches what was decapsulated
        ASSERT_TRUE(std::equal(result.shared_secret.begin(), result.shared_secret.end(), 
                               decapsulated_secret.begin()));
    }
}

// Add a performance test
TEST_F(KeyExchangeTest, PerformanceTest) {
    // Time key generation
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; ++i) {
        KeyPair perf_keys = generate_key_pair();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_keygen = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Time encapsulation
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; ++i) {
        EncapsulationResult result = encapsulate(keys.public_key);
    }
    end = std::chrono::high_resolution_clock::now();
    auto duration_encaps = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Time decapsulation
    EncapsulationResult result = encapsulate(keys.public_key);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> decapsulated_secret = decapsulate(keys.secret_key, result.ciphertext);
    }
    end = std::chrono::high_resolution_clock::now();
    auto duration_decaps = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Output performance metrics
    std::cout << "Performance metrics (10 iterations):" << std::endl;
    std::cout << "Key generation: " << duration_keygen.count() << " ms" << std::endl;
    std::cout << "Encapsulation: " << duration_encaps.count() << " ms" << std::endl;
    std::cout << "Decapsulation: " << duration_decaps.count() << " ms" << std::endl;
    
    // No assertions, just informational
}

} // namespace 