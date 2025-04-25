#include "key_exchange.h"
#include <iostream>
#include <iomanip>
#include <stdexcept>

// Helper function to print byte vectors in a readable format
void print_bytes(const std::string& label, const std::vector<uint8_t>& bytes, size_t max_display = 32) {
    std::cout << label << ": ";
    
    const size_t display_size = std::min(bytes.size(), max_display);
    for (size_t i = 0; i < display_size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(bytes[i]) << " ";
    }
    
    if (bytes.size() > max_display) {
        std::cout << "... (" << std::dec << bytes.size() << " bytes total)";
    }
    
    std::cout << std::dec << std::endl;
}

int main() {
    try {
        std::cout << "Citadelle C++ Version - Post-Quantum Key Exchange Demo" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        
#ifdef CITADELLE_USE_LIBOQS
        std::cout << "Using liboqs for real post-quantum KEM" << std::endl;
#else
        std::cout << "Using simulation mode (not real post-quantum KEM)" << std::endl;
#endif
        std::cout << "----------------------------------------------" << std::endl;
        
        // Generate a key pair
        std::cout << "Generating key pair..." << std::endl;
        citadelle::KeyPair keys = citadelle::generate_key_pair();
        
        print_bytes("Public Key", keys.public_key);
        print_bytes("Secret Key", keys.secret_key);
        
        // Encapsulate a shared secret using the public key
        std::cout << "\nEncapsulating shared secret..." << std::endl;
        citadelle::EncapsulationResult encaps_result = citadelle::encapsulate(keys.public_key);
        
        print_bytes("Shared Secret", encaps_result.shared_secret);
        print_bytes("Ciphertext", encaps_result.ciphertext);
        
        // Decapsulate using the secret key
        std::cout << "\nDecapsulating shared secret..." << std::endl;
        std::vector<uint8_t> decapsulated_secret = citadelle::decapsulate(keys.secret_key, encaps_result.ciphertext);
        
        print_bytes("Decapsulated Secret", decapsulated_secret);
        
        // Verify
        bool match = (encaps_result.shared_secret == decapsulated_secret);
        std::cout << "\nShared secret " << (match ? "matches" : "does not match") 
                  << " the decapsulated secret." << std::endl;
        
        // Security information
        std::cout << "\nSecurity Information:" << std::endl;
        std::cout << "- Implementation: " << 
#ifdef CITADELLE_USE_LIBOQS
            "liboqs (NIST PQC Round 3 Finalist)"
#else
            "Simulation (not suitable for production use)"
#endif
            << std::endl;
        std::cout << "- Algorithm: Kyber-512" << std::endl;
        std::cout << "- Security Level: NIST Level 1 (equivalent to AES-128)" << std::endl;
        
        return match ? 0 : 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 