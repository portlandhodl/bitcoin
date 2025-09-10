#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <libbitcoinpqc/bitcoinpqc.h>
#include <libbitcoinpqc/slh_dsa.h>
#include <random.h>
#include <util/strencodings.h>
#include <iostream>
#include <iomanip>

BOOST_FIXTURE_TEST_SUITE(slh_dsa_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_slh_dsa_keygen)
{
    std::cout << "=== SLH-DSA Key Generation Test ===" << std::endl;
    
    // Generate random entropy for key generation
    std::vector<uint8_t> random_data(256); // 256 bytes of entropy
    FastRandomContext{}.fillrand(MakeWritableByteSpan(random_data));
    
    std::cout << "Generated " << random_data.size() << " bytes of entropy" << std::endl;
    
    // Allocate buffers for keys
    std::vector<uint8_t> public_key(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> secret_key(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    
    std::cout << "Public key size: " << SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE << " bytes" << std::endl;
    std::cout << "Secret key size: " << SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE << " bytes" << std::endl;
    std::cout << "Signature size: " << SLH_DSA_SHAKE_128S_SIGNATURE_SIZE << " bytes" << std::endl;
    
    // Generate key pair using direct SLH-DSA API
    int result = slh_dsa_shake_128s_keygen(
        public_key.data(),
        secret_key.data(),
        random_data.data(),
        random_data.size()
    );
    
    BOOST_CHECK_EQUAL(result, 0);
    if (result != 0) {
        std::cout << "Key generation failed with error code: " << result << std::endl;
        return;
    }
    
    std::cout << "✓ Key generation successful!" << std::endl;
    
    // Display the generated keys
    std::cout << "\nPublic Key (hex): " << HexStr(public_key) << std::endl;
    std::cout << "Secret Key (hex): " << HexStr(secret_key) << std::endl;
    
    // Test signing and verification
    std::string test_message = "Hello, post-quantum Bitcoin!";
    std::vector<uint8_t> message_bytes(test_message.begin(), test_message.end());
    
    std::cout << "\nTesting signature generation and verification..." << std::endl;
    std::cout << "Message: " << test_message << std::endl;
    
    // Generate signature
    std::vector<uint8_t> signature(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    size_t signature_length = 0;
    
    result = slh_dsa_shake_128s_sign(
        signature.data(),
        &signature_length,
        message_bytes.data(),
        message_bytes.size(),
        secret_key.data()
    );
    
    BOOST_CHECK_EQUAL(result, 0);
    if (result != 0) {
        std::cout << "Signature generation failed with error code: " << result << std::endl;
        return;
    }
    
    std::cout << "✓ Signature generation successful!" << std::endl;
    std::cout << "Signature length: " << signature_length << " bytes" << std::endl;
    std::cout << "Signature (first 64 bytes, hex): " << HexStr(std::span<const uint8_t>(signature.data(), std::min(signature_length, size_t(64)))) << "..." << std::endl;
    
    // Verify signature
    result = slh_dsa_shake_128s_verify(
        signature.data(),
        signature_length,
        message_bytes.data(),
        message_bytes.size(),
        public_key.data()
    );
    
    BOOST_CHECK_EQUAL(result, 0);
    if (result != 0) {
        std::cout << "Signature verification failed with error code: " << result << std::endl;
        return;
    }
    
    std::cout << "✓ Signature verification successful!" << std::endl;
    
    // Test with wrong message (should fail)
    std::string wrong_message = "Wrong message";
    std::vector<uint8_t> wrong_message_bytes(wrong_message.begin(), wrong_message.end());
    
    result = slh_dsa_shake_128s_verify(
        signature.data(),
        signature_length,
        wrong_message_bytes.data(),
        wrong_message_bytes.size(),
        public_key.data()
    );
    
    BOOST_CHECK_NE(result, 0);
    std::cout << "✓ Signature verification correctly failed for wrong message" << std::endl;
    
    std::cout << "\n=== All tests passed! ===" << std::endl;
}

BOOST_AUTO_TEST_CASE(test_slh_dsa_high_level_api)
{
    std::cout << "\n=== SLH-DSA High-Level API Test ===" << std::endl;
    
    // Generate random entropy
    std::vector<uint8_t> random_data(256);
    FastRandomContext{}.fillrand(MakeWritableByteSpan(random_data));
    
    // Create keypair structure
    bitcoin_pqc_keypair_t keypair;
    keypair.algorithm = BITCOIN_PQC_SLH_DSA_SHAKE_128S;
    keypair.public_key = nullptr;
    keypair.secret_key = nullptr;
    keypair.public_key_size = 0;
    keypair.secret_key_size = 0;
    
    // Generate key pair using high-level API
    bitcoin_pqc_error_t result = bitcoin_pqc_keygen(
        BITCOIN_PQC_SLH_DSA_SHAKE_128S,
        &keypair,
        random_data.data(),
        random_data.size()
    );
    
    BOOST_CHECK_EQUAL(result, BITCOIN_PQC_OK);
    if (result != BITCOIN_PQC_OK) {
        std::cout << "High-level key generation failed with error code: " << result << std::endl;
        return;
    }
    
    std::cout << "✓ High-level key generation successful!" << std::endl;
    std::cout << "Public key size: " << keypair.public_key_size << " bytes" << std::endl;
    std::cout << "Secret key size: " << keypair.secret_key_size << " bytes" << std::endl;
    
    // Display keys
    std::cout << "Public Key (hex): " << HexStr(std::span<const uint8_t>(static_cast<uint8_t*>(keypair.public_key), keypair.public_key_size)) << std::endl;
    std::cout << "Secret Key (hex): " << HexStr(std::span<const uint8_t>(static_cast<uint8_t*>(keypair.secret_key), keypair.secret_key_size)) << std::endl;
    
    // Test signing with high-level API
    std::string test_message = "High-level API test message";
    std::vector<uint8_t> message_bytes(test_message.begin(), test_message.end());
    
    bitcoin_pqc_signature_t signature;
    signature.algorithm = BITCOIN_PQC_SLH_DSA_SHAKE_128S;
    signature.signature = nullptr;
    signature.signature_size = 0;
    
    result = bitcoin_pqc_sign(
        BITCOIN_PQC_SLH_DSA_SHAKE_128S,
        static_cast<uint8_t*>(keypair.secret_key),
        keypair.secret_key_size,
        message_bytes.data(),
        message_bytes.size(),
        &signature
    );
    
    BOOST_CHECK_EQUAL(result, BITCOIN_PQC_OK);
    if (result != BITCOIN_PQC_OK) {
        std::cout << "High-level signing failed with error code: " << result << std::endl;
        bitcoin_pqc_keypair_free(&keypair);
        return;
    }
    
    std::cout << "✓ High-level signing successful!" << std::endl;
    std::cout << "Signature size: " << signature.signature_size << " bytes" << std::endl;
    
    // Test verification with high-level API
    result = bitcoin_pqc_verify(
        BITCOIN_PQC_SLH_DSA_SHAKE_128S,
        static_cast<uint8_t*>(keypair.public_key),
        keypair.public_key_size,
        message_bytes.data(),
        message_bytes.size(),
        static_cast<uint8_t*>(signature.signature),
        signature.signature_size
    );
    
    BOOST_CHECK_EQUAL(result, BITCOIN_PQC_OK);
    if (result != BITCOIN_PQC_OK) {
        std::cout << "High-level verification failed with error code: " << result << std::endl;
    } else {
        std::cout << "✓ High-level verification successful!" << std::endl;
    }
    
    // Clean up
    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);
    
    std::cout << "=== High-level API test completed! ===" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()