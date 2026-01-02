#include <iostream>
#include <cassert>
#include <cstring>
#include <iomanip>
#include <sstream>
#include "tsig.h"

using namespace std;

// Helper to convert binary to hex string for comparison
string toHex(const string& binary) {
    ostringstream oss;
    for (size_t i = 0; i < binary.length(); i++) {
        oss << hex << setw(2) << setfill('0') << (int)(unsigned char)binary[i];
    }
    return oss.str();
}

void test_hmac_sha256_test_vector() {
    cout << "Testing HMAC-SHA256 with RFC 4231 test vector..." << endl;
    
    // RFC 4231 Test Case 2
    // Key = "Jefe"
    // Data = "what do ya want for nothing?"
    // HMAC-SHA256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    
    TSIG::Key key;
    key.algorithm = TSIG::HMAC_SHA256;
    key.decoded_secret = "Jefe";
    
    string data = "what do ya want for nothing?";
    string mac = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data);
    string mac_hex = toHex(mac);
    
    string expected_hex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    
    assert(mac.length() == 32 && "SHA256 HMAC should be 32 bytes");
    assert(mac_hex == expected_hex && "HMAC-SHA256 must match RFC 4231 test vector");
    
    cout << "  ✓ HMAC-SHA256 matches RFC 4231 test vector" << endl;
}

void test_hmac_md5_test_vector() {
    cout << "Testing HMAC-MD5 with RFC 2104 test vector..." << endl;
    
    // RFC 2104 Test Case 1
    // Key = 0x0b (repeated 16 times)
    // Data = "Hi There"
    // HMAC-MD5 = 9294727a3638bb1c13f48ef8158bfc9d
    
    TSIG::Key key;
    key.algorithm = TSIG::HMAC_MD5;
    key.decoded_secret = string(16, 0x0b);
    
    string data = "Hi There";
    string mac = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data);
    string mac_hex = toHex(mac);
    
    string expected_hex = "9294727a3638bb1c13f48ef8158bfc9d";
    
    assert(mac.length() == 16 && "MD5 HMAC should be 16 bytes");
    assert(mac_hex == expected_hex && "HMAC-MD5 must match RFC 2104 test vector");
    
    cout << "  ✓ HMAC-MD5 matches RFC 2104 test vector" << endl;
}

void test_hmac_sha1_test_vector() {
    cout << "Testing HMAC-SHA1 with RFC 2202 test vector..." << endl;
    
    // RFC 2202 Test Case 1
    // Key = 0x0b (repeated 20 times)
    // Data = "Hi There"
    // HMAC-SHA1 = b617318655057264e28bc0b6fb378c8ef146be00
    
    TSIG::Key key;
    key.algorithm = TSIG::HMAC_SHA1;
    key.decoded_secret = string(20, 0x0b);
    
    string data = "Hi There";
    string mac = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data);
    string mac_hex = toHex(mac);
    
    string expected_hex = "b617318655057264e28bc0b6fb378c8ef146be00";
    
    assert(mac.length() == 20 && "SHA1 HMAC should be 20 bytes");
    assert(mac_hex == expected_hex && "HMAC-SHA1 must match RFC 2202 test vector");
    
    cout << "  ✓ HMAC-SHA1 matches RFC 2202 test vector" << endl;
}

void test_hmac_different_inputs() {
    cout << "Testing HMAC produces different results for different inputs..." << endl;
    
    TSIG::Key key;
    key.name = "test-key.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "dGVzdHNlY3JldA==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string data1 = "message 1";
    string data2 = "message 2";
    
    string mac1 = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data1);
    string mac2 = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data2);
    
    assert(mac1 != mac2 && "Different inputs must produce different MACs");
    assert(!mac1.empty() && "MAC1 must not be empty");
    assert(!mac2.empty() && "MAC2 must not be empty");
    
    cout << "  ✓ Different inputs produce different MACs" << endl;
}

void test_hmac_same_input_same_result() {
    cout << "Testing HMAC is deterministic..." << endl;
    
    TSIG::Key key;
    key.name = "test-key.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "dGVzdHNlY3JldA==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string data = "consistent message";
    
    string mac1 = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data);
    string mac2 = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data);
    
    assert(mac1 == mac2 && "Same input must produce same MAC");
    assert(!mac1.empty() && "MAC must not be empty");
    
    cout << "  ✓ HMAC is deterministic" << endl;
}

void test_hmac_all_algorithms() {
    cout << "Testing all HMAC algorithms produce non-empty results..." << endl;
    
    TSIG::Algorithm algorithms[] = {
        TSIG::HMAC_MD5,
        TSIG::HMAC_SHA1,
        TSIG::HMAC_SHA256,
        TSIG::HMAC_SHA384,
        TSIG::HMAC_SHA512
    };
    
    size_t expected_lengths[] = {16, 20, 32, 48, 64};
    
    TSIG::Key key;
    key.secret = "dGVzdHNlY3JldA==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string data = "test message";
    
    for (size_t i = 0; i < 5; i++) {
        key.algorithm = algorithms[i];
        string mac = TSIG::computeHMAC(key.algorithm, key.decoded_secret, data);
        
        assert(!mac.empty() && "HMAC must not be empty");
        assert(mac.length() == expected_lengths[i] && "HMAC length must match algorithm");
        
        cout << "  ✓ " << TSIG::algorithmToName(algorithms[i]) << " produces " 
             << expected_lengths[i] << " byte MAC" << endl;
    }
}

int main() {
    cout << "=== TSIG HMAC Tests ===" << endl << endl;
    
    test_hmac_sha256_test_vector();
    test_hmac_md5_test_vector();
    test_hmac_sha1_test_vector();
    test_hmac_different_inputs();
    test_hmac_same_input_same_result();
    test_hmac_all_algorithms();
    
    cout << endl << "All TSIG HMAC tests passed!" << endl;
    return 0;
}
