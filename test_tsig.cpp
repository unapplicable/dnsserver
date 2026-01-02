#include <iostream>
#include <cassert>
#include <cstring>
#include "tsig.h"
#include "rrtsig.h"
#include "zone.h"

using namespace std;

void test_base64_encode_decode() {
    cout << "Testing Base64 encoding/decoding..." << endl;
    
    string original = "Hello, TSIG!";
    string encoded = TSIG::base64Encode(original);
    string decoded = TSIG::base64Decode(encoded);
    
    assert(decoded == original);
    cout << "  Original: " << original << endl;
    cout << "  Encoded: " << encoded << endl;
    cout << "  Decoded: " << decoded << endl;
    cout << "  PASSED" << endl;
}

void test_algorithm_conversion() {
    cout << "Testing algorithm name conversion..." << endl;
    
    // Test algorithm name to enum
    assert(TSIG::algorithmFromName("hmac-md5") == TSIG::HMAC_MD5);
    assert(TSIG::algorithmFromName("hmac-sha1") == TSIG::HMAC_SHA1);
    assert(TSIG::algorithmFromName("hmac-sha256") == TSIG::HMAC_SHA256);
    assert(TSIG::algorithmFromName("hmac-sha384") == TSIG::HMAC_SHA384);
    assert(TSIG::algorithmFromName("hmac-sha512") == TSIG::HMAC_SHA512);
    
    // Test enum to algorithm name
    assert(TSIG::algorithmToName(TSIG::HMAC_MD5) == "hmac-md5.sig-alg.reg.int.");
    assert(TSIG::algorithmToName(TSIG::HMAC_SHA256) == "hmac-sha256.");
    
    cout << "  PASSED" << endl;
}

void test_hmac_computation() {
    cout << "Testing HMAC computation..." << endl;
    
    string key = "secret";
    string data = "message";
    
    // Compute HMAC-SHA256
    string mac = TSIG::computeHMAC(TSIG::HMAC_SHA256, key, data);
    
    // Should be 32 bytes for SHA256
    assert(mac.length() == 32);
    
    // Computing again should give same result
    string mac2 = TSIG::computeHMAC(TSIG::HMAC_SHA256, key, data);
    assert(mac == mac2);
    
    // Different key should give different result
    string mac3 = TSIG::computeHMAC(TSIG::HMAC_SHA256, "different", data);
    assert(mac != mac3);
    
    cout << "  HMAC-SHA256 length: " << mac.length() << " bytes" << endl;
    cout << "  PASSED" << endl;
}

void test_tsig_key_structure() {
    cout << "Testing TSIG Key structure..." << endl;
    
    TSIG::Key key;
    key.name = "mykey.example.com.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    assert(key.name == "mykey.example.com.");
    assert(key.algorithm == TSIG::HMAC_SHA256);
    assert(key.decoded_secret.length() == 16);
    
    cout << "  Key name: " << key.name << endl;
    cout << "  Algorithm: " << TSIG::algorithmToName(key.algorithm) << endl;
    cout << "  Decoded secret length: " << key.decoded_secret.length() << " bytes" << endl;
    cout << "  PASSED" << endl;
}

void test_rrtsig_record() {
    cout << "Testing RRTSIG record..." << endl;
    
    RRTSIG tsig;
    tsig.name = "testkey.example.com.";
    tsig.type = RR::TSIG;
    tsig.rrclass = RR::CLASSANY;
    tsig.ttl = 0;
    tsig.algorithm = "hmac-sha256.";
    tsig.setTimeSigned(1704153600); // 2024-01-02 00:00:00 UTC
    tsig.fudge = 300;
    tsig.mac = "test_mac_value";
    tsig.mac_size = tsig.mac.length();
    tsig.original_id = 12345;
    tsig.error = 0;
    tsig.other_len = 0;
    
    // Test getTimeSigned
    assert(tsig.getTimeSigned() == 1704153600);
    
    // Test setTimeSigned with 48-bit value (16-bit high + 32-bit low)
    uint64_t test_time = 0x00001234ABCDEF00ULL;
    tsig.setTimeSigned(test_time);
    assert(tsig.time_signed_high == 0x1234);
    assert(tsig.time_signed_low == 0xABCDEF00);
    assert(tsig.getTimeSigned() == test_time);
    
    cout << "  TSIG record name: " << tsig.name << endl;
    cout << "  Algorithm: " << tsig.algorithm << endl;
    cout << "  Fudge: " << tsig.fudge << " seconds" << endl;
    cout << "  PASSED" << endl;
}

void test_tsig_verification_no_key() {
    cout << "Testing TSIG verification with no key..." << endl;
    
    // Create a message without TSIG
    Message msg;
    char dummy_buffer[512] = {0};
    string error;
    
    // Should succeed when no key required and no TSIG present
    bool result = TSIG::verify(&msg, dummy_buffer, 12, NULL, error);
    assert(result == true);
    
    cout << "  PASSED" << endl;
}

void test_tsig_verification_key_required() {
    cout << "Testing TSIG verification when key required..." << endl;
    
    // Create a message without TSIG
    Message msg;
    char dummy_buffer[512] = {0};
    string error;
    
    // Create a key
    TSIG::Key key;
    key.name = "testkey.example.com.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    // Should fail when key required but no TSIG present
    bool result = TSIG::verify(&msg, dummy_buffer, 12, &key, error);
    assert(result == false);
    assert(error == "TSIG required but not present");
    
    cout << "  Error message: " << error << endl;
    cout << "  PASSED" << endl;
}

void test_different_hmac_algorithms() {
    cout << "Testing different HMAC algorithms..." << endl;
    
    string key = "shared_secret";
    string data = "test_data";
    
    string md5 = TSIG::computeHMAC(TSIG::HMAC_MD5, key, data);
    string sha1 = TSIG::computeHMAC(TSIG::HMAC_SHA1, key, data);
    string sha256 = TSIG::computeHMAC(TSIG::HMAC_SHA256, key, data);
    string sha384 = TSIG::computeHMAC(TSIG::HMAC_SHA384, key, data);
    string sha512 = TSIG::computeHMAC(TSIG::HMAC_SHA512, key, data);
    
    // Verify expected lengths
    assert(md5.length() == 16);    // MD5 = 128 bits = 16 bytes
    assert(sha1.length() == 20);   // SHA1 = 160 bits = 20 bytes
    assert(sha256.length() == 32); // SHA256 = 256 bits = 32 bytes
    assert(sha384.length() == 48); // SHA384 = 384 bits = 48 bytes
    assert(sha512.length() == 64); // SHA512 = 512 bits = 64 bytes
    
    // All should be different
    assert(md5 != sha1);
    assert(sha1 != sha256);
    assert(sha256 != sha384);
    assert(sha384 != sha512);
    
    cout << "  MD5:    " << md5.length() << " bytes" << endl;
    cout << "  SHA1:   " << sha1.length() << " bytes" << endl;
    cout << "  SHA256: " << sha256.length() << " bytes" << endl;
    cout << "  SHA384: " << sha384.length() << " bytes" << endl;
    cout << "  SHA512: " << sha512.length() << " bytes" << endl;
    cout << "  PASSED" << endl;
}

void test_tsig_invalid_mac() {
    cout << "Testing TSIG verification with invalid MAC..." << endl;
    
    // Create a message with invalid TSIG
    Message msg;
    RRTSIG* tsig = new RRTSIG();
    tsig->name = "testkey.example.com.";
    tsig->type = RR::TSIG;
    tsig->rrclass = RR::CLASSANY;
    tsig->ttl = 0;
    tsig->algorithm = "hmac-sha256.";
    tsig->setTimeSigned(time(NULL));
    tsig->fudge = 300;
    tsig->mac = "invalid_mac_signature";
    tsig->mac_size = tsig->mac.length();
    tsig->original_id = 12345;
    tsig->error = 0;
    tsig->other_len = 0;
    msg.ar.push_back(tsig);
    
    // Create raw message buffer
    char raw_buffer[512];
    memset(raw_buffer, 0, sizeof(raw_buffer));
    unsigned int raw_len = 12; // DNS header size
    
    // Create a key
    TSIG::Key key;
    key.name = "testkey.example.com.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string error;
    bool result = TSIG::verify(&msg, raw_buffer, raw_len, &key, error);
    
    assert(result == false);
    assert(error == "TSIG signature verification failed");
    
    cout << "  Error message: " << error << endl;
    cout << "  PASSED" << endl;
}

void test_tsig_algorithm_mismatch() {
    cout << "Testing TSIG verification with algorithm mismatch..." << endl;
    
    Message msg;
    RRTSIG* tsig = new RRTSIG();
    tsig->name = "testkey.example.com.";
    tsig->type = RR::TSIG;
    tsig->rrclass = RR::CLASSANY;
    tsig->ttl = 0;
    tsig->algorithm = "hmac-md5.sig-alg.reg.int.";  // Different algorithm
    tsig->setTimeSigned(time(NULL));
    tsig->fudge = 300;
    tsig->mac = "some_mac";
    tsig->mac_size = tsig->mac.length();
    tsig->original_id = 12345;
    tsig->error = 0;
    tsig->other_len = 0;
    msg.ar.push_back(tsig);
    
    char raw_buffer[512] = {0};
    
    TSIG::Key key;
    key.name = "testkey.example.com.";
    key.algorithm = TSIG::HMAC_SHA256;  // Different from message
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string error;
    bool result = TSIG::verify(&msg, raw_buffer, 12, &key, error);
    
    assert(result == false);
    assert(error == "TSIG algorithm mismatch");
    
    cout << "  Error message: " << error << endl;
    cout << "  PASSED" << endl;
}

void test_tsig_time_check() {
    cout << "Testing TSIG time check..." << endl;
    
    Message msg;
    RRTSIG* tsig = new RRTSIG();
    tsig->name = "testkey.example.com.";
    tsig->type = RR::TSIG;
    tsig->rrclass = RR::CLASSANY;
    tsig->ttl = 0;
    tsig->algorithm = "hmac-sha256.";
    tsig->setTimeSigned(time(NULL) - 1000);  // 1000 seconds in the past
    tsig->fudge = 300;  // Only 300 seconds allowed
    tsig->mac = "some_mac";
    tsig->mac_size = tsig->mac.length();
    tsig->original_id = 12345;
    tsig->error = 0;
    tsig->other_len = 0;
    msg.ar.push_back(tsig);
    
    char raw_buffer[512] = {0};
    
    TSIG::Key key;
    key.name = "testkey.example.com.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string error;
    bool result = TSIG::verify(&msg, raw_buffer, 12, &key, error);
    
    assert(result == false);
    assert(error == "TSIG time check failed");
    
    cout << "  Error message: " << error << endl;
    cout << "  PASSED" << endl;
}

void test_tsig_key_name_mismatch() {
    cout << "Testing TSIG verification with key name mismatch..." << endl;
    
    Message msg;
    RRTSIG* tsig = new RRTSIG();
    tsig->name = "wrongkey.example.com.";  // Different key name
    tsig->type = RR::TSIG;
    tsig->rrclass = RR::CLASSANY;
    tsig->ttl = 0;
    tsig->algorithm = "hmac-sha256.";
    tsig->setTimeSigned(time(NULL));
    tsig->fudge = 300;
    tsig->mac = "some_mac";
    tsig->mac_size = tsig->mac.length();
    tsig->original_id = 12345;
    tsig->error = 0;
    tsig->other_len = 0;
    msg.ar.push_back(tsig);
    
    char raw_buffer[512] = {0};
    
    TSIG::Key key;
    key.name = "testkey.example.com.";  // Different from message
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    string error;
    bool result = TSIG::verify(&msg, raw_buffer, 12, &key, error);
    
    assert(result == false);
    assert(error == "TSIG key name mismatch");
    
    cout << "  Error message: " << error << endl;
    cout << "  PASSED" << endl;
}

int main() {
    cout << "Running TSIG unit tests..." << endl << endl;
    
    try {
        test_base64_encode_decode();
        test_algorithm_conversion();
        test_hmac_computation();
        test_tsig_key_structure();
        test_rrtsig_record();
        test_tsig_verification_no_key();
        test_tsig_verification_key_required();
        test_different_hmac_algorithms();
        test_tsig_invalid_mac();
        test_tsig_algorithm_mismatch();
        test_tsig_time_check();
        test_tsig_key_name_mismatch();
        
        cout << endl << "All TSIG tests PASSED!" << endl;
        return 0;
    } catch (const exception& e) {
        cerr << "Test FAILED: " << e.what() << endl;
        return 1;
    }
}
