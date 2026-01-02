#ifndef HAVE_TSIG_H
#define HAVE_TSIG_H

#include <string>
#include <map>
#include "message.h"
#include "rrtsig.h"

// TSIG (Transaction Signature) authentication - RFC 2845
// Supports HMAC-MD5, HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512
class TSIG {
public:
    enum Algorithm {
        HMAC_MD5,
        HMAC_SHA1,
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512
    };
    
    // TSIG key configuration
    struct Key {
        std::string name;           // Key name (e.g., "mykey.example.com.")
        Algorithm algorithm;
        std::string secret;         // Base64-encoded shared secret
        std::string decoded_secret; // Decoded binary secret
        
        Key() : algorithm(HMAC_SHA256) {}
    };
    
    // Verify TSIG signature on a DNS message
    // Returns true if signature is valid or no TSIG is required
    // Returns false if TSIG verification fails
    static bool verify(const Message* msg, 
                      const char* raw_message, 
                      unsigned int raw_length,
                      const Key* key,
                      std::string& error);
    
    // Sign a DNS message with TSIG
    static bool sign(Message* msg,
                    char* raw_message,
                    unsigned int& raw_length,
                    const Key* key,
                    unsigned short original_id,
                    std::string& error);
    
    // Algorithm name to enum
    static Algorithm algorithmFromName(const std::string& name);
    
    // Algorithm enum to name
    static std::string algorithmToName(Algorithm algo);
    
    // Compute HMAC for given algorithm
    static std::string computeHMAC(Algorithm algo,
                                  const std::string& key,
                                  const std::string& data);
    
    // Base64 decode
    static std::string base64Decode(const std::string& encoded);
    
    // Base64 encode
    static std::string base64Encode(const std::string& data);
    
private:
    // Extract TSIG record from additional section
    static RRTSIG* extractTSIG(const Message* msg);
    
    // Build TSIG signing data
    static std::string buildSigningData(const char* message,
                                       unsigned int message_len,
                                       const RRTSIG* tsig,
                                       bool include_mac = false);
};

#endif
