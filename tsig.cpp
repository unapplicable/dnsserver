#include "tsig.h"
#include "rrtsig.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>
#include <ctime>
#include <arpa/inet.h>

using namespace std;

TSIG::Algorithm TSIG::algorithmFromName(const string& name) {
    string lower = dns_name_tolower(name);
    
    if (lower.find("hmac-md5") != string::npos)
        return HMAC_MD5;
    if (lower.find("hmac-sha1") != string::npos)
        return HMAC_SHA1;
    if (lower.find("hmac-sha256") != string::npos)
        return HMAC_SHA256;
    if (lower.find("hmac-sha384") != string::npos)
        return HMAC_SHA384;
    if (lower.find("hmac-sha512") != string::npos)
        return HMAC_SHA512;
    
    return HMAC_SHA256; // Default
}

string TSIG::algorithmToName(Algorithm algo) {
    switch (algo) {
        case HMAC_MD5:    return "hmac-md5.sig-alg.reg.int.";
        case HMAC_SHA1:   return "hmac-sha1.";
        case HMAC_SHA256: return "hmac-sha256.";
        case HMAC_SHA384: return "hmac-sha384.";
        case HMAC_SHA512: return "hmac-sha512.";
    }
    return "hmac-sha256.";
}

string TSIG::base64Decode(const string& encoded) {
    BIO *bio, *b64;
    char buffer[encoded.length()];
    memset(buffer, 0, sizeof(buffer));
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_size = BIO_read(bio, buffer, sizeof(buffer));
    BIO_free_all(bio);
    
    if (decoded_size < 0)
        return "";
    
    return string(buffer, decoded_size);
}

string TSIG::base64Encode(const string& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.c_str(), data.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return encoded;
}

string TSIG::computeHMAC(Algorithm algo, const string& key, const string& data) {
    const EVP_MD* md = NULL;
    
    switch (algo) {
        case HMAC_MD5:    md = EVP_md5(); break;
        case HMAC_SHA1:   md = EVP_sha1(); break;
        case HMAC_SHA256: md = EVP_sha256(); break;
        case HMAC_SHA384: md = EVP_sha384(); break;
        case HMAC_SHA512: md = EVP_sha512(); break;
    }
    
    if (!md)
        return "";
    
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    
    HMAC(md, key.c_str(), key.length(),
         (unsigned char*)data.c_str(), data.length(),
         result, &result_len);
    
    return string((char*)result, result_len);
}

RRTSIG* TSIG::extractTSIG(const Message* msg) {
    // TSIG must be the last record in additional section
    if (msg->ar.empty())
        return NULL;
    
    RR* last = msg->ar.back();
    if (last->type != RR::TSIG)
        return NULL;
    
    return dynamic_cast<RRTSIG*>(last);
}

string TSIG::buildSigningData(const char* message,
                              unsigned int message_len,
                              const RRTSIG* tsig,
                              bool include_mac) {
    string data;
    
    if (include_mac) {
        // For responses, include request MAC (2-byte length + MAC)
        uint16_t mac_size = htons(tsig->mac.length());
        data.append((char*)&mac_size, 2);
        data.append(tsig->mac);
    }
    
    // DNS Message without TSIG
    // Per RFC 2845: entire DNS message with TSIG RR removed and ARCOUNT decremented
    
    if (message_len < 12) {
        return data; // Invalid message
    }
    
    // Step 1: Parse header to get counts
    uint16_t qdcount = ntohs(*(uint16_t*)&message[4]);
    uint16_t ancount = ntohs(*(uint16_t*)&message[6]);
    uint16_t nscount = ntohs(*(uint16_t*)&message[8]);
    uint16_t arcount = ntohs(*(uint16_t*)&message[10]);
    
    // Step 2: Find where TSIG record starts (it's the last AR record)
    unsigned int offset = 12; // Start after DNS header
    
    // Helper lambda to skip a domain name
    auto skip_name = [&]() {
        while (offset < message_len) {
            unsigned char len = (unsigned char)message[offset];
            if (len == 0) {
                offset++;
                return;
            }
            if ((len & 0xC0) == 0xC0) { // Compression pointer
                offset += 2;
                return;
            }
            offset += len + 1;
        }
    };
    
    // Helper lambda to skip an RR
    auto skip_rr = [&]() {
        skip_name(); // Skip name
        if (offset + 10 > message_len) return;
        uint16_t rdlength = ntohs(*(uint16_t*)&message[offset + 8]);
        offset += 10 + rdlength; // type(2) + class(2) + ttl(4) + rdlen(2) + rdata
    };
    
    // Skip QD section
    for (uint16_t i = 0; i < qdcount && offset < message_len; i++) {
        skip_name();
        offset += 4; // type + class
    }
    
    // Skip AN section
    for (uint16_t i = 0; i < ancount && offset < message_len; i++) {
        skip_rr();
    }
    
    // Skip NS section
    for (uint16_t i = 0; i < nscount && offset < message_len; i++) {
        skip_rr();
    }
    
    // Skip AR section except last record (TSIG)
    for (uint16_t i = 0; i < arcount - 1 && offset < message_len; i++) {
        skip_rr();
    }
    
    // Now offset points to where TSIG starts
    // Copy message up to TSIG, but with adjusted ARCOUNT in header
    
    // Copy header with decremented ARCOUNT
    data.append(message, 10); // ID through NSCOUNT
    uint16_t new_arcount = htons(arcount > 0 ? arcount - 1 : 0);
    data.append((char*)&new_arcount, 2);
    
    // Copy rest of message up to (but not including) TSIG
    if (offset > 12 && offset <= message_len) {
        data.append(&message[12], offset - 12);
    }
    
    // TSIG Variables (RFC 2845 section 3.4.2)
    // These are NOT in wire format, but specific encoding:
    
    // TSIG record name (wire format)
    char name_buf[256];
    unsigned int name_offset = 0;
    RR::packName(name_buf, sizeof(name_buf), name_offset, tsig->name);
    data.append(name_buf, name_offset);
    
    // TSIG class (2 bytes) - ANY
    uint16_t tsig_class = htons(RR::CLASSANY);
    data.append((char*)&tsig_class, 2);
    
    // TSIG TTL (4 bytes) - always 0
    uint32_t tsig_ttl = 0;
    data.append((char*)&tsig_ttl, 4);
    
    // Algorithm name (wire format)
    char algo_buf[256];
    unsigned int algo_offset = 0;
    RR::packName(algo_buf, sizeof(algo_buf), algo_offset, tsig->algorithm);
    data.append(algo_buf, algo_offset);
    
    // Time signed (48 bits: 16-bit high + 32-bit low)
    uint16_t time_high = htons(tsig->time_signed_high);
    uint32_t time_low = htonl(tsig->time_signed_low);
    data.append((char*)&time_high, 2);
    data.append((char*)&time_low, 4);
    
    // Fudge (16 bits)
    uint16_t fudge = htons(tsig->fudge);
    data.append((char*)&fudge, 2);
    
    // Error (16 bits)
    uint16_t error = htons(tsig->error);
    data.append((char*)&error, 2);
    
    // Other length (16 bits)
    uint16_t other_len = htons(tsig->other_len);
    data.append((char*)&other_len, 2);
    
    // Other data (if present)
    if (tsig->other_len > 0) {
        data.append(tsig->other_data);
    }
    
    return data;
}

bool TSIG::verify(const Message* msg,
                 const char* raw_message,
                 unsigned int raw_length,
                 const Key* key,
                 string& error) {
    // Extract TSIG record
    RRTSIG* tsig = extractTSIG(msg);
    
    if (!tsig) {
        // No TSIG in message
        if (key) {
            error = "TSIG required but not present";
            return false;
        }
        // No TSIG required, no TSIG present - OK
        return true;
    }
    
    if (!key) {
        error = "TSIG present but no key configured";
        return false;
    }
    
    // Check key name matches
    if (dns_name_tolower(tsig->name) != dns_name_tolower(key->name)) {
        error = "TSIG key name mismatch";
        return false;
    }
    
    // Check algorithm matches
    Algorithm msg_algo = algorithmFromName(tsig->algorithm);
    if (msg_algo != key->algorithm) {
        error = "TSIG algorithm mismatch";
        return false;
    }
    
    // Check time (within fudge)
    uint64_t now = time(NULL);
    uint64_t time_signed = tsig->getTimeSigned();
    uint64_t time_diff = (now > time_signed) ? (now - time_signed) : (time_signed - now);
    
    if (time_diff > tsig->fudge) {
        error = "TSIG time check failed";
        return false;
    }
    
    // Build signing data
    string signing_data = buildSigningData(raw_message, raw_length, tsig, false);
    
    // Compute expected MAC
    string expected_mac = computeHMAC(key->algorithm, key->decoded_secret, signing_data);
    
    // Compare MACs
    if (expected_mac != tsig->mac) {
        error = "TSIG signature verification failed";
        return false;
    }
    
    return true;
}

bool TSIG::sign(Message* msg,
               char* raw_message,
               unsigned int& raw_length,
               const Key* key,
               unsigned short original_id,
               string& error) {
    if (!key) {
        error = "No TSIG key provided";
        return false;
    }
    
    // Create TSIG record
    RRTSIG* tsig = new RRTSIG();
    tsig->name = key->name;
    tsig->type = RR::TSIG;
    tsig->rrclass = RR::CLASSANY;
    tsig->ttl = 0;
    tsig->algorithm = algorithmToName(key->algorithm);
    tsig->setTimeSigned(time(NULL));
    tsig->fudge = 300;
    tsig->original_id = original_id;
    tsig->error = 0;
    tsig->other_len = 0;
    
    // Build signing data (without MAC first)
    string signing_data = buildSigningData(raw_message, raw_length, tsig, false);
    
    // Compute MAC
    tsig->mac = computeHMAC(key->algorithm, key->decoded_secret, signing_data);
    tsig->mac_size = tsig->mac.length();
    
    // Add TSIG to message
    msg->ar.push_back(tsig);
    
    // Repack message with TSIG
    unsigned int new_offset = 0;
    msg->pack(raw_message, 65536, new_offset);
    raw_length = new_offset;
    
    return true;
}
