#ifndef HAVE_RRTSIG_H
#define HAVE_RRTSIG_H

#include "rr.h"
#include <string>
#include <cstdint>

// TSIG (Transaction Signature) Resource Record - RFC 2845
// Provides DNS message authentication using shared secrets
class RRTSIG : public RR
{
public:
    std::string algorithm;  // Algorithm name (e.g., hmac-sha256)
    unsigned long time_signed_high;  // High 16 bits of time signed
    unsigned long time_signed_low;   // Low 32 bits of time signed
    unsigned short fudge;            // Time fudge (seconds)
    unsigned short mac_size;         // MAC size in octets
    std::string mac;                 // Message Authentication Code
    unsigned short original_id;      // Original message ID
    unsigned short error;            // Error code
    unsigned short other_len;        // Other data length
    std::string other_data;          // Other data
    
    RRTSIG() : RR()
    {
        type = TSIG;
        time_signed_high = 0;
        time_signed_low = 0;
        fudge = 300;  // Default 5 minute fudge
        mac_size = 0;
        original_id = 0;
        error = 0;
        other_len = 0;
    }
    
    virtual bool unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery) override;
    virtual void packContents(char* data, unsigned int len, unsigned int& offset) override;
    virtual std::ostream& dumpContents(std::ostream& os) const override;
    virtual RR* clone() const override { return new RRTSIG(*this); }
    
    // Helper to get full 48-bit timestamp
    uint64_t getTimeSigned() const {
        return ((uint64_t)time_signed_high << 32) | time_signed_low;
    }
    
    void setTimeSigned(uint64_t time) {
        time_signed_high = (time >> 32) & 0xFFFF;
        time_signed_low = time & 0xFFFFFFFF;
    }
};

#endif
