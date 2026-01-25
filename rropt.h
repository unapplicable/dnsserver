#ifndef HAVE_RROPT_H
#define HAVE_RROPT_H

#include "rr.h"
#include <string>
#include <cstdint>
#include <vector>

// OPT pseudo-RR for EDNS(0) - RFC 6891
// EDNS provides DNS extension mechanisms including:
// - UDP payload size negotiation
// - Extended RCODE support
// - DNSSEC OK (DO) flag
// - Optional data (options)
class RROPT : public RR
{
public:
    // EDNS fields stored in the pseudo-RR header
    uint16_t udp_payload_size;  // Stored in CLASS field
    uint8_t extended_rcode;     // High 8 bits of extended RCODE (stored in TTL)
    uint8_t version;            // EDNS version (stored in TTL)
    uint16_t flags;             // EDNS flags including DO bit (stored in TTL)
    
    // EDNS options stored in RDATA
    struct EDNSOption {
        uint16_t code;
        std::string data;
    };
    std::vector<EDNSOption> options;
    
    RROPT() : RR()
    {
        type = OPT;
        name = ".";  // OPT RR name must be root (empty)
        udp_payload_size = 4096;  // Default 4096 bytes
        extended_rcode = 0;
        version = 0;  // EDNS version 0
        flags = 0;
        rrclass = (RRClass)udp_payload_size;  // CLASS field holds UDP size
        ttl = 0;  // TTL holds extended RCODE, version, and flags
    }
    
    virtual bool unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery) override;
    virtual void packContents(char* data, unsigned int len, unsigned int& offset) override;
    void pack(char *data, unsigned int len, unsigned int& offset);
    virtual std::ostream& dumpContents(std::ostream& os) const override;
    virtual RR* clone() const override { return new RROPT(*this); }
    
    // Helper methods
    bool getDO() const { return (flags & 0x8000) != 0; }  // DNSSEC OK bit
    void setDO(bool enable) { 
        if (enable) 
            flags |= 0x8000; 
        else 
            flags &= ~0x8000; 
    }
    
    void addOption(uint16_t code, const std::string& data) {
        EDNSOption opt;
        opt.code = code;
        opt.data = data;
        options.push_back(opt);
    }
    
    // Synchronize the pseudo-RR fields with base RR fields
    void syncFields() {
        rrclass = (RRClass)udp_payload_size;
        // Pack TTL: extended_rcode (8 bits) | version (8 bits) | flags (16 bits)
        ttl = ((uint32_t)extended_rcode << 24) | ((uint32_t)version << 16) | (uint32_t)flags;
    }
    
    void extractFields() {
        udp_payload_size = (uint16_t)rrclass;
        extended_rcode = (ttl >> 24) & 0xFF;
        version = (ttl >> 16) & 0xFF;
        flags = ttl & 0xFFFF;
    }
};

#endif
