#include "rropt.h"
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>

using namespace std;

bool RROPT::unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery)
{
    // Unpack name (should be root ".")
    name = RR::unpackName(data, len, offset);
    
    if (offset + 10 > len)
        return false;
    
    // Type (should be 41)
    type = (RRType)ntohs(*(uint16_t*)&data[offset]);
    offset += 2;
    
    if (type != OPT)
        return false;
    
    // CLASS field holds UDP payload size
    udp_payload_size = ntohs(*(uint16_t*)&data[offset]);
    rrclass = (RRClass)udp_payload_size;
    offset += 2;
    
    // TTL field holds extended RCODE, version, and flags
    ttl = ntohl(*(uint32_t*)&data[offset]);
    offset += 4;
    extractFields();
    
    // RDLEN
    rdlen = ntohs(*(uint16_t*)&data[offset]);
    offset += 2;
    
    if (offset + rdlen > len)
        return false;
    
    // Store raw rdata
    rdata.assign(&data[offset], rdlen);
    
    // Parse EDNS options from rdata
    unsigned int opt_offset = 0;
    while (opt_offset + 4 <= rdlen) {
        EDNSOption option;
        option.code = ntohs(*(uint16_t*)&rdata[opt_offset]);
        opt_offset += 2;
        
        uint16_t opt_len = ntohs(*(uint16_t*)&rdata[opt_offset]);
        opt_offset += 2;
        
        if (opt_offset + opt_len > rdlen)
            break;  // Malformed option
        
        option.data.assign(&rdata[opt_offset], opt_len);
        opt_offset += opt_len;
        
        options.push_back(option);
    }
    
    offset += rdlen;
    query = isQuery;
    
    return true;
}

void RROPT::packContents(char* data, unsigned int len, unsigned int& offset)
{
    // Pack RDATA only (rdata should already be built by pack())
    // This matches the base RR::packContents() pattern
    if (offset + rdlen > len)
        return;
    rdata.copy(&data[offset], rdlen);
    offset += rdlen;
}

void RROPT::pack(char *data, unsigned int len, unsigned int& offset)
{
    // Sync fields before packing
    syncFields();
    
    // Pack name (root ".")
    RR::packName(data, len, offset, name);
    
    // Pack type (OPT = 41)
    if (offset + 2 > len)
        return;
    *(uint16_t*)&data[offset] = htons(OPT);
    offset += 2;
    
    // Pack CLASS (UDP payload size)
    if (offset + 2 > len)
        return;
    *(uint16_t*)&data[offset] = htons(udp_payload_size);
    offset += 2;
    
    // Pack TTL (extended RCODE | version | flags)
    if (offset + 4 > len)
        return;
    *(uint32_t*)&data[offset] = htonl(ttl);
    offset += 4;
    
    // Rebuild rdata to get correct rdlen
    rdata.clear();
    for (const auto& opt : options) {
        uint16_t code_net = htons(opt.code);
        rdata.append((char*)&code_net, 2);
        
        uint16_t len_net = htons(opt.data.length());
        rdata.append((char*)&len_net, 2);
        
        rdata.append(opt.data);
    }
    rdlen = rdata.length();
    
    // Pack RDLEN
    if (offset + 2 > len)
        return;
    *(uint16_t*)&data[offset] = htons(rdlen);
    offset += 2;
    
    // Pack contents (RDATA with options)
    packContents(data, len, offset);
}

ostream& RROPT::dumpContents(ostream& os) const
{
    os << "EDNS: version=" << (int)version
       << " flags=" << hex << setfill('0') << setw(4) << flags << dec
       << " udp=" << udp_payload_size;
    
    if (getDO())
        os << " do";
    
    if (!options.empty()) {
        os << " options=" << options.size();
        for (const auto& opt : options) {
            os << " {code=" << opt.code << " len=" << opt.data.length() << "}";
        }
    }
    
    return os;
}
