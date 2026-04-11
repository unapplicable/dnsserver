#include "rrtsig.h"
#include "wire.h"
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>

using namespace std;

bool RRTSIG::unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery)
{
    if (!RR::unpack(data, len, offset, isQuery))
        return false;
    
    if (isQuery)
        return true;
    
    // Unpack TSIG rdata
    unsigned int rdata_offset = 0;
    
    // Algorithm name
    algorithm = RR::unpackNameWithDot((char*)rdata.data(), rdata.length(), rdata_offset);
    
    // Time signed (48 bits)
    if (rdata_offset + 6 > rdata.length())
        return false;
    time_signed_high = wire_read_u16(rdata.data(), rdata_offset);
    rdata_offset += 2;
    time_signed_low = wire_read_u32(rdata.data(), rdata_offset);
    rdata_offset += 4;
    
    // Fudge
    if (rdata_offset + 2 > rdata.length())
        return false;
    fudge = wire_read_u16(rdata.data(), rdata_offset);
    rdata_offset += 2;
    
    // MAC size and MAC
    if (rdata_offset + 2 > rdata.length())
        return false;
    mac_size = wire_read_u16(rdata.data(), rdata_offset);
    rdata_offset += 2;
    
    if (rdata_offset + mac_size > rdata.length())
        return false;
    mac.assign(&rdata[rdata_offset], mac_size);
    rdata_offset += mac_size;
    
    // Original ID
    if (rdata_offset + 2 > rdata.length())
        return false;
    original_id = wire_read_u16(rdata.data(), rdata_offset);
    rdata_offset += 2;
    
    // Error
    if (rdata_offset + 2 > rdata.length())
        return false;
    error = wire_read_u16(rdata.data(), rdata_offset);
    rdata_offset += 2;
    
    // Other length and other data
    if (rdata_offset + 2 > rdata.length())
        return false;
    other_len = wire_read_u16(rdata.data(), rdata_offset);
    rdata_offset += 2;
    
    if (rdata_offset + other_len > rdata.length())
        return false;
    if (other_len > 0)
        other_data.assign(&rdata[rdata_offset], other_len);
    
    return true;
}

void RRTSIG::packContents(char* data, unsigned int len, unsigned int& offset)
{
    // Pack algorithm name
    RR::packName(data, len, offset, algorithm);
    
    // Pack time signed (48 bits)
    wire_write_u16(data, offset, time_signed_high);
    offset += 2;
    wire_write_u32(data, offset, time_signed_low);
    offset += 4;
    
    // Pack fudge
    wire_write_u16(data, offset, fudge);
    offset += 2;
    
    // Pack MAC size and MAC
    wire_write_u16(data, offset, mac_size);
    offset += 2;
    mac.copy(&data[offset], mac_size);
    offset += mac_size;
    
    // Pack original ID
    wire_write_u16(data, offset, original_id);
    offset += 2;
    
    // Pack error
    wire_write_u16(data, offset, error);
    offset += 2;
    
    // Pack other length and data
    wire_write_u16(data, offset, other_len);
    offset += 2;
    if (other_len > 0) {
        other_data.copy(&data[offset], other_len);
        offset += other_len;
    }
}

ostream& RRTSIG::dumpContents(ostream& os) const
{
    os << "algorithm=" << algorithm 
       << " time=" << getTimeSigned()
       << " fudge=" << fudge
       << " mac_size=" << mac_size
       << " mac=";
    
    for (size_t i = 0; i < mac.length(); ++i) {
        os << hex << setfill('0') << setw(2) 
           << (int)(unsigned char)mac[i];
    }
    os << dec;
    
    return os;
}
