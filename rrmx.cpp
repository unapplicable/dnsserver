#include "socket.h"
#include "rrmx.h"

std::ostream& RRMX::dumpContents(std::ostream& os) const
{
	return os << std::dec << pref << " " << rdata;
};

std::string RRMX::toString() const
{
	return name + " " + std::to_string(ttl) + " IN MX " + std::to_string(pref) + " " + rdata;
}

void RRMX::fromStringContents(const std::vector<std::string>& tokens, const std::string& origin)
{
	pref = atoi(tokens[0].c_str());
	rdata = process_domain_name(tokens[1], origin);
};

bool RRMX::unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery)
{
	if (!RR::unpack(data, len, offset, isQuery))
		return false;
	
	if (isQuery)
		return true;
	
	unsigned int rdataOffset = offset - rdlen;
	unsigned int rdataEnd = offset;
	
	if (rdataOffset + 2 > rdataEnd)
		return false;
	
	pref = ntohs(*(uint16_t*)&data[rdataOffset]);
	rdataOffset += 2;
	
	rdata = unpackNameWithDot(data, len, rdataOffset);
	return true;
}

void RRMX::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	(unsigned short&)data[offset] = htons(pref);
	offset += 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}

