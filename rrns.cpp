#include "socket.h"
#include "rrns.h"

void RRNS::fromStringContents(const std::vector<std::string>& tokens, const std::string& origin)
{
	rdata = process_domain_name(tokens[0], origin);
}

std::ostream& RRNS::dumpContents(std::ostream& os) const
{
	return os << rdata;
}

std::string RRNS::toString() const
{
	return name + " " + std::to_string(ttl) + " IN NS " + rdata;
}

bool RRNS::unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery)
{
	if (!RR::unpack(data, len, offset, isQuery))
		return false;
	
	if (isQuery)
		return true;
	
	unsigned int rdataOffset = offset - rdlen;
	rdata = unpackNameWithDot(data, len, rdataOffset);
	return true;
}

void RRNS::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}