#include "socket.h"
#include "rrptr.h"

std::ostream& RRPTR::dumpContents(std::ostream& os) const
{
	return os << rdata;
}

std::string RRPTR::toString() const
{
	return name + " " + std::to_string(ttl) + " IN PTR " + rdata;
}

void RRPTR::fromStringContents(const std::vector<std::string>& tokens, const std::string& origin)
{
	rdata = process_domain_name(tokens[0], origin);
}

bool RRPTR::unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery)
{
	if (!RR::unpack(data, len, offset, isQuery))
		return false;
	
	if (isQuery)
		return true;
	
	// Handle empty RDATA (rdlen=0) - valid for DNS UPDATE operations
	// RFC 2136: empty RDATA in UPDATE section means "delete all RRsets from a name"
	if (rdlen == 0)
	{
		rdata = "";
		return true;
	}
	
	unsigned int rdataOffset = offset - rdlen;
	rdata = unpackNameWithDot(data, len, rdataOffset);
	return true;
}

void RRPTR::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}