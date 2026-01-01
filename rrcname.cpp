#include "socket.h"
#include "rrcname.h"

std::ostream& RRCNAME::dumpContents(std::ostream& os) const
{
	return os << rdata;
}

void RRCNAME::fromStringContents(const std::vector<std::string>& tokens)
{
	rdata = tokens[0];
}

bool RRCNAME::unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery)
{
	if (!RR::unpack(data, len, offset, isQuery))
		return false;
	
	if (isQuery)
		return true;
	
	unsigned int rdataOffset = offset - rdlen;
	rdata = unpackNameWithDot(data, len, rdataOffset);
	return true;
}

void RRCNAME::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}