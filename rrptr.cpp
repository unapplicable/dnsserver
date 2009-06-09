#include "socket.h"
#include "rrptr.h"

std::ostream& RRPTR::dumpContents(std::ostream& os) const
{
	return os << rdata;
}

void RRPTR::fromStringContents(const std::vector<std::string>& tokens)
{
	rdata = tokens[0];
}

void RRPTR::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}