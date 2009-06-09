#include "socket.h"
#include "rrns.h"

void RRNS::fromStringContents(const std::vector<std::string>& tokens)
{
	rdata = tokens[0];
}

std::ostream& RRNS::dumpContents(std::ostream& os) const
{
	return os << rdata;
}

void RRNS::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}