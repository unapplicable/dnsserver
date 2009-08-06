#include "socket.h"
#include "rrtxt.h"

void RRTXT::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, rdata, false);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}

void RRTXT::fromStringContents(const std::vector<std::string>& tokens)
{
	for (unsigned int i = 0; i < tokens.size(); ++i)
					rdata += (i != 0 ? " " : "" )+ tokens[i];
}

std::ostream& RRTXT::dumpContents(std::ostream& os) const
{
	return os << rdata;
}