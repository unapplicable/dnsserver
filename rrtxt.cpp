#include "socket.h"
#include "rrtxt.h"

void RRTXT::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	data[offset++] = (unsigned char)rdata.length();
	rdata.copy(&data[offset], rdata.length());
	offset += (unsigned int)rdata.length();
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
