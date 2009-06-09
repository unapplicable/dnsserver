#include "socket.h"
#include "rrmx.h"

std::ostream& RRMX::dumpContents(std::ostream& os) const
{
	return os << std::dec << pref << " " << rdata;
};

void RRMX::fromStringContents(const std::vector<std::string>& tokens)
{
	pref = atoi(tokens[0].c_str());
	rdata = tokens[1];	
};

void RRMX::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	(unsigned short&)data[offset] = htons(10);
	offset += 2;
	packName(data, len, offset, rdata);
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}

