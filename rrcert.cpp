#include "rrcert.h"

std::ostream& RRCERT::dumpContents(std::ostream& os) const
{

    for (unsigned int i = 0; i < rdata.length(); ++i)
        os << std::hex << ((unsigned int)rdata[i] & 0xFF) << " ";

    return os;
}

void RRCERT::fromStringContents(const std::vector<std::string>& tokens)
{
	rdata.append("\x01\x00\x00\x00\x00", 5);
	for (unsigned int i = 0; i < tokens[0].length(); i += 2)
		rdata += hex2bin(tokens[0].substr(i, 2));
}
