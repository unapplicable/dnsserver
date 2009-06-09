#include "rrcert.h"

void RRCERT::fromStringContents(const std::vector<std::string>& tokens)
{
	rdata.append("\x01\x00\x00\x00\x00", 5);
	for (unsigned int i = 0; i < tokens[0].length(); i += 2)
		rdata += hex2bin(tokens[0].substr(i, 2));
}
