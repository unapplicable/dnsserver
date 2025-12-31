#include "socket.h"
#include "rrdhcid.h"
#include <sstream>
#include <iomanip>

std::ostream& RRDHCID::dumpContents(std::ostream& os) const
{
	os << "dhcid [";
	for (size_t i = 0; i < identifier.length(); ++i)
	{
		os << std::hex << std::setfill('0') << std::setw(2) 
		   << (static_cast<unsigned int>(static_cast<unsigned char>(identifier[i])));
		if (i < identifier.length() - 1)
			os << " ";
	}
	os << "]";
	return os;
}

void RRDHCID::fromStringContents(const std::vector<std::string>& tokens)
{
	if (tokens.size() > 0)
	{
		identifier = tokens[0];
	}
}

void RRDHCID::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	
	identifier.copy(&data[offset], identifier.length());
	offset += static_cast<unsigned int>(identifier.length());
	
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}
