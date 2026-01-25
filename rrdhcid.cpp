#include "socket.h"
#include "rrdhcid.h"
#include "tsig.h"
#include <sstream>
#include <iomanip>

bool RRDHCID::unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery)
{
	if (!RR::unpack(data, len, offset, isQuery))
		return false;
	
	if (isQuery)
		return true;
	
	// rdata contains the raw binary DHCID data
	identifier = rdata;
	return true;
}

std::ostream& RRDHCID::dumpContents(std::ostream& os) const
{
	// DHCID is stored as binary data internally, encode to base64 for zone file
	os << TSIG::base64Encode(identifier);
	return os;
}

void RRDHCID::fromStringContents(const std::vector<std::string>& tokens, const std::string& /* origin */)
{
	if (tokens.size() > 0)
	{
		// DHCID in zone files is base64-encoded, decode it to binary
		identifier = TSIG::base64Decode(tokens[0]);
		rdata = identifier;
	}
}

void RRDHCID::packContents(char* data, unsigned int /* len */, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	
	identifier.copy(&data[offset], identifier.length());
	offset += static_cast<unsigned int>(identifier.length());
	
	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);
}
