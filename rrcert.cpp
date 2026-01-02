#include "rrcert.h"
#include <iomanip>
#include <sstream>

std::ostream& RRCERT::dumpContents(std::ostream& os) const
{
	// CERT format: type key_tag algorithm certificate_data
	// For simplicity, we dump the raw data fields stored in rdata
	if (rdata.length() >= 5)
	{
		unsigned char type = rdata[0];
		unsigned char key_tag_hi = rdata[1];
		unsigned char key_tag_lo = rdata[2];
		unsigned char algorithm = rdata[3];
		
		os << (unsigned int)type << " "
		   << (unsigned int)((key_tag_hi << 8) | key_tag_lo) << " "
		   << (unsigned int)algorithm << " ";
		
		// Output cert data in hex
		for (unsigned int i = 4; i < rdata.length(); ++i)
			os << std::hex << std::setfill('0') << std::setw(2) 
			   << (unsigned int)((unsigned char)rdata[i]);
	}
	return os;
}

void RRCERT::fromStringContents(const std::vector<std::string>& tokens, const std::string& /* origin */)
{
	rdata.append("\x01\x00\x00\x00\x00", 5);
	for (unsigned int i = 0; i < tokens[0].length(); i += 2)
		rdata += hex2bin(tokens[0].substr(i, 2));
}
