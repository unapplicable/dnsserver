#include "socket.h"
#include "wire.h"
#include "rrtxt.h"

void RRTXT::packContents(char* data, unsigned int /* len */, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	// A DNS TXT record is a sequence of character-strings, each at most 255
	// bytes (RFC 1035 3.3.14). Long values (e.g. a 2048-bit DKIM key) must be
	// split across multiple strings; receivers concatenate them.
	const std::string& v = rdata;
	std::string::size_type pos = 0;
	while (pos < v.size())
	{
		std::string::size_type n = v.size() - pos > 255 ? 255 : v.size() - pos;
		data[offset++] = (unsigned char)n;
		v.copy(&data[offset], n, pos);
		offset += n;
		pos += n;
	}
	unsigned int packedrdlen = offset - (oldoffset + 2);
	wire_write_u16(data, oldoffset, packedrdlen);
}

void RRTXT::fromStringContents(const std::vector<std::string>& tokens, const std::string& /* origin */)
{
	for (unsigned int i = 0; i < tokens.size(); ++i)
					rdata += (i != 0 ? " " : "" )+ tokens[i];
}

std::ostream& RRTXT::dumpContents(std::ostream& os) const
{
	return os << rdata;
}

std::string RRTXT::toString() const
{
	return name + " " + std::to_string(ttl) + " IN TXT " + rdata;
}
