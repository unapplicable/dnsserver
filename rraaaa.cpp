#include "rraaaa.h"

static std::string bin2aaaa(const std::string& in)
{
	std::string res;
	for (std::string::size_type i = 0; i < in.length(); i += 2)
	{
		res.append(bin2hex(in[i]));
		res.append(bin2hex(in[i + 1]));	
		res.append(1, ':');
	}

	return res;
}

static std::string aaaa2bin(const std::string& in)
{
	std::string res;
	for (std::string::size_type i = 0; i < in.length(); i += 5)
	{
		res.append(1, hex2bin(in.substr(i, 2)));
		res.append(1, hex2bin(in.substr(i + 2, 2)));
	}
	
	return res;
}

void RRAAAA::fromStringContents(const std::vector<std::string>& tokens, const std::string& /* origin */)
{
	rdata = aaaa2bin(tokens[0]);
}

std::ostream& RRAAAA::dumpContents(std::ostream& os) const
{
	return os << bin2aaaa(rdata);
}