#include "socket.h"
#include "rra.h"

static std::string bin2a(const std::string& in)
{
	return inet_ntoa(*reinterpret_cast<const in_addr*>(in.c_str()));
}

static std::string a2bin(const std::string& in)
{
	std::string res;
	unsigned long a = inet_addr(in.c_str());
	res.append(reinterpret_cast<char*>(&a), 4);
	return res;
}

std::ostream& RRA::dumpContents(std::ostream& os) const
{
	return os << bin2a(rdata);
}

void RRA::fromStringContents(const std::vector<std::string>& tokens)
{
	rdata = a2bin(tokens[0]);
}