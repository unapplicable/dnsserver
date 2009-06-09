#include "socket.h"
#include "rrsoa.h"

std::ostream& RRSoa::dumpContents(std::ostream& os) const
{
	os << "ns [" << ns << "] ";
	os << "mail [" << mail << "] ";
	os << "serial [" << serial << "] ";
	os << "refresh [" << refresh << "] ";
	os << "retry [" << retry << "] ";
	os << "expire [" << expire << "] ";
	os << "minttl [" << minttl << "] ";
	return os;
};

void RRSoa::fromStringContents(const std::vector<std::string>& tokens)
{
	ns = tokens[0];
	mail = tokens[1];
	serial = atoi(tokens[2].c_str());
	refresh = atoi(tokens[3].c_str());
	retry = atoi(tokens[4].c_str());
	expire = atoi(tokens[5].c_str());
	minttl = atoi(tokens[6].c_str());
};

void RRSoa::packContents(char* data, unsigned int len, unsigned int& offset)
{
	unsigned int oldoffset = offset - 2;
	packName(data, len, offset, ns); // ns
	packName(data, len, offset, mail); // mail
	(unsigned long&)data[offset] = htonl(serial); // serial
	offset += 4;
	(unsigned long&)data[offset] = htonl(refresh); // refresh
	offset += 4;
	(unsigned long&)data[offset] = htonl(retry); // retry
	offset += 4;
	(unsigned long&)data[offset] = htonl(expire); // expire
	offset += 4;
	(unsigned long&)data[offset] = htonl(minttl); // minttl
	offset += 4;

	unsigned int packedrdlen = offset - (oldoffset + 2);
	(unsigned short&)data[oldoffset] = htons(packedrdlen);	
}
