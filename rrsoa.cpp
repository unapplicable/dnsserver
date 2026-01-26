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

void RRSoa::fromStringContents(const std::vector<std::string>& tokens, const std::string& origin)
{
	ns = process_domain_name(tokens[0], origin);
	mail = process_domain_name(tokens[1], origin);
	serial = atoi(tokens[2].c_str());
	refresh = atoi(tokens[3].c_str());
	retry = atoi(tokens[4].c_str());
	expire = atoi(tokens[5].c_str());
	minttl = atoi(tokens[6].c_str());
};

bool RRSoa::unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery)
{
	if (!RR::unpack(data, len, offset, isQuery))
		return false;
	
	if (isQuery)
		return true;
	
	// Handle empty RDATA (rdlen=0) - valid for DNS UPDATE operations
	// RFC 2136: empty RDATA in UPDATE section means "delete all RRsets from a name"
	if (rdlen == 0)
	{
		ns = "";
		mail = "";
		serial = 0;
		refresh = 0;
		retry = 0;
		expire = 0;
		minttl = 0;
		return true;
	}
	
	unsigned int rdataOffset = offset - rdlen;
	unsigned int rdataEnd = offset;
	
	ns = unpackNameWithDot(data, len, rdataOffset);
	mail = unpackNameWithDot(data, len, rdataOffset);
	
	if (rdataOffset + 20 > rdataEnd)
		return false;
	
	serial = ntohl(*(uint32_t*)&data[rdataOffset]);
	rdataOffset += 4;
	
	refresh = ntohl(*(uint32_t*)&data[rdataOffset]);
	rdataOffset += 4;
	
	retry = ntohl(*(uint32_t*)&data[rdataOffset]);
	rdataOffset += 4;
	
	expire = ntohl(*(uint32_t*)&data[rdataOffset]);
	rdataOffset += 4;
	
	minttl = ntohl(*(uint32_t*)&data[rdataOffset]);
	rdataOffset += 4;
	
	return true;
}

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

std::string RRSoa::toString() const
{
std::ostringstream ss;
ss << name << " IN SOA " << ns << " " << mail << " " << serial << " " 
   << refresh << " " << retry << " " << expire << " " << minttl;
return ss.str();
}
