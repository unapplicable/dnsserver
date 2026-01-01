#include "rr.h"
#include "socket.h"

#include "rrsoa.h"
#include "rrmx.h"
#include "rrtxt.h"
#include "rrptr.h"
#include "rrcname.h"
#include "rrns.h"
#include "rraaaa.h"
#include "rra.h"
#include "rrcert.h"
#include "rrdhcid.h"

#include <cstring>
#include <exception>

static char *hextab = (char*)"0123456789ABCDEF";

unsigned char hex2bin(const std::string& hex)
{
	unsigned char res = 0;
	res |= static_cast<unsigned char>((strchr(hextab, toupper(hex[0])) - hextab)) << 4;
	res |= static_cast<unsigned char>((strchr(hextab, toupper(hex[1])) - hextab));
	return res;
}

std::string bin2hex(unsigned char bin)
{
	std::string res;
	res += hextab[bin >> 4 & 0x0F];
	res += hextab[bin & 0x0F];

	return res;
}

std::ostream& operator <<(std::ostream& os, const RR::RRType rrt)
{
	return os << RR::RRTypeToString(rrt);	
}

std::ostream& operator <<(std::ostream& os, const RR::RRClass rrc)
{
	return os << RR::RRClassToString(rrc);	
}

std::ostream& operator <<(std::ostream& os, const RR& r)
{
	os << r.rrclass << " " << r.type << " " << r.name;
	if (r.query)
		return os;

	os << " = ";

	r.dumpContents(os);

	return os << " (ttl:" << r.ttl << ")";
}


std::ostream& RR::dumpContents(std::ostream& os) const
{
	for (unsigned int i = 0; i < rdata.length(); ++i)
		os << std::hex << ((unsigned int)rdata[i] & 0xFF) << " ";

	return os;	
}

void RR::packName(char *data, unsigned int /* len */, unsigned int& offset, std::string name, bool terminate)
{
	std::string part;
	do
	{
		std::string::size_type dot;
		if ((dot = name.find('.')) != std::string::npos)
		{
			part = name.substr(0, dot);
			name.erase(0, dot + 1);
		} else
		{
			part = name;
			name.clear();
		};

		if (terminate || !part.empty())
		{
			data[offset++] = (unsigned char)part.length();
			part.copy(&data[offset], part.length());
			offset += (unsigned int)part.length();
		}
		
	} while (!part.empty());
}

std::string RR::unpackName(char *data, unsigned int len, unsigned int& offset)
{
	std::string name;
	unsigned int& iter = offset;
	bool packed = false;
	

	for (unsigned int i = iter; ;)
	{
		if (i >= len)
			throw std::exception();

		unsigned char tokencode = (unsigned char)data[i];
		if ((tokencode & 0xC0) == 0xC0)
		{
			i = ntohs((unsigned short &)data[i]) & ~0xC000;
			if (!packed)
			{
				iter += 2;
				packed = true;
			}
			continue;
		} else
		{
			i++;
			if (!packed)
				iter = i;
		}

		if (tokencode == 0)
			break;

		if (i + tokencode >= len)
			throw std::exception();

		if (!name.empty())
			name += '.';

		name.append(data + i, tokencode);
		

		i += tokencode;
		if (!packed)
			iter = i;
	}

	return name;
}

RR* RR::createByType(RRType type)
{
	switch (type)
	{
		case SOA:
			return new RRSoa();

		case MX:
			return new RRMX();

		case TXT:
			return new RRTXT();

		case PTR:
			return new RRPTR();

		case CNAME:
			return new RRCNAME();

		case NS:
			return new RRNS();

		case AAAA:
			return new RRAAAA();

		case A:
			return new RRA();

		case CERT:
			return new RRCERT();

		case DHCID:
			return new RRDHCID();

		default:
			// For unknown RR types, return a base RR object
			// It will store and forward the rdata as-is
			return new RR();
	}
}

void RR::fromString(const std::vector<std::string>& tokens)
{
	name = dns_name_tolower(tokens[0]);

	if (tokens[1] == "IN")
		rrclass = CLASSIN;
	else
	if (tokens[1] == "CH")
		rrclass = CH;
	else
	if (tokens[1] == "*" || tokens[1] == "ANY")
		rrclass = CLASSANY;
	else
		rrclass = CLASSUNDEF;

	type = RRTypeFromString(tokens[2]);

	fromStringContents(std::vector<std::string>(tokens.begin() + 3, tokens.end()));
}

void RR::fromStringContents(const std::vector<std::string>& /* tokens */)
{
	throw std::exception();
}

void RR::packContents(char* data, unsigned int /* len */, unsigned int& offset)
{
	rdata.copy(&data[offset], rdlen);
	offset += rdlen;
}

void RR::pack(char *data, unsigned int len, unsigned int& offset)
{
	packName(data, len, offset, name);

	(unsigned short&)data[offset] = htons(type);
	offset += 2;

	(unsigned short&)data[offset] = htons(rrclass);
	offset += 2;

	if (query)
		return;

	(unsigned long&)data[offset] = htonl(ttl);
	offset += 4;

	rdlen = static_cast<unsigned short>(rdata.length());
	(unsigned short&)data[offset] = htons(rdlen);
	offset += 2;

	packContents(data, len, offset);
}

bool RR::unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery)
{
	query = isQuery;
	name.clear();

	name = dns_name_tolower(unpackName(data, len, offset));
	
	// Ensure name has trailing dot for consistency with zone file loading
	if (!name.empty() && name[name.length()-1] != '.')
		name += '.';

	if (offset + 1 >= len)
		return false;

	type = (RRType)ntohs((short &)data[offset]);
	offset += 2;

	if (offset + 1 >= len)
		return false;

	rrclass = (RRClass)ntohs((short &)data[offset]);
	offset += 2;

	if (query)
	{
		ttl = 0;
		rdlen = 0;
		rdata.clear();
		return true;
	}

	if (offset + 3 >= len)
		return false;

	ttl = ntohl(*(uint32_t*)&data[offset]);
	offset += 4;

	if (offset + 1 >= len)
		return false;

	rdlen = ntohs(*(uint16_t*)&data[offset]);
	offset += 2;

	if (offset + rdlen > len)
		return false;

	rdata.clear();
	rdata.append(data + offset, rdlen);
	
	offset += rdlen;
	return true;
}
