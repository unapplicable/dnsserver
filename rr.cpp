#include "rr.h"
#include "socket.h"

#include "rrsoa.h"

#include <cstring>

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

std::string bin2aaaa(const std::string& in)
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

std::string bin2a(const std::string& in)
{
	return inet_ntoa(*reinterpret_cast<const in_addr*>(in.c_str()));
}

std::string aaaa2bin(const std::string& in)
{
	std::string res;
	for (std::string::size_type i = 0; i < in.length(); i += 5)
	{
		res.append(1, hex2bin(in.substr(i, 2)));
		res.append(1, hex2bin(in.substr(i + 2, 2)));
	}
	
	return res;
}

std::string a2bin(const std::string& in)
{
	std::string res;
	unsigned long a = inet_addr(in.c_str());
	res.append(reinterpret_cast<char*>(&a), 4);
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
	switch (type)
	{
		case CNAME:
		case PTR:
		case TXT:
		{
			os << rdata;
			break;
		}

		case MX:
		{
			
			os << std::dec << 10 << " " << rdata;
			break;
		}

		case A:
		{
			os << bin2a(rdata);
			break;
		}

		case AAAA:
		{
			os << bin2aaaa(rdata);
			break;
		}

		default:
			for (unsigned int i = 0; i < rdata.length(); ++i)
				os << std::hex << (unsigned char)rdata[i] << " ";
			break;
	}

	return os;	
}

void RR::packName(char *data, unsigned int len, unsigned int& offset, std::string name, bool terminate)
{
	std::string part;
	do
	{
		std::string::size_type dot;
		if ((dot = name.find('.')) != -1)
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
		if ((tokencode & 0xC0) != 0)
		{
			i = ntohs((unsigned short &)data[i]) & ~0xC000;
			iter += 2;
			packed = true;
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

		default:
			return new RR();
	}
}

void RR::fromString(const std::vector<std::string>& tokens)
{
	name = tokens[0];

	if (tokens[1] == "IN")
		rrclass = CLASSIN;
	else
	if (tokens[1] == "CH")
		rrclass = CH;
	else
	if (tokens[1] == "*")
		rrclass = CLASSSTAR;
	else
		rrclass = CLASSUNDEF;

	type = RRTypeFromString(tokens[2]);

	fromStringContents(std::vector<std::string>(tokens.begin() + 3, tokens.end()));
}

void RR::fromStringContents(const std::vector<std::string>& tokens)
{
	switch (type)
	{
		case MX:
			rdata = tokens[1];
			break;

		case PTR:
		case CNAME:
		case NS:
			rdata = tokens[0];
			break;

		case AAAA:
			rdata = aaaa2bin(tokens[0]);
			break;
		
		case A:
			rdata = a2bin(tokens[0]);
			break;

		case TXT:
			for (unsigned int i = 0; i < tokens.size(); ++i)
				rdata += (i != 3 ? " " : "" )+ tokens[i];
			break;

		case CERT:
			rdata.append("\x01\x00\x00\x00\x00", 5);
			for (unsigned int i = 0; i < tokens[0].length(); i += 2)
				rdata += hex2bin(tokens[0].substr(i, 2));
			break;

		default:
			break;
	}
}

void RR::packContents(char* data, unsigned int len, unsigned int& offset)
{
	switch (type)
	{
		case CNAME:
		case PTR:		
		{
			unsigned int oldoffset = offset - 2;
			packName(data, len, offset, rdata);
			unsigned int packedrdlen = offset - (oldoffset + 2);
			(unsigned short&)data[oldoffset] = htons(packedrdlen);
			break;
		}

		case TXT:
		{
			unsigned int oldoffset = offset - 2;
			packName(data, len, offset, rdata, false);
			unsigned int packedrdlen = offset - (oldoffset + 2);
			(unsigned short&)data[oldoffset] = htons(packedrdlen);
			break;
		}

		case MX:
		{
			unsigned int oldoffset = offset - 2;
			(unsigned short&)data[offset] = htons(10);
			offset += 2;
			packName(data, len, offset, rdata);
			unsigned int packedrdlen = offset - (oldoffset + 2);
			(unsigned short&)data[oldoffset] = htons(packedrdlen);
			break;
		}

		default:
			rdata.copy(&data[offset], rdlen);
			offset += rdlen;
			break;
	}
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

	name = unpackName(data, len, offset);

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

	ttl = ntohl((long &)data[offset]);
	offset += 4;

	if (offset + 1 >= len)
		return false;

	rdlen = ntohs((short &)data[offset]);
	offset += 2;

	if (offset + rdlen > len)
		return false;

	rdata.clear();
	rdata.append(data + offset, rdlen);
	
	offset += rdlen;
	return true;
}

RR::~RR()
{
}
