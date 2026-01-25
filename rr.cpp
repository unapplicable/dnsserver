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
#include "rropt.h"
#include "rrtsig.h"

#include <cstring>
#include <cctype>
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
	
	// Track visited offsets to detect compression loops
	// DNS packet max size is 65536 bytes, need 65536 bits = 8192 bytes
	static const unsigned int MAX_VISITED_BYTES = 8192; // 65536 / 8
	unsigned char visited[MAX_VISITED_BYTES] = {0};
	
	// Limit maximum compression pointer jumps to prevent deep recursion
	unsigned int jump_count = 0;
	static const unsigned int MAX_JUMPS = 64;
	
	// Limit total name length (RFC 1035: max 255 bytes)
	static const unsigned int MAX_NAME_LENGTH = 255;

	for (unsigned int i = iter; ;)
	{
		if (i >= len)
			throw DNSParseException(DNSParseException::OFFSET_OUT_OF_BOUNDS, 
			                        "Reading beyond packet boundary", i, len);

		unsigned char tokencode = (unsigned char)data[i];
		if ((tokencode & 0xC0) == 0xC0)
		{
			// Compression pointer detected
			if (i + 1 >= len)
				throw DNSParseException(DNSParseException::TRUNCATED_PACKET,
				                        "Incomplete compression pointer", i, len);
			
			unsigned int ptr_offset = ntohs((unsigned short &)data[i]) & ~0xC000;
			
			// Check for loop: have we visited this offset before?
			// Calculate byte and bit indices in the visited array
			unsigned int byte_idx = ptr_offset / 8;
			unsigned int bit_idx = ptr_offset % 8;
			
			if (byte_idx < MAX_VISITED_BYTES)
			{
				if (visited[byte_idx] & (1 << bit_idx))
				{
					// Loop detected!
					std::ostringstream details;
					details << "Pointer at offset " << i << " points to " << ptr_offset;
					throw DNSParseException(DNSParseException::COMPRESSION_LOOP,
					                        details.str(), ptr_offset, len);
				}
				visited[byte_idx] |= (1 << bit_idx);
			}
			
			// Check jump count limit
			if (++jump_count > MAX_JUMPS)
			{
				std::ostringstream details;
				details << "Exceeded max " << MAX_JUMPS << " jumps";
				throw DNSParseException(DNSParseException::TOO_MANY_JUMPS,
				                        details.str(), i, len);
			}
			
			// Check pointer doesn't point beyond packet
			if (ptr_offset >= len)
			{
				std::ostringstream details;
				details << "Pointer " << ptr_offset << " >= packet length " << len;
				throw DNSParseException(DNSParseException::POINTER_OUT_OF_BOUNDS,
				                        details.str(), ptr_offset, len);
			}
			
			// Follow the pointer
			i = ptr_offset;
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
		{
			std::ostringstream details;
			details << "Label length " << (int)tokencode << " at offset " << (i-1) 
			        << " extends beyond packet";
			throw DNSParseException(DNSParseException::LABEL_TOO_LONG,
			                        details.str(), i, len);
		}

		// Check name length doesn't exceed maximum
		if (name.length() + tokencode + 1 > MAX_NAME_LENGTH)
		{
			std::ostringstream details;
			details << "Current name '" << name << "' + label of " << (int)tokencode 
			        << " bytes exceeds " << MAX_NAME_LENGTH;
			throw DNSParseException(DNSParseException::NAME_TOO_LONG,
			                        details.str(), i, len);
		}

		if (!name.empty())
			name += '.';

		name.append(data + i, tokencode);
		

		i += tokencode;
		if (!packed)
			iter = i;
	}

	return name;
}

std::string RR::unpackNameWithDot(char *data, unsigned int len, unsigned int& offset)
{
	std::string name = unpackName(data, len, offset);
	if (!name.empty() && name[name.length()-1] != '.')
		name += '.';
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

		case OPT:
			return new RROPT();

		case TSIG:
			return new RRTSIG();

		default:
			// For unknown RR types, return a base RR object
			// It will store and forward the rdata as-is
			return new RR();
	}
}

void RR::fromString(const std::vector<std::string>& tokens, const std::string& origin, const std::string& previousName)
{
	// Handle empty name (use previous name)
	std::string rawName = tokens[0].empty() && !previousName.empty() ? previousName : tokens[0];
	
	name = process_domain_name(rawName, origin);

	// Parse: name [ttl] class type rdata...
	// ttl is optional and numeric
	size_t idx = 1;
	ttl = 0; // default TTL
	
	// Check if next token is a number (TTL)
	if (idx < tokens.size() && !tokens[idx].empty() && isdigit(tokens[idx][0]))
	{
		ttl = std::stoul(tokens[idx]);
		idx++;
	}
	
	// Parse class
	if (idx >= tokens.size())
	{
		rrclass = CLASSUNDEF;
		type = RRUNDEF;
		return;
	}
	
	if (tokens[idx] == "IN")
		rrclass = CLASSIN;
	else if (tokens[idx] == "CH")
		rrclass = CH;
	else if (tokens[idx] == "*" || tokens[idx] == "ANY")
		rrclass = CLASSANY;
	else
		rrclass = CLASSUNDEF;
	idx++;
	
	// Parse type
	if (idx >= tokens.size())
	{
		type = RRUNDEF;
		return;
	}
	
	type = RRTypeFromString(tokens[idx]);
	idx++;
	
	// Parse rdata
	fromStringContents(std::vector<std::string>(tokens.begin() + idx, tokens.end()), origin);
}

void RR::fromStringContents(const std::vector<std::string>& /* tokens */, const std::string& /* origin */)
{
	std::ostringstream oss;
	oss << "fromStringContents not implemented for RR type " << RRTypeToString(type);
	throw std::runtime_error(oss.str());
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

std::string RR::toString() const
{
	std::ostringstream ss;
	ss << name << " " << ttl << " ";
	
	// Output class
	if (rrclass == CLASSIN)
		ss << "IN";
	else if (rrclass == CH)
		ss << "CH";
	else if (rrclass == CLASSANY)
		ss << "ANY";
	else
		ss << "UNKNOWN";
	
	ss << " " << RRTypeToString(type) << " ";
	dumpContents(ss);
	return ss.str();
}
