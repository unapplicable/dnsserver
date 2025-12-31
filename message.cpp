#include "message.h"
#include "socket.h"

std::ostream& operator <<(std::ostream& os, const Message& m)
{
	os << std::hex << m.id << " " << (m.query ? "Q" : "q") << " " << m.opcode << " " << (m.authoritative ? "A" : "a") <<
		(m.truncation ? "T" : "t") << (m.recursiondesired ? "RD" : "rd") << (m.recursionavailable ? "RA" : "ra") <<
		" " << m.rcode;

	for (int rrtype = 0; rrtype < 4; rrtype++)
	{
		std::vector<RR *> rrs[4] = {(m.qd), (m.an), (m.ns), (m.ar)};

		bool first = true;
		for (unsigned short i = 0; i < rrs[rrtype].size(); i++)
		{
			if (first)
			{
				os << "[ ";
				first = false;
			}
			os << *(rrs[rrtype][i]);
			if (i == rrs[rrtype].size() - 1)
				os << " ]";
			os << "\n";
		}
	}

	return os;
}

bool Message::unpack(char *data, unsigned int len, unsigned int& offset)
{
	unsigned int& iter = offset;

	if (iter + 1 >= len)
		return false;

	id = ntohs((unsigned short &)data[iter]);
	iter += 2;

	if (iter + 1 >= len)
		return false;

	unsigned short flags = ntohs((unsigned short &)data[iter]);
	iter += 2;

	// DNS flags after ntohs() on little-endian keep network bit positions
	// Standard clients send with opcode in bits 11-14 (network order)
	// After ntohs(), these stay at bits 11-14 on little-endian
	query = (flags & 0x8000) == 0;
	opcode = (Opcode)((flags & 0x7800) >> 11);
	authoritative = (flags & 0x0400) != 0;
	truncation = (flags & 0x0200) != 0;
	recursiondesired = (flags & 0x0100) != 0;
	recursionavailable = (flags & 0x0080) != 0;
	rcode = (RCode)((flags & 0x000F));

	if (iter + 2 * 4 > len)
		return false;

	unsigned short counts[] = {0, 0, 0, 0};

	counts[0] = ntohs((unsigned short &)data[iter]);
	iter += 2;
	counts[1] = ntohs((unsigned short &)data[iter]);
	iter += 2;
	counts[2] = ntohs((unsigned short &)data[iter]);
	iter += 2;
	counts[3] = ntohs((unsigned short &)data[iter]);
	iter += 2;

	for (int rrtype = 0; rrtype < 4; rrtype++)
	{
		
		std::vector<RR *>* rrs[] = {&qd, &an, &ns, &ar};

		for (unsigned short i = 0; i < counts[rrtype]; i++)
		{
			// First, peek at the RR to determine its type
			unsigned int peek_offset = iter;
			std::string rr_name = RR::unpackName(data, len, peek_offset);
			
			if (peek_offset + 1 >= len)
				return false;
			
			RR::RRType rr_type = (RR::RRType)ntohs((short &)data[peek_offset]);
			
			// Create the correct RR subclass based on type
			RR *r = RR::createByType(rr_type);
			
			try
			{
				// For QUERY messages: only section 0 (Question) is query-style
				// For UPDATE messages: only section 0 (Zone) is query-style
				// For both message types, section 0 is query-style (name/type/class only)
				bool isQueryStyleRR = (rrtype == 0);
				if (!r->unpack(data, len, iter, isQueryStyleRR))
				{
					delete r;
					return false;
				}
			} catch (std::exception& ex)
			{
				std::cerr << "failed to unpack" << std::endl;
				delete r;
				return false;
			}

			rrs[rrtype]->push_back(r);
		}
	}

	return true;
}

void Message::pack(char *data, unsigned int len, unsigned int& offset) const
{
	offset = 0;

	(unsigned short &)data[offset] = htons(id);
	offset += 2;

	unsigned short flags = 0;
	flags |= (query == false) << 15;
	flags |= (opcode & 0x0F) << 11;  // 4 bits for opcode (to support UPDATE=5)
	flags |= authoritative << 10;
	flags |= truncation ? 0x0200 : 0; 
	flags |= recursiondesired ? 0x0100 : 0;
	flags |= recursionavailable ? 0x0080 : 0;
	flags |= (rcode & 0x0F);
	
	(unsigned short &)data[offset] = htons(flags);
	offset += 2;

	(unsigned short &)data[offset] = htons(static_cast<unsigned short>(qd.size()));
	offset += 2;

	(unsigned short &)data[offset] = htons(static_cast<unsigned short>(an.size()));
	offset += 2;

	(unsigned short &)data[offset] = htons(static_cast<unsigned short>(ns.size()));
	offset += 2;

	(unsigned short &)data[offset] = htons(static_cast<unsigned short>(ar.size()));
	offset += 2;

	for (int rrtype = 0; rrtype < 4; rrtype++)
	{
		const std::vector<RR *>* rrs[] = {&qd, &an, &ns, &ar};

		for (unsigned short i = 0; i < rrs[rrtype]->size(); i++)
			rrs[rrtype]->at(i)->pack(data, len, offset);			
	}
}

Message::~Message()
{
	for (int rrtype = 0; rrtype < 4; ++rrtype)
	{
		std::vector<RR *>* rrs[] = {&qd, &an, &ns, &ar};

		for (std::vector<RR *>::iterator it = rrs[rrtype]->begin();
			it != rrs[rrtype]->end();
			++it)
		{
			delete *it;
		}
	}
}

std::ostream& operator <<(std::ostream& os, const Message::Opcode o)
{
	return os << Message::OpcodeToString(o);	
}

std::ostream& operator <<(std::ostream& os, const Message::RCode rc)
{
	return os << Message::RCodeToString(rc);	
}
