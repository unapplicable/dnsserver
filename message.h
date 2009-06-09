#ifndef HAVE_MESSAGE_H
#define HAVE_MESSAGE_H

#include <vector>
#include <iostream>
#include "rr.h"

#define SCC(x) case CODE##x: return #x;

class Message
{
public:
	enum Opcode {QUERY = 0, IQUERY = 1, STATUS = 2};
	enum RCode {CODENOERROR , CODEFORMATERROR, CODESERVERFAILURE, CODENAMEERROR, CODENOTIMPLEMENTED, CODEREFUSED};

	unsigned short id;
	bool query;
	Opcode opcode;
	bool authoritative;
	bool truncation;
	bool recursiondesired;
	bool recursionavailable;
	RCode rcode;
	std::vector<RR *> qd, an, ns, ar;

	bool unpack(char *data, unsigned int len, unsigned int& offset);
	void pack(char *data, unsigned int len, unsigned int& offset) const;
	Message() 
	{
	}
	~Message();

	static std::string OpcodeToString(Opcode o)
	{
		switch (o)
		{ 
			SC(QUERY); SC(IQUERY); SC(STATUS);
			default: 
				std::stringstream ss;
				ss << "unk(" << std::hex << (int)o << ")";
				return ss.str();
		}
	}

	static std::string RCodeToString(RCode c)
	{
		switch (c)
		{
			SCC(NOERROR); SCC(FORMATERROR); SCC(SERVERFAILURE); 
			SCC(NAMEERROR); SCC(NOTIMPLEMENTED); SCC(REFUSED); 
			default:
				std::stringstream ss;
				ss << "unk(" << std::hex << (int)c << ")";
				return ss.str();
		}	
	}
};

std::ostream& operator <<(std::ostream& os, const Message& m);
std::ostream& operator <<(std::ostream& os, const Message::Opcode o);
std::ostream& operator <<(std::ostream& os, const Message::RCode rc);

#endif