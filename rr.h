#ifndef HAVE_RR_H
#define HAVE_RR_H

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>

unsigned char hex2bin(const std::string& hex);
std::string bin2hex(unsigned char bin);

#define SC(x) case x: return #x
#define SC2(x, y) case x: return #y;
#define MATCHSTRING(haystack, needle, match) if (haystack == #needle) return match;

class RR
{
public:
	enum RRType { RRUNDEF = 0, A = 1, NS, MD, MF, CNAME, SOA, MB, MG, MR,RRNULL,WKS, PTR, HINFO, MINFO, MX, TXT,AAAA = 28, CERT = 37, AXFR = 252, MAILB = 253, MAILA = 254, TYPESTAR = 255};
	enum RRClass { CLASSUNDEF = 0, CLASSIN = 1, CS = 2, CH = 3, HS = 4, CLASSSTAR = 255 };

	
	RRType type;
	std::string name;
	RRClass rrclass;
	bool query;
	unsigned long ttl;
	unsigned short rdlen;
	std::string rdata;

	static RR* createByType(RRType type);
	bool unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery);
	void pack(char *data, unsigned int len, unsigned int& offset);
	virtual void packContents(char* data, unsigned int len, unsigned int& offset);
	virtual std::ostream& dumpContents(std::ostream& os) const;
	virtual void fromString(const std::vector<std::string>& v);
	virtual void fromStringContents(const std::vector<std::string>& v);
	virtual RR* clone() const { return new RR(*this); }
	virtual ~RR() {};

	
	static RRType RRTypeFromString(const std::string& srrtype)
	{
		MATCHSTRING(srrtype, A, A);
		MATCHSTRING(srrtype, NS, NS);
		MATCHSTRING(srrtype, MD, MD);
		MATCHSTRING(srrtype, CNAME, CNAME);
		MATCHSTRING(srrtype, SOA, SOA);
		MATCHSTRING(srrtype, MB, MB);
		MATCHSTRING(srrtype, RRNULL, RRUNDEF);
		MATCHSTRING(srrtype, WKS, WKS);
		MATCHSTRING(srrtype, PTR, PTR);
		MATCHSTRING(srrtype, MINFO, MINFO);
		MATCHSTRING(srrtype, MX, MX);
		MATCHSTRING(srrtype, TXT, TXT);
		MATCHSTRING(srrtype, AAAA, AAAA);
		MATCHSTRING(srrtype, CERT, CERT);
		MATCHSTRING(srrtype, AXFR, AXFR);
		MATCHSTRING(srrtype, MAILB, MAILB);
		MATCHSTRING(srrtype, MAILA, MAILA);
		MATCHSTRING(srrtype, STAR, TYPESTAR);
		return RRUNDEF;
	}

	static std::string RRTypeToString(RRType t)
	{
		switch (t)
		{	SC(A); SC(NS); SC(MD); SC(CNAME); SC(SOA); SC(MB); SC(MR); SC2(RRNULL, NULL); SC(WKS);
			SC(PTR); SC(MINFO); SC(MX); SC(TXT); SC(AAAA); SC(CERT); SC(AXFR); SC(MAILB); SC(MAILA); 
			SC2(TYPESTAR, STAR);
			default: 
				std::stringstream ss;
				ss << "unk(" << std::hex << (unsigned short)t << ")"; 
				return ss.str();
		}
	}

	static std::string RRClassToString(RRClass c)
	{
		switch (c)
		{
			SC2(CLASSIN, IN); SC(CS); SC(CH); SC(HS); SC2(CLASSSTAR, STAR);
			default: 
				std::stringstream ss;
				ss << "unk(" << std::hex << (int)c << ")"; 
				return ss.str();
		}
	}

protected:	
	static void packName(char *data, unsigned int len, unsigned int& offset, std::string name, bool terminate = true);
	static std::string unpackName(char *data, unsigned int len, unsigned int& offset);
};

std::ostream& operator <<(std::ostream& os, const RR::RRType rrt);

std::ostream& operator <<(std::ostream& os, const RR::RRClass rrc);

std::ostream& operator <<(std::ostream& os, const RR& r);

#endif