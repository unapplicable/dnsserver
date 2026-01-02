#ifndef HAVE_RR_H
#define HAVE_RR_H

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

unsigned char hex2bin(const std::string& hex);
std::string bin2hex(unsigned char bin);

// Utility function to lowercase DNS names (case-insensitive per RFC)
inline std::string dns_name_tolower(const std::string& name) {
	std::string result = name;
	std::transform(result.begin(), result.end(), result.begin(), 
	               [](unsigned char c){ return std::tolower(c); });
	return result;
}

// Utility function to normalize DNS name (remove trailing dot)
inline std::string normalize_dns_name(const std::string& name) {
	if (!name.empty() && name[name.length()-1] == '.')
		return name.substr(0, name.length()-1);
	return name;
}

// Utility function to process domain name with origin
inline std::string process_domain_name(const std::string& name, const std::string& origin) {
	std::string result = name;
	
	// Append origin if name is relative (no trailing dot)
	if (!result.empty() && result[result.length()-1] != '.' && !origin.empty())
		result = result + "." + origin;
	
	// Ensure trailing dot
	if (!result.empty() && result[result.length()-1] != '.')
		result += ".";
	
	return dns_name_tolower(result);
}

#define SC(x) case x: return #x
#define SC2(x, y) case x: return #y;
#define MATCHSTRING(haystack, needle, match) if (haystack == #needle) return match;

class RR
{
public:
	enum RRType { RRUNDEF = 0, A = 1, NS, MD, MF, CNAME, SOA, MB, MG, MR,RRNULL,WKS, PTR, HINFO, MINFO, MX, TXT,AAAA = 28, CERT = 37, DHCID = 49, TSIG = 250, AXFR = 252, MAILB = 253, MAILA = 254, TYPESTAR = 255};
	enum RRClass { CLASSUNDEF = 0, CLASSIN = 1, CS = 2, CH = 3, HS = 4, CLASSNONE = 254, CLASSANY = 255 };

	
	RRType type;
	std::string name;
	RRClass rrclass;
	bool query;
	unsigned long ttl;
	unsigned short rdlen;
	std::string rdata;

	static RR* createByType(RRType type);
	virtual bool unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery);
	void pack(char *data, unsigned int len, unsigned int& offset);
	virtual void packContents(char* data, unsigned int len, unsigned int& offset);
	virtual std::ostream& dumpContents(std::ostream& os) const;
	virtual std::string toString() const;  // Serialize full record: name + type + rdata
	virtual void fromString(const std::vector<std::string>& v, const std::string& origin = "", const std::string& previousName = "");
	virtual void fromStringContents(const std::vector<std::string>& v, const std::string& origin = "");
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
		MATCHSTRING(srrtype, DHCID, DHCID);
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
			SC(PTR); SC(MINFO); SC(MX); SC(TXT); SC(AAAA); SC(CERT); SC(DHCID); SC(TSIG); SC(AXFR); SC(MAILB); SC(MAILA); 
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
			SC2(CLASSIN, IN); SC(CS); SC(CH); SC(HS); SC2(CLASSNONE, NONE); SC2(CLASSANY, ANY);
			default: 
				std::stringstream ss;
				ss << "unk(" << std::hex << (int)c << ")"; 
				return ss.str();
		}
	}

	static void packName(char *data, unsigned int len, unsigned int& offset, std::string name, bool terminate = true);
	static std::string unpackName(char *data, unsigned int len, unsigned int& offset);
	static std::string unpackNameWithDot(char *data, unsigned int len, unsigned int& offset);

protected:	
};

std::ostream& operator <<(std::ostream& os, const RR::RRType rrt);

std::ostream& operator <<(std::ostream& os, const RR::RRClass rrc);

std::ostream& operator <<(std::ostream& os, const RR& r);

#endif