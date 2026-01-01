#ifndef HAVE_ZONE_H
#define HAVE_ZONE_H

#include <string>
#include <vector>
#include "socket.h"
#include "rr.h"

class Zone;

struct Subnet
{
	unsigned long ip;
	unsigned long mask;
	bool match(unsigned long ip) const
	{
		return (ip & mask) == (this->ip & mask);
	}

	Subnet(std::string str)
	{
		long smask;
		std::string::size_type s;
		if ((s = str.find('/')) != std::string::npos)
		{
			smask = atoi(str.substr(s + 1).c_str());
			ip = inet_addr(str.substr(0, s).c_str());
		} else
		{
			smask = 32;
			ip = inet_addr(str.c_str());
		}
		mask = 0;
		for (int i = 31; i >= 32 - smask; --i)
			mask |= 1 << i;

		mask = htonl(mask);
	}
};

struct AclEntry
{
	Subnet subnet;
	Zone* zone;
};

class Zone
{
public:
	std::string name;
	std::vector<AclEntry> acl;
	
	// Record operations (merged from ZoneDatabase)
	std::vector<RR*> findRecordsByName(const std::string& name, 
	                                   RR::RRType type = RR::RRUNDEF) const;
	bool hasRecordWithName(const std::string& name) const;
	bool hasRecordWithNameAndType(const std::string& name, RR::RRType type) const;
	void addRecord(RR* record);
	int removeRecords(const std::string& name, 
	                  RR::RRType type = RR::RRUNDEF,
	                  const std::string& rdata = "");
	const std::vector<RR*>& getAllRecords() const { return rrs; }
	
	// SOA serial management
	bool incrementSerial();

private:
	std::vector<RR *> rrs;
};

typedef std::vector<Zone*> t_zones;
#endif