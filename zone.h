#ifndef HAVE_ZONE_H
#define HAVE_ZONE_H

#include <string>
#include <vector>
#include "socket.h"

class RR;
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
		std::vector<RR *> rrs;
};

typedef std::vector<Zone*> t_zones;
#endif