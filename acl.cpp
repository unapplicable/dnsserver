#include "acl.h"
#include "zone.h"
#include "tsig.h"
#include <sstream>
#include <cstring>

using namespace std;

// Subnet implementation
Subnet::Subnet(const string& str)
{
	long smask;
	string::size_type s;
	if ((s = str.find('/')) != string::npos)
	{
		smask = atoi(str.substr(s + 1).c_str());
		ip = inet_addr(str.substr(0, s).c_str());
	}
	else
	{
		smask = 32;
		ip = inet_addr(str.c_str());
	}
	
	mask = 0;
	for (int i = 31; i >= 32 - smask; --i)
		mask |= 1 << i;
	
	mask = htonl(mask);
}

bool Subnet::match(unsigned long client_ip) const
{
	return (client_ip & mask) == (ip & mask);
}

string Subnet::toString() const
{
	struct in_addr addr;
	addr.s_addr = ip;
	string result = inet_ntoa(addr);
	
	// Calculate CIDR prefix from mask
	unsigned long host_mask = ntohl(mask);
	int prefix = 0;
	for (int i = 31; i >= 0; i--)
	{
		if (host_mask & (1UL << i))
			prefix++;
		else
			break;
	}
	
	if (prefix != 32)
	{
		ostringstream ss;
		ss << result << "/" << prefix;
		return ss.str();
	}
	
	return result;
}

// Acl implementation
Acl::Acl()
{
}

Acl::~Acl()
{
}

void Acl::addSubnet(const string& subnet_str, Zone* zone)
{
	Subnet subnet(subnet_str);
	entries.push_back(AclEntry(subnet, zone));
}

bool Acl::checkAccess(unsigned long client_ip, Zone** out_zone) const
{
	for (vector<AclEntry>::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		if (it->subnet.match(client_ip))
		{
			if (out_zone)
				*out_zone = it->zone;
			return true;
		}
	}
	return false;
}

Zone* Acl::findMostSpecificMatch(unsigned long client_ip) const
{
	Zone* best_match = NULL;
	unsigned long best_mask = 0;
	
	for (vector<AclEntry>::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		if (it->subnet.match(client_ip))
		{
			unsigned long current_mask = ntohl(it->subnet.getMask());
			if (current_mask >= best_mask)
			{
				best_mask = current_mask;
				best_match = it->zone;
			}
		}
	}
	
	return best_match;
}

string Acl::toString() const
{
	ostringstream ss;
	for (vector<AclEntry>::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		if (it != entries.begin())
			ss << " ";
		ss << it->subnet.toString();
	}
	return ss.str();
}

void Acl::propagateTSIGKey(const TSIG::Key* key)
{
	if (!key)
		return;
	
	for (vector<AclEntry>::iterator it = entries.begin(); it != entries.end(); ++it)
	{
		if (it->zone && !it->zone->tsig_key)
		{
			it->zone->tsig_key = new TSIG::Key(*key);
		}
	}
}
