#ifndef HAVE_ACL_H
#define HAVE_ACL_H

#include <string>
#include <vector>
#include "socket.h"
#include "tsig.h"

class Zone;

class Subnet
{
public:
	Subnet(const std::string& str);
	bool match(unsigned long ip) const;
	std::string toString() const;
	
	unsigned long getIp() const { return ip; }
	unsigned long getMask() const { return mask; }
	
private:
	unsigned long ip;
	unsigned long mask;
};

class Acl
{
public:
	Acl();
	~Acl();
	
	void addSubnet(const std::string& subnet_str, Zone* zone);
	bool checkAccess(unsigned long client_ip, Zone** out_zone) const;
	size_t size() const { return entries.size(); }
	std::string toString() const;
	void propagateTSIGKey(const struct TSIG::Key* key);
	
	// Expose entries for serialization
	struct AclEntry
	{
		Subnet subnet;
		Zone* zone;
		
		AclEntry(const Subnet& s, Zone* z) : subnet(s), zone(z) {}
	};
	
	const std::vector<AclEntry>& getEntries() const { return entries; }
	
private:
	std::vector<AclEntry> entries;
};

#endif
