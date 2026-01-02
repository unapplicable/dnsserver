#ifndef HAVE_ZONE_H
#define HAVE_ZONE_H

#include <string>
#include <vector>
#include "rr.h"
#include "tsig.h"

class Acl;

class Zone
{
public:
	std::string name;
	std::string filename;  // Source file for this zone
	bool auto_save;        // Whether to persist changes back to disk
	bool modified;         // Whether zone has been modified since load
	Acl* acl;              // Access control list
	TSIG::Key* tsig_key;   // Optional TSIG key for UPDATE authentication
	Zone* parent;          // Parent zone (for ACL sub-zones, otherwise NULL)
	
	Zone();
	~Zone();
	
	// Record operations
	std::vector<RR*> findRecordsByName(const std::string& name, 
	                                   RR::RRType type = RR::RRUNDEF) const;
	bool hasRecordWithName(const std::string& name) const;
	bool hasRecordWithNameAndType(const std::string& name, RR::RRType type) const;
	void addRecord(RR* record);
	int removeRecords(const std::string& name, 
	                  RR::RRType type = RR::RRUNDEF,
	                  const std::string& rdata = "");
	const std::vector<RR*>& getAllRecords() const { return rrs; }
	
	// Update tracking
	void recordUpdate();  // Increment serial and mark as modified (marks parent if ACL zone)
	void clearModified() { modified = false; }

private:
	std::vector<RR *> rrs;
	
	// SOA serial management (internal)
	bool incrementSerial();
};

typedef std::vector<Zone*> t_zones;
#endif