#ifndef HAVE_ZONE_DATABASE_H
#define HAVE_ZONE_DATABASE_H

#include <string>
#include <vector>
#include "rr.h"
#include "zone.h"

// Low-level zone data storage and record operations
// Manages the actual RR records within a zone
class ZoneDatabase {
public:
    explicit ZoneDatabase(Zone* zone) : zone_(zone) {}
    
    // Find records matching name and optionally type
    std::vector<RR*> findRecordsByName(const std::string& name, 
                                       RR::RRType type = RR::RRUNDEF) const;
    
    // Check if a record with given name exists
    bool hasRecordWithName(const std::string& name) const;
    
    // Check if a specific RR type exists for name
    bool hasRecordWithNameAndType(const std::string& name, RR::RRType type) const;
    
    // Add a new record to the zone
    void addRecord(RR* record);
    
    // Remove records matching criteria
    int removeRecords(const std::string& name, 
                      RR::RRType type = RR::RRUNDEF,
                      const std::string& rdata = "");
    
    // Get all records in zone
    const std::vector<RR*>& getAllRecords() const { return zone_->rrs; }
    
    // Find SOA record
    RR* findSOARecord() const;
    
private:
    Zone* zone_;
};

#endif
