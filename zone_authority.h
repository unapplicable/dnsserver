#ifndef HAVE_ZONE_AUTHORITY_H
#define HAVE_ZONE_AUTHORITY_H

#include <string>
#include <vector>
#include "zone.h"

// Result of zone lookup with authorization check
struct ZoneLookupResult {
    Zone* zone;
    bool found;
    bool authorized;
    std::string error_message;
    
    ZoneLookupResult() : zone(NULL), found(false), authorized(false) {}
};

// Manages a collection of zones and their access control
// Responsible for zone selection and ACL checking
class ZoneAuthority {
public:
    explicit ZoneAuthority(const std::vector<Zone*>& zones) : zones_(zones) {}
    
    // Find zone by name, checking ACL if present
    ZoneLookupResult findZoneForName(const std::string& zone_name, 
                                     unsigned long client_addr) const;
    
    // Increment SOA serial for a zone
    static bool incrementSerial(Zone* zone);
    
private:
    const std::vector<Zone*>& zones_;
};

#endif
