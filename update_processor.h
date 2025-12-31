#ifndef HAVE_UPDATE_PROCESSOR_H
#define HAVE_UPDATE_PROCESSOR_H

#include <string>
#include "message.h"
#include "zone_database.h"

// Handles DNS UPDATE operations (RFC 2136)
// Validates prerequisites and applies updates atomically
class UpdateProcessor {
public:
    // Check if all prerequisites are satisfied
    static bool checkPrerequisites(const Message* request, 
                                   ZoneDatabase& zonedb,
                                   std::string& error_message);
    
    // Apply all updates to the zone
    static bool applyUpdates(const Message* request,
                            ZoneDatabase& zonedb,
                            std::string& error_message);
};

#endif
