#include "zone_authority.h"
#include "rr.h"
#include "rrsoa.h"
#include "acl.h"
#include <iostream>

using namespace std;

ZoneAuthority::ZoneAuthority(const vector<Zone*>& zones) : zones_(zones)
{
}

ZoneLookupResult ZoneAuthority::findZoneForName(const string& zone_name, 
                                                 unsigned long client_addr) const
{
    ZoneLookupResult result;
    Zone* best_match = NULL;
    size_t best_match_length = 0;
    
    // Find the longest matching zone (most specific)
    for (vector<Zone*>::const_iterator ziter = zones_.begin(); ziter != zones_.end(); ++ziter)
    {
        Zone *z = *ziter;
        
        // Normalize both names - ensure they end with dot for comparison
        string query_normalized = zone_name;
        if (query_normalized.empty() || query_normalized[query_normalized.length()-1] != '.')
            query_normalized += '.';
            
        string zone_normalized = z->name;
        if (zone_normalized.empty() || zone_normalized[zone_normalized.length()-1] != '.')
            zone_normalized += '.';
        
        // Check if zone matches (exact match or suffix match)
        bool matches = (query_normalized == zone_normalized);
        if (!matches && query_normalized.length() >= zone_normalized.length())
        {
            // Check if query_normalized ends with zone_normalized
            size_t pos = query_normalized.length() - zone_normalized.length();
            if (query_normalized.substr(pos) == zone_normalized)
            {
                // Make sure there's a dot separator (or it's at the beginning)
                if (pos == 0 || query_normalized[pos - 1] == '.')
                    matches = true;
            }
        }
        
        // Keep track of the longest (most specific) matching zone
        if (matches && zone_normalized.length() > best_match_length)
        {
            best_match = z;
            best_match_length = zone_normalized.length();
        }
    }
    
    if (best_match)
    {
        result.found = true;
        
        // Check ACL if present - use longest match
        if (best_match->acl && best_match->acl->size() > 0)
        {
            Zone* acl_zone = best_match->acl->findMostSpecificMatch(client_addr);
            if (acl_zone)
            {
                // Found matching ACL entry - use its zone
                result.authorized = true;
                result.zone = acl_zone;
                return result;
            }
            
            // ACL present but no match - deny access
            result.authorized = false;
            result.error_message = "Access denied by ACL";
            return result;
        }
        else
        {
            // No ACL - allow access to parent zone
            result.authorized = true;
            result.zone = best_match;
            return result;
        }
    }
    
    result.error_message = "Zone not found or not authoritative";
    return result;
}
