#include "zone_authority.h"
#include "rr.h"
#include "rrsoa.h"
#include <iostream>

using namespace std;

ZoneAuthority::ZoneAuthority(const vector<Zone*>& zones) : zones_(zones)
{
}

ZoneLookupResult ZoneAuthority::findZoneForName(const string& zone_name, 
                                                 unsigned long client_addr) const
{
    ZoneLookupResult result;
    
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
        
        if (matches)
        {
            result.found = true;
            
            // Check ACL if present
            if (z->acl.size())
            {
                for (vector<AclEntry>::const_iterator i = z->acl.begin(); i != z->acl.end(); ++i)
                {
                    if (i->subnet.match(client_addr))
                    {
                        result.authorized = true;
                        result.zone = i->zone ? i->zone : z;
                        return result;
                    }
                }
                
                result.authorized = false;
                result.error_message = "Access denied by ACL";
                return result;
            }
            else
            {
                result.authorized = true;
                result.zone = z;
                return result;
            }
        }
    }
    
    result.error_message = "Zone not found or not authoritative";
    return result;
}

bool ZoneAuthority::incrementSerial(Zone* zone)
{
    for (vector<RR*>::iterator it = zone->rrs.begin(); it != zone->rrs.end(); ++it)
    {
        RR* rr = *it;
        if (rr->type == RR::SOA)
        {
            RRSoa* soa = dynamic_cast<RRSoa*>(rr);
            if (soa)
            {
                soa->serial++;
                cout << "SOA serial incremented to " << soa->serial << endl;
                return true;
            }
        }
    }
    
    return false;
}

