#include "zone_authority.h"
#include "rr.h"
#include "rrsoa.h"
#include <iostream>

using namespace std;

ZoneLookupResult ZoneAuthority::findZoneForName(const string& zone_name, 
                                                 unsigned long client_addr) const
{
    ZoneLookupResult result;
    string zone_name_normalized = normalize_dns_name(zone_name);
    
    for (vector<Zone*>::const_iterator ziter = zones_.begin(); ziter != zones_.end(); ++ziter)
    {
        Zone *z = *ziter;
        string znormalized = normalize_dns_name(z->name);
        
        // Check if zone matches (exact match or suffix match)
        if (zone_name_normalized == znormalized || 
            (zone_name_normalized.length() >= znormalized.length() && 
             zone_name_normalized.substr(zone_name_normalized.length() - znormalized.length()) == znormalized))
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

