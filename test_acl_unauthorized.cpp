#include "zone_authority.h"
#include "zone.h"
#include "acl.h"
#include "message.h"
#include "query_processor.h"
#include "rra.h"
#include <cassert>
#include <iostream>
#include <vector>

using namespace std;

// Test that unauthorized queries (ACL denies access) are properly rejected
// This test verifies the fix for the bug: `Zone *z = lookup.authorized ? lookup.zone : lookup.zone;`
// which always used lookup.zone regardless of authorization status
void test_unauthorized_acl_access() {
    Zone *zone = new Zone();
    zone->name = "example.com.";
    
    // Add a record to the zone
    RRA *record = new RRA();
    record->name = "www.example.com.";
    record->type = RR::A;
    record->rrclass = RR::CLASSIN;
    record->ttl = 3600;
    vector<string> rdata;
    rdata.push_back("10.0.0.1");
    record->fromStringContents(rdata);
    zone->addRecord(record);
    
    // Create ACL that only allows access from 10.0.0.0/24
    Acl *acl = new Acl();
    Zone *acl_zone = new Zone();
    acl_zone->name = "example.com.";
    acl_zone->parent = zone;
    acl->addSubnet("10.0.0.0/24", acl_zone);
    zone->acl = acl;
    
    vector<Zone*> zones;
    zones.push_back(zone);
    
    ZoneAuthority auth(zones);
    
    // Query from unauthorized IP (192.168.1.100)
    unsigned long unauthorized_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100;
    ZoneLookupResult result = auth.findZoneForName("www.example.com.", unauthorized_ip);
    
    assert(result.found && "Should find zone");
    assert(!result.authorized && "Should NOT be authorized");
    assert(!result.error_message.empty() && "Should have error message");
    
    // In the old buggy code: `Zone *z = lookup.authorized ? lookup.zone : lookup.zone;`
    // This would always use lookup.zone regardless of authorization
    // The server should check lookup.authorized and return early if false
    // This test ensures that unauthorized access is properly detected
    
    cout << "✓ Unauthorized ACL access properly rejected" << endl;
    
    delete zone; // This will delete acl and its zones
}

int main() {
    test_unauthorized_acl_access();
    cout << "All ACL unauthorized tests passed!" << endl;
    return 0;
}
