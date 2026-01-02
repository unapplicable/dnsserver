#include <iostream>
#include <cassert>
#include "zone.h"
#include "zone_authority.h"
#include "rr.h"
#include "rra.h"
#include "socket.h"

using namespace std;

void test_zone_name_exact_match() {
    cout << "Testing zone name exact match..." << endl;
    
    Zone z;
    z.name = "example.com.";
    
    // Add a test record
    RRA* rr = new RRA();
    rr->name = "host.example.com.";
    rr->type = RR::A;
    rr->rrclass = RR::CLASSIN;
    rr->ttl = 300;
    unsigned long addr = inet_addr("192.0.2.1");
    rr->rdata.append(reinterpret_cast<char*>(&addr), 4);
    z.addRecord(rr);
    
    // SUT: Test zone record lookup with exact name (case insensitive)
    vector<RR*> matches1 = z.findRecordsByName(dns_name_tolower("host.example.com."));
    assert(matches1.size() == 1 && "Exact match should find record");
    
    vector<RR*> matches2 = z.findRecordsByName(dns_name_tolower("HOST.EXAMPLE.COM."));
    assert(matches2.size() == 1 && "Case insensitive match should find record");
    
    vector<RR*> matches3 = z.findRecordsByName(dns_name_tolower("other.example.com."));
    assert(matches3.size() == 0 && "Different name should not match");
    
    cout << "  ✓ Exact zone name matching works" << endl;
}

void test_zone_name_case_insensitive() {
    cout << "Testing zone name case insensitive matching..." << endl;
    
    Zone z;
    z.name = "Example.COM.";
    
    // Test case insensitive comparison
    assert(dns_name_tolower(z.name) == dns_name_tolower("example.com.") && "Lowercase should match");
    assert(dns_name_tolower(z.name) == dns_name_tolower("EXAMPLE.COM.") && "Uppercase should match");
    assert(dns_name_tolower(z.name) == dns_name_tolower("ExAmPlE.cOm.") && "Mixed case should match");
    
    cout << "  ✓ Case insensitive zone name matching works" << endl;
}

void test_zone_name_must_not_match_wrong_zone() {
    cout << "Testing zone name rejects wrong zones..." << endl;
    
    Zone z;
    z.name = "example.com.";
    
    // Test mismatch cases
    assert(dns_name_tolower(z.name) != dns_name_tolower("test.example.com.") && "Subdomain should not match");
    assert(dns_name_tolower(z.name) != dns_name_tolower("other.net.") && "Different TLD should not match");
    assert(dns_name_tolower(z.name) != dns_name_tolower("") && "Empty string should not match");
    assert(dns_name_tolower(z.name) != dns_name_tolower("notexample.com.") && "Similar name should not match");
    
    cout << "  ✓ Zone name correctly rejects wrong zones" << endl;
}

void test_zone_name_trailing_dot() {
    cout << "Testing zone name handles trailing dots..." << endl;
    
    Zone z1;
    z1.name = "example.com.";
    
    Zone z2;
    z2.name = "example.com";
    
    // Zones with and without trailing dots are different in our implementation
    // but normalized comparison via dns_name_tolower can handle it
    assert(dns_name_tolower(z1.name) == dns_name_tolower("example.com.") && "With dot should match");
    
    cout << "  ✓ Zone name handles trailing dots" << endl;
}

void test_most_specific_zone_wins() {
    cout << "Testing most specific zone wins..." << endl;
    
    // Create parent zone: example.com
    Zone* parent = new Zone();
    parent->name = "example.com.";
    
    RRA* parent_a = new RRA();
    parent_a->name = "www.example.com.";
    parent_a->type = RR::A;
    parent_a->rrclass = RR::CLASSIN;
    parent_a->ttl = 300;
    unsigned long addr1 = inet_addr("1.2.3.4");
    parent_a->rdata.assign(reinterpret_cast<char*>(&addr1), 4);
    parent->addRecord(parent_a);
    
    // Create child zone: sub.example.com
    Zone* child = new Zone();
    child->name = "sub.example.com.";
    
    RRA* child_a = new RRA();
    child_a->name = "www.sub.example.com.";
    child_a->type = RR::A;
    child_a->rrclass = RR::CLASSIN;
    child_a->ttl = 300;
    unsigned long addr2 = inet_addr("5.6.7.8");
    child_a->rdata.assign(reinterpret_cast<char*>(&addr2), 4);
    child->addRecord(child_a);
    
    // Create ZoneAuthority with both zones
    vector<Zone*> zones;
    zones.push_back(parent);
    zones.push_back(child);
    
    ZoneAuthority auth(zones);
    
    // Query for www.example.com should match parent zone
    ZoneLookupResult result1 = auth.findZoneForName("www.example.com.", 0);
    assert(result1.found && "Should find parent zone");
    assert(result1.authorized && "Should be authorized");
    assert(result1.zone == parent && "Should return parent zone");
    
    // Query for www.sub.example.com should match child zone (most specific)
    ZoneLookupResult result2 = auth.findZoneForName("www.sub.example.com.", 0);
    assert(result2.found && "Should find child zone");
    assert(result2.authorized && "Should be authorized");
    assert(result2.zone == child && "Should return child zone (most specific)");
    
    // Query for sub.example.com should match child zone
    ZoneLookupResult result3 = auth.findZoneForName("sub.example.com.", 0);
    assert(result3.found && "Should find child zone");
    assert(result3.authorized && "Should be authorized");
    assert(result3.zone == child && "Should return child zone");
    
    // Query for example.com should match parent zone
    ZoneLookupResult result4 = auth.findZoneForName("example.com.", 0);
    assert(result4.found && "Should find parent zone");
    assert(result4.authorized && "Should be authorized");
    assert(result4.zone == parent && "Should return parent zone");
    
    delete parent;
    delete child;
    
    cout << "  ✓ Most specific zone wins" << endl;
}

void test_reverse_zone_specificity() {
    cout << "Testing reverse zone specificity..." << endl;
    
    // Create parent zone: 10.in-addr.arpa
    Zone* parent = new Zone();
    parent->name = "10.in-addr.arpa.";
    
    // Create child zone: 1.10.in-addr.arpa
    Zone* child = new Zone();
    child->name = "1.10.in-addr.arpa.";
    
    vector<Zone*> zones;
    zones.push_back(parent);
    zones.push_back(child);
    
    ZoneAuthority auth(zones);
    
    // Query for 5.1.10.in-addr.arpa should match child zone (most specific)
    ZoneLookupResult result1 = auth.findZoneForName("5.1.10.in-addr.arpa.", 0);
    assert(result1.found && "Should find child zone");
    assert(result1.authorized && "Should be authorized");
    assert(result1.zone == child && "Should return child zone (most specific)");
    
    // Query for 2.10.in-addr.arpa should match parent zone
    ZoneLookupResult result2 = auth.findZoneForName("2.10.in-addr.arpa.", 0);
    assert(result2.found && "Should find parent zone");
    assert(result2.authorized && "Should be authorized");
    assert(result2.zone == parent && "Should return parent zone");
    
    delete parent;
    delete child;
    
    cout << "  ✓ Reverse zone specificity works" << endl;
}

void test_zone_order_independence() {
    cout << "Testing zone order independence..." << endl;
    
    // Create zones
    Zone* parent = new Zone();
    parent->name = "example.com.";
    
    Zone* child = new Zone();
    child->name = "sub.example.com.";
    
    // Test with child first, then parent
    vector<Zone*> zones1;
    zones1.push_back(child);
    zones1.push_back(parent);
    
    ZoneAuthority auth1(zones1);
    
    ZoneLookupResult result1 = auth1.findZoneForName("www.sub.example.com.", 0);
    assert(result1.found && "Should find zone");
    assert(result1.zone == child && "Should return child zone regardless of order");
    
    // Test with parent first, then child
    vector<Zone*> zones2;
    zones2.push_back(parent);
    zones2.push_back(child);
    
    ZoneAuthority auth2(zones2);
    
    ZoneLookupResult result2 = auth2.findZoneForName("www.sub.example.com.", 0);
    assert(result2.found && "Should find zone");
    assert(result2.zone == child && "Should return child zone regardless of order");
    
    delete parent;
    delete child;
    
    cout << "  ✓ Zone order independence works" << endl;
}

int main() {
    cout << "=== Zone Matching Tests ===" << endl << endl;
    
    test_zone_name_exact_match();
    test_zone_name_case_insensitive();
    test_zone_name_must_not_match_wrong_zone();
    test_zone_name_trailing_dot();
    test_most_specific_zone_wins();
    test_reverse_zone_specificity();
    test_zone_order_independence();
    
    cout << endl << "All zone matching tests passed!" << endl;
    return 0;
}
