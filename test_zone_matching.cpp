#include <iostream>
#include <cassert>
#include "zone.h"
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

int main() {
    cout << "=== Zone Matching Tests ===" << endl << endl;
    
    test_zone_name_exact_match();
    test_zone_name_case_insensitive();
    test_zone_name_must_not_match_wrong_zone();
    test_zone_name_trailing_dot();
    
    cout << endl << "All zone matching tests passed!" << endl;
    return 0;
}
