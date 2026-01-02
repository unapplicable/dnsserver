#include <iostream>
#include <cassert>
#include <arpa/inet.h>
#include "acl.h"
#include "zone.h"

using namespace std;

void test_subnet_matching() {
    cout << "Testing subnet matching..." << endl;
    
    // Test /24 subnet
    Subnet subnet24("192.168.1.0/24");
    
    unsigned long ip_in_subnet = inet_addr("192.168.1.100");
    unsigned long ip_out_subnet = inet_addr("192.168.2.100");
    
    assert(subnet24.match(ip_in_subnet));
    assert(!subnet24.match(ip_out_subnet));
    
    cout << "  /24 subnet matching: PASSED" << endl;
    
    // Test /32 (single IP)
    Subnet subnet32("10.0.0.1/32");
    unsigned long exact_ip = inet_addr("10.0.0.1");
    unsigned long different_ip = inet_addr("10.0.0.2");
    
    assert(subnet32.match(exact_ip));
    assert(!subnet32.match(different_ip));
    
    cout << "  /32 single IP matching: PASSED" << endl;
    
    // Test /16 subnet
    Subnet subnet16("172.16.0.0/16");
    unsigned long ip_in_16 = inet_addr("172.16.50.100");
    unsigned long ip_out_16 = inet_addr("172.17.0.1");
    
    assert(subnet16.match(ip_in_16));
    assert(!subnet16.match(ip_out_16));
    
    cout << "  /16 subnet matching: PASSED" << endl;
}

void test_subnet_toString() {
    cout << "Testing subnet toString..." << endl;
    
    Subnet s1("192.168.1.0/24");
    assert(s1.toString() == "192.168.1.0/24");
    
    Subnet s2("10.0.0.1/32");
    assert(s2.toString() == "10.0.0.1");  // /32 should not show prefix
    
    cout << "  Subnet toString: PASSED" << endl;
}

void test_acl_access_control() {
    cout << "Testing ACL access control..." << endl;
    
    Zone zone1, zone2;
    zone1.name = "zone1.test.";
    zone2.name = "zone2.test.";
    
    Acl acl;
    acl.addSubnet("192.168.1.0/24", &zone1);
    acl.addSubnet("10.0.0.0/8", &zone2);
    
    Zone* matched_zone = NULL;
    
    // Test matching first subnet
    unsigned long ip1 = inet_addr("192.168.1.50");
    assert(acl.checkAccess(ip1, &matched_zone));
    assert(matched_zone == &zone1);
    
    cout << "  First subnet match: PASSED" << endl;
    
    // Test matching second subnet
    matched_zone = NULL;
    unsigned long ip2 = inet_addr("10.5.5.5");
    assert(acl.checkAccess(ip2, &matched_zone));
    assert(matched_zone == &zone2);
    
    cout << "  Second subnet match: PASSED" << endl;
    
    // Test no match
    matched_zone = NULL;
    unsigned long ip3 = inet_addr("172.16.0.1");
    assert(!acl.checkAccess(ip3, &matched_zone));
    
    cout << "  No match rejection: PASSED" << endl;
}

void test_acl_toString() {
    cout << "Testing ACL toString..." << endl;
    
    Zone zone;
    Acl acl;
    acl.addSubnet("192.168.1.0/24", &zone);
    acl.addSubnet("10.0.0.0/8", &zone);
    
    string str = acl.toString();
    assert(str.find("192.168.1.0/24") != string::npos);
    assert(str.find("10.0.0.0/8") != string::npos);
    
    cout << "  ACL toString: PASSED" << endl;
}

void test_acl_tsig_propagation() {
    cout << "Testing TSIG key propagation..." << endl;
    
    Zone zone1, zone2;
    zone1.name = "zone1.test.";
    zone2.name = "zone2.test.";
    
    // Ensure zones start with no TSIG key
    assert(zone1.tsig_key == NULL);
    assert(zone2.tsig_key == NULL);
    
    Acl acl;
    acl.addSubnet("192.168.1.0/24", &zone1);
    acl.addSubnet("10.0.0.0/8", &zone2);
    
    // Create TSIG key
    TSIG::Key key;
    key.name = "testkey.example.com.";
    key.algorithm = TSIG::HMAC_SHA256;
    key.secret = "K2tf3TRrmE7TJd+m2NPBuw==";
    key.decoded_secret = TSIG::base64Decode(key.secret);
    
    // Propagate to all zones
    acl.propagateTSIGKey(&key);
    
    // Verify both zones got the key
    assert(zone1.tsig_key != NULL);
    assert(zone2.tsig_key != NULL);
    assert(zone1.tsig_key->name == "testkey.example.com.");
    assert(zone2.tsig_key->algorithm == TSIG::HMAC_SHA256);
    
    cout << "  TSIG propagation: PASSED" << endl;
}

int main() {
    cout << "Running ACL unit tests..." << endl << endl;
    
    try {
        test_subnet_matching();
        test_subnet_toString();
        test_acl_access_control();
        test_acl_toString();
        test_acl_tsig_propagation();
        
        cout << endl << "All ACL tests PASSED!" << endl;
        return 0;
    } catch (const exception& e) {
        cerr << "Test FAILED: " << e.what() << endl;
        return 1;
    }
}
