#include "zone.h"
#include "acl.h"
#include "rra.h"
#include "rrsoa.h"
#include "socket.h"
#include <iostream>
#include <cassert>
#include <sstream>
#include <vector>

using namespace std;

// Helper to get IP from RRA record
static unsigned long getRRAIp(RRA* rra)
{
	// Parse the IP from the toString output
	string str = rra->toString();
	// Format is "name type ttl ip"
	size_t last_space = str.rfind(' ');
	if (last_space != string::npos)
	{
		string ip_str = str.substr(last_space + 1);
		return inet_addr(ip_str.c_str());
	}
	return 0;
}

// Helper to create an RRA record with specific IP
static RRA* createRRA(const string& name, const string& ip_str)
{
	RRA* rra = new RRA();
	rra->name = name;
	rra->type = RR::A;
	vector<string> parts;
	parts.push_back(ip_str);
	rra->fromStringContents(parts);
	return rra;
}

// Test that the most specific (longest prefix) ACL match is returned
void testAclLongestMatch()
{
	cout << "TEST: ACL longest prefix match selection" << endl;
	
	// Create parent zone
	Zone* parent_zone = new Zone();
	parent_zone->name = "example.com.";
	
	RR* soa1 = new RRSoa();
	soa1->name = "example.com.";
	soa1->type = RR::SOA;
	parent_zone->addRecord(soa1);
	
	RRA* a1 = createRRA("www.example.com.", "1.2.3.4");
	parent_zone->addRecord(a1);
	
	// Create ACL sub-zones with different subnets
	Zone* acl_zone_24 = new Zone();
	acl_zone_24->name = "example.com.";
	acl_zone_24->parent = parent_zone;
	RRA* a2 = createRRA("www.example.com.", "10.0.0.1");
	acl_zone_24->addRecord(a2);
	
	Zone* acl_zone_28 = new Zone();
	acl_zone_28->name = "example.com.";
	acl_zone_28->parent = parent_zone;
	RRA* a3 = createRRA("www.example.com.", "10.0.1.1");
	acl_zone_28->addRecord(a3);
	
	Zone* acl_zone_30 = new Zone();
	acl_zone_30->name = "example.com.";
	acl_zone_30->parent = parent_zone;
	RRA* a4 = createRRA("www.example.com.", "10.0.2.1");
	acl_zone_30->addRecord(a4);
	
	// Add ACL entries to parent zone (not in specificity order)
	parent_zone->acl->addSubnet("192.168.1.0/24", acl_zone_24);  // /24
	parent_zone->acl->addSubnet("192.168.1.16/30", acl_zone_30); // /30 (most specific)
	parent_zone->acl->addSubnet("192.168.1.0/28", acl_zone_28);  // /28
	
	// Test 1: IP matching only /24 should return acl_zone_24
	unsigned long test_ip_1 = inet_addr("192.168.1.100");
	Zone* result1 = parent_zone->acl->findMostSpecificMatch(test_ip_1);
	assert(result1 == acl_zone_24);
	cout << "  ✓ IP 192.168.1.100 matches /24 subnet (least specific match)" << endl;
	
	// Test 2: IP matching /28 and /24 should return acl_zone_28 (more specific)
	unsigned long test_ip_2 = inet_addr("192.168.1.10");
	Zone* result2 = parent_zone->acl->findMostSpecificMatch(test_ip_2);
	assert(result2 == acl_zone_28);
	cout << "  ✓ IP 192.168.1.10 matches /28 subnet (more specific than /24)" << endl;
	
	// Test 3: IP matching all three should return acl_zone_30 (most specific)
	unsigned long test_ip_3 = inet_addr("192.168.1.17");
	Zone* result3 = parent_zone->acl->findMostSpecificMatch(test_ip_3);
	assert(result3 == acl_zone_30);
	cout << "  ✓ IP 192.168.1.17 matches /30 subnet (most specific)" << endl;
	
	// Test 4: IP not matching any ACL should return NULL
	unsigned long test_ip_4 = inet_addr("10.0.0.1");
	Zone* result4 = parent_zone->acl->findMostSpecificMatch(test_ip_4);
	assert(result4 == NULL);
	cout << "  ✓ IP 10.0.0.1 doesn't match any ACL (NULL)" << endl;
	
	// Test 5: IP matching only /30 and /28 should return acl_zone_30
	unsigned long test_ip_5 = inet_addr("192.168.1.18");
	Zone* result5 = parent_zone->acl->findMostSpecificMatch(test_ip_5);
	assert(result5 == acl_zone_30);
	cout << "  ✓ IP 192.168.1.18 matches /30 subnet (most specific of two matches)" << endl;
	
	delete parent_zone;
	delete acl_zone_24;
	delete acl_zone_28;
	delete acl_zone_30;
	
	cout << "PASS: ACL longest prefix match" << endl << endl;
}

// Test that conflicting records in ACL zones work correctly
void testAclConflictingRecords()
{
	cout << "TEST: ACL zones with conflicting records" << endl;
	
	// Create parent zone with one A record
	Zone* parent_zone = new Zone();
	parent_zone->name = "test.com.";
	
	RR* soa1 = new RRSoa();
	soa1->name = "test.com.";
	soa1->type = RR::SOA;
	parent_zone->addRecord(soa1);
	
	RRA* parent_a = createRRA("server.test.com.", "192.168.1.1");
	parent_zone->addRecord(parent_a);
	
	// Create ACL sub-zone with different A record for same name
	Zone* acl_zone = new Zone();
	acl_zone->name = "test.com.";
	acl_zone->parent = parent_zone;
	
	RRA* acl_a = createRRA("server.test.com.", "10.0.0.1");
	acl_zone->addRecord(acl_a);
	
	parent_zone->acl->addSubnet("10.0.0.0/8", acl_zone);
	
	// Verify records exist in each zone
	const vector<RR*>& parent_records = parent_zone->getAllRecords();
	assert(parent_records.size() == 2); // SOA + A
	
	const vector<RR*>& acl_records = acl_zone->getAllRecords();
	assert(acl_records.size() == 1); // Just A record
	
	// Find the A records
	RRA* found_parent_a = NULL;
	for (vector<RR*>::const_iterator it = parent_records.begin(); it != parent_records.end(); ++it)
	{
		if ((*it)->type == RR::A && (*it)->name == "server.test.com.")
		{
			found_parent_a = (RRA*)(*it);
			break;
		}
	}
	assert(found_parent_a != NULL);
	assert(getRRAIp(found_parent_a) == inet_addr("192.168.1.1"));
	
	RRA* found_acl_a = NULL;
	for (vector<RR*>::const_iterator it = acl_records.begin(); it != acl_records.end(); ++it)
	{
		if ((*it)->type == RR::A)
		{
			found_acl_a = (RRA*)(*it);
			break;
		}
	}
	assert(found_acl_a != NULL);
	assert(getRRAIp(found_acl_a) == inet_addr("10.0.0.1"));
	
	cout << "  ✓ Parent zone has A record: server.test.com. -> 192.168.1.1" << endl;
	cout << "  ✓ ACL zone has A record: server.test.com. -> 10.0.0.1" << endl;
	cout << "  ✓ Records with same name can exist in parent and ACL zones" << endl;
	
	delete parent_zone;
	delete acl_zone;
	
	cout << "PASS: ACL conflicting records" << endl << endl;
}

// Test multiple ACL entries with overlapping subnets
void testMultipleOverlappingAcls()
{
	cout << "TEST: Multiple overlapping ACL subnets" << endl;
	
	Zone* parent_zone = new Zone();
	parent_zone->name = "corp.local.";
	
	// Create multiple ACL zones
	Zone* acl1 = new Zone();
	acl1->name = "corp.local.";
	Zone* acl2 = new Zone();
	acl2->name = "corp.local.";
	Zone* acl3 = new Zone();
	acl3->name = "corp.local.";
	
	RRA* a1 = createRRA("service.corp.local.", "172.16.0.1");
	acl1->addRecord(a1);
	
	RRA* a2 = createRRA("service.corp.local.", "172.16.1.1");
	acl2->addRecord(a2);
	
	RRA* a3 = createRRA("service.corp.local.", "172.16.2.1");
	acl3->addRecord(a3);
	
	// Add ACL entries with overlapping subnets
	parent_zone->acl->addSubnet("10.0.0.0/8", acl1);      // Covers all 10.x.x.x
	parent_zone->acl->addSubnet("10.1.0.0/16", acl2);     // Covers 10.1.x.x (more specific)
	parent_zone->acl->addSubnet("10.1.1.0/24", acl3);     // Covers 10.1.1.x (most specific)
	
	// Test longest match for 10.1.1.50 -> should get acl3
	unsigned long ip1 = inet_addr("10.1.1.50");
	Zone* result1 = parent_zone->acl->findMostSpecificMatch(ip1);
	assert(result1 == acl3);
	cout << "  ✓ IP 10.1.1.50 matches /24 subnet (most specific of three)" << endl;
	
	// Test longest match for 10.1.5.50 -> should get acl2
	unsigned long ip2 = inet_addr("10.1.5.50");
	Zone* result2 = parent_zone->acl->findMostSpecificMatch(ip2);
	assert(result2 == acl2);
	cout << "  ✓ IP 10.1.5.50 matches /16 subnet (more specific than /8)" << endl;
	
	// Test longest match for 10.5.5.50 -> should get acl1
	unsigned long ip3 = inet_addr("10.5.5.50");
	Zone* result3 = parent_zone->acl->findMostSpecificMatch(ip3);
	assert(result3 == acl1);
	cout << "  ✓ IP 10.5.5.50 matches /8 subnet (only match)" << endl;
	
	delete parent_zone;
	delete acl1;
	delete acl2;
	delete acl3;
	
	cout << "PASS: Multiple overlapping ACLs" << endl << endl;
}

int main()
{
	cout << "=== ACL Longest Match Tests ===" << endl << endl;
	
	testAclLongestMatch();
	testAclConflictingRecords();
	testMultipleOverlappingAcls();
	
	cout << "=== All ACL Longest Match Tests Passed ===" << endl;
	
	return 0;
}
