#include "query_processor.h"
#include "zone_authority.h"
#include "acl.h"
#include "rra.h"
#include "rrsoa.h"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace std;

void test_acl_query_returns_both_zones()
{
    cout << "TEST: ACL query returns records from both main and ACL zones" << endl;
    
    // Create main zone
    Zone* main_zone = new Zone();
    main_zone->name = "example.com.";
    
    // Add SOA to main zone
    RRSoa* soa = new RRSoa();
    soa->name = "example.com.";
    soa->type = RR::SOA;
    soa->ns = "ns1.example.com.";
    soa->mail = "admin.example.com.";
    soa->serial = 2025010201;
    soa->refresh = 3600;
    soa->retry = 600;
    soa->expire = 86400;
    soa->minttl = 300;
    main_zone->addRecord(soa);
    
    // Add A record to main zone using fromString
    RRA* main_a = new RRA();
    main_a->name = "example.com.";
    main_a->type = RR::A;
    vector<string> a_data;
    a_data.push_back("1.2.3.4");
    main_a->fromStringContents(a_data);
    main_zone->addRecord(main_a);
    
    // Create ACL sub-zone
    Zone* acl_zone = new Zone();
    acl_zone->name = "example.com.";
    acl_zone->parent = main_zone;
    
    // Add A record to ACL zone using fromString
    RRA* acl_a = new RRA();
    acl_a->name = "example.com.";
    acl_a->type = RR::A;
    vector<string> acl_data;
    acl_data.push_back("10.0.0.1");
    acl_a->fromStringContents(acl_data);
    acl_zone->addRecord(acl_a);
    
    // Setup ACL
    Acl* acl = new Acl();
    acl->addSubnet("192.168.1.0/24", acl_zone);
    main_zone->acl = acl;
    
    // Create query for ANY record
    RR query;
    query.name = "example.com.";
    query.type = RR::TYPESTAR;  // ANY query
    
    // Test 1: Query from ACL subnet should return records from both zones
    vector<RR*> matches;
    RR* ns = NULL;
    
    // First search ACL zone
    QueryProcessor::findMatches(&query, *acl_zone, matches, &ns);
    
    // Then search parent zone
    if (acl_zone->parent)
    {
        QueryProcessor::findMatches(&query, *acl_zone->parent, matches, &ns);
    }
    
    // Should have 3 records: SOA from main, A from main, A from ACL
    cout << "Found " << matches.size() << " matches:" << endl;
    for (vector<RR*>::iterator it = matches.begin(); it != matches.end(); ++it)
    {
        RR* rr = *it;
        cout << "  - " << rr->name << " " << rr->type << endl;
    }
    assert(matches.size() == 3);
    
    bool found_soa = false;
    bool found_main_a = false;
    bool found_acl_a = false;
    
    for (vector<RR*>::iterator it = matches.begin(); it != matches.end(); ++it)
    {
        RR* rr = *it;
        if (rr->type == RR::SOA)
        {
            found_soa = true;
        }
        else if (rr->type == RR::A && rr->name == "example.com.")
        {
            if (!found_main_a)
                found_main_a = true;
            else
                found_acl_a = true;
        }
    }
    
    assert(found_soa);
    assert(found_main_a);
    assert(found_acl_a);
    
    // Cleanup - set parent to NULL to prevent double-free
    acl_zone->parent = NULL;
    main_zone->acl = NULL;
    delete acl;
    delete main_zone;
    delete acl_zone;
    
    cout << "PASS" << endl;
}

int main()
{
    test_acl_query_returns_both_zones();
    cout << "All ACL query tests passed!" << endl;
    return 0;
}
