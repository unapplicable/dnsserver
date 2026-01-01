#include <iostream>
#include <cassert>
#include <cstring>
#include "query_processor.h"
#include "zone.h"
#include "rra.h"
#include "rrcname.h"
#include "rrns.h"
#include "socket.h"

using namespace std;

void test_case_insensitive_matching() {
    cout << "Testing case-insensitive matching..." << endl;
    
    Zone z;
    z.name = "example.com.";
    
    // Add records (names are already lowercased in real zone loading)
    RRA *rr1 = new RRA();
    rr1->name = "host.example.com.";
    rr1->type = RR::A;
    rr1->rrclass = RR::CLASSIN;
    rr1->ttl = 300;
    // A records store IP in rdata as binary
    unsigned long addr1 = inet_addr("192.0.2.1");
    rr1->rdata.append(reinterpret_cast<char*>(&addr1), 4);
    z.rrs.push_back(rr1);
    
    RRA *rr2 = new RRA();
    rr2->name = "host.example.com.";
    rr2->type = RR::A;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    unsigned long addr2 = inet_addr("192.0.2.2");
    rr2->rdata.append(reinterpret_cast<char*>(&addr2), 4);
    z.rrs.push_back(rr2);
    
    // Zone z already available
    
    // Query with different case (but names are already lowercased in real parsing)
    RR query_rr;
    query_rr.name = dns_name_tolower("HOST.EXAMPLE.COM.");
    query_rr.type = RR::A;
    query_rr.rrclass = RR::CLASSIN;
    
    cout << "  Query name: '" << query_rr.name << "'" << endl;
    cout << "  Zone records:" << endl;
    for (size_t i = 0; i < z.rrs.size(); i++) {
        cout << "    [" << i << "] name='" << z.rrs[i]->name << "' type=" << z.rrs[i]->type << endl;
    }
    
    vector<RR*> matches;
    QueryProcessor::findMatches(&query_rr, z, matches);
    
    // Should match both records
    cout << "  Found " << matches.size() << " matches (expected 2)" << endl;
    assert(matches.size() == 2);
    cout << "  PASSED" << endl;
}

void test_wildcard_query() {
    cout << "Testing wildcard query..." << endl;
    
    Zone z;
    z.name = "example.com.";
    
    RRA *rr1 = new RRA();
    rr1->name = "test.example.com.";
    rr1->type = RR::A;
    rr1->rrclass = RR::CLASSIN;
    rr1->ttl = 300;
    unsigned long addr = inet_addr("192.0.2.1");
    rr1->rdata.append(reinterpret_cast<char*>(&addr), 4);
    z.rrs.push_back(rr1);
    
    RRCNAME *rr2 = new RRCNAME();
    rr2->name = "test.example.com.";
    rr2->type = RR::CNAME;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    rr2->rdata = "target.example.com.";
    z.rrs.push_back(rr2);
    
    // Zone z already available
    
    // Query with TYPESTAR
    RR query_rr;
    query_rr.name = "test.example.com.";
    query_rr.type = RR::TYPESTAR;
    query_rr.rrclass = RR::CLASSIN;
    
    vector<RR*> matches;
    QueryProcessor::findMatches(&query_rr, z, matches);
    
    // Should match both A and CNAME
    assert(matches.size() == 2);
    cout << "  Found " << matches.size() << " matches (expected 2)" << endl;
    cout << "  PASSED" << endl;
}

void test_ns_record_detection() {
    cout << "Testing NS record detection..." << endl;
    
    Zone z;
    z.name = "example.com.";
    
    RRNS *ns_rr = new RRNS();
    ns_rr->name = "sub.example.com.";
    ns_rr->type = RR::NS;
    ns_rr->rrclass = RR::CLASSIN;
    ns_rr->ttl = 300;
    ns_rr->rdata = "ns1.example.com.";
    z.rrs.push_back(ns_rr);
    
    // Zone z already available
    
    // Query for something under subdomain
    RR query_rr;
    query_rr.name = "host.sub.example.com.";
    query_rr.type = RR::A;
    query_rr.rrclass = RR::CLASSIN;
    
    vector<RR*> matches;
    RR *ns_record = NULL;
    QueryProcessor::findMatches(&query_rr, z, matches, &ns_record);
    
    // Should find NS record for delegation
    assert(ns_record != NULL);
    assert(ns_record->type == RR::NS);
    cout << "  Found NS record for delegation" << endl;
    cout << "  PASSED" << endl;
}

int main() {
    cout << "Running QueryProcessor unit tests..." << endl << endl;
    
    try {
        test_case_insensitive_matching();
        test_wildcard_query();
        test_ns_record_detection();
        
        cout << endl << "All tests PASSED!" << endl;
        return 0;
    } catch (const exception& e) {
        cerr << "Test FAILED: " << e.what() << endl;
        return 1;
    }
}
