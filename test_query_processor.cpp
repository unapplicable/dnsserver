#include <iostream>
#include <cassert>
#include <cstring>
#include "query_processor.h"
#include "zone.h"
#include "rra.h"
#include "rraaaa.h"
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
    z.addRecord(rr1);
    
    RRA *rr2 = new RRA();
    rr2->name = "host.example.com.";
    rr2->type = RR::A;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    unsigned long addr2 = inet_addr("192.0.2.2");
    rr2->rdata.append(reinterpret_cast<char*>(&addr2), 4);
    z.addRecord(rr2);
    
    // Zone z already available
    
    // Query with different case (but names are already lowercased in real parsing)
    RR query_rr;
    query_rr.name = dns_name_tolower("HOST.EXAMPLE.COM.");
    query_rr.type = RR::A;
    query_rr.rrclass = RR::CLASSIN;
    
    cout << "  Query name: '" << query_rr.name << "'" << endl;
    cout << "  Zone records:" << endl;
    const vector<RR*>& records = z.getAllRecords();
    for (size_t i = 0; i < records.size(); i++) {
        cout << "    [" << i << "] name='" << records[i]->name << "' type=" << records[i]->type << endl;
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
    z.addRecord(rr1);
    
    RRCNAME *rr2 = new RRCNAME();
    rr2->name = "test.example.com.";
    rr2->type = RR::CNAME;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    rr2->rdata = "target.example.com.";
    z.addRecord(rr2);
    
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
    z.addRecord(ns_rr);
    
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

void test_single_wildcard_prefix() {
    cout << "Testing single wildcard prefix (*.foo.com.)..." << endl;
    
    Zone z;
    z.name = "foo.com.";
    
    // Add immediate subdomains
    RRA *rr1 = new RRA();
    rr1->name = "a.foo.com.";
    rr1->type = RR::A;
    rr1->rrclass = RR::CLASSIN;
    rr1->ttl = 300;
    unsigned long addr1 = inet_addr("192.0.2.1");
    rr1->rdata.append(reinterpret_cast<char*>(&addr1), 4);
    z.addRecord(rr1);
    
    RRA *rr2 = new RRA();
    rr2->name = "b.foo.com.";
    rr2->type = RR::A;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    unsigned long addr2 = inet_addr("192.0.2.2");
    rr2->rdata.append(reinterpret_cast<char*>(&addr2), 4);
    z.addRecord(rr2);
    
    // Add nested subdomain (should NOT match *.foo.com.)
    RRA *rr3 = new RRA();
    rr3->name = "x.y.foo.com.";
    rr3->type = RR::A;
    rr3->rrclass = RR::CLASSIN;
    rr3->ttl = 300;
    unsigned long addr3 = inet_addr("192.0.2.3");
    rr3->rdata.append(reinterpret_cast<char*>(&addr3), 4);
    z.addRecord(rr3);
    
    // Add AAAA record for immediate subdomain
    RRAAAA *rr4 = new RRAAAA();
    rr4->name = "c.foo.com.";
    rr4->type = RR::AAAA;
    rr4->rrclass = RR::CLASSIN;
    rr4->ttl = 300;
    z.addRecord(rr4);
    
    // Query with *.foo.com. for A records
    RR query_rr;
    query_rr.name = "*.foo.com.";
    query_rr.type = RR::A;
    query_rr.rrclass = RR::CLASSIN;
    
    vector<RR*> matches;
    QueryProcessor::findMatches(&query_rr, z, matches);
    
    // Should match a.foo.com. and b.foo.com., but not x.y.foo.com. or c.foo.com. (AAAA)
    cout << "  Found " << matches.size() << " A record matches (expected 2)" << endl;
    assert(matches.size() == 2);
    
    // Verify the matched records
    bool found_a = false, found_b = false;
    for (size_t i = 0; i < matches.size(); i++) {
        if (matches[i]->name == "a.foo.com.") found_a = true;
        if (matches[i]->name == "b.foo.com.") found_b = true;
    }
    assert(found_a && found_b);
    
    cout << "  PASSED" << endl;
}

void test_double_wildcard_prefix() {
    cout << "Testing double wildcard prefix (**.foo.com.)..." << endl;
    
    Zone z;
    z.name = "foo.com.";
    
    // Add immediate subdomains
    RRA *rr1 = new RRA();
    rr1->name = "a.foo.com.";
    rr1->type = RR::A;
    rr1->rrclass = RR::CLASSIN;
    rr1->ttl = 300;
    unsigned long addr1 = inet_addr("192.0.2.1");
    rr1->rdata.append(reinterpret_cast<char*>(&addr1), 4);
    z.addRecord(rr1);
    
    // Add nested subdomains
    RRA *rr2 = new RRA();
    rr2->name = "x.y.foo.com.";
    rr2->type = RR::A;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    unsigned long addr2 = inet_addr("192.0.2.2");
    rr2->rdata.append(reinterpret_cast<char*>(&addr2), 4);
    z.addRecord(rr2);
    
    RRA *rr3 = new RRA();
    rr3->name = "a.b.c.foo.com.";
    rr3->type = RR::A;
    rr3->rrclass = RR::CLASSIN;
    rr3->ttl = 300;
    unsigned long addr3 = inet_addr("192.0.2.3");
    rr3->rdata.append(reinterpret_cast<char*>(&addr3), 4);
    z.addRecord(rr3);
    
    // Query with **.foo.com. for A records
    RR query_rr;
    query_rr.name = "**.foo.com.";
    query_rr.type = RR::A;
    query_rr.rrclass = RR::CLASSIN;
    
    vector<RR*> matches;
    QueryProcessor::findMatches(&query_rr, z, matches);
    
    // Should match all A records under foo.com.
    cout << "  Found " << matches.size() << " A record matches (expected 3)" << endl;
    assert(matches.size() == 3);
    
    // Verify the matched records
    bool found_a = false, found_xy = false, found_abc = false;
    for (size_t i = 0; i < matches.size(); i++) {
        if (matches[i]->name == "a.foo.com.") found_a = true;
        if (matches[i]->name == "x.y.foo.com.") found_xy = true;
        if (matches[i]->name == "a.b.c.foo.com.") found_abc = true;
    }
    assert(found_a && found_xy && found_abc);
    
    cout << "  PASSED" << endl;
}

void test_wildcard_with_typestar() {
    cout << "Testing wildcard prefix with TYPESTAR..." << endl;
    
    Zone z;
    z.name = "foo.com.";
    
    // Add multiple record types for same name
    RRA *rr1 = new RRA();
    rr1->name = "a.foo.com.";
    rr1->type = RR::A;
    rr1->rrclass = RR::CLASSIN;
    rr1->ttl = 300;
    unsigned long addr = inet_addr("192.0.2.1");
    rr1->rdata.append(reinterpret_cast<char*>(&addr), 4);
    z.addRecord(rr1);
    
    RRAAAA *rr2 = new RRAAAA();
    rr2->name = "a.foo.com.";
    rr2->type = RR::AAAA;
    rr2->rrclass = RR::CLASSIN;
    rr2->ttl = 300;
    z.addRecord(rr2);
    
    RRCNAME *rr3 = new RRCNAME();
    rr3->name = "b.foo.com.";
    rr3->type = RR::CNAME;
    rr3->rrclass = RR::CLASSIN;
    rr3->ttl = 300;
    rr3->rdata = "target.foo.com.";
    z.addRecord(rr3);
    
    // Query with *.foo.com. for all types
    RR query_rr;
    query_rr.name = "*.foo.com.";
    query_rr.type = RR::TYPESTAR;
    query_rr.rrclass = RR::CLASSIN;
    
    vector<RR*> matches;
    QueryProcessor::findMatches(&query_rr, z, matches);
    
    // Should match all records immediately under foo.com.
    cout << "  Found " << matches.size() << " matches (expected 3)" << endl;
    assert(matches.size() == 3);
    
    cout << "  PASSED" << endl;
}

void test_wildcard_no_matches() {
    cout << "Testing wildcard with no matches..." << endl;
    
    Zone z;
    z.name = "foo.com.";
    
    // Add record that doesn't match
    RRA *rr1 = new RRA();
    rr1->name = "bar.com.";
    rr1->type = RR::A;
    rr1->rrclass = RR::CLASSIN;
    rr1->ttl = 300;
    unsigned long addr = inet_addr("192.0.2.1");
    rr1->rdata.append(reinterpret_cast<char*>(&addr), 4);
    z.addRecord(rr1);
    
    // Query with *.foo.com.
    RR query_rr;
    query_rr.name = "*.foo.com.";
    query_rr.type = RR::A;
    query_rr.rrclass = RR::CLASSIN;
    
    vector<RR*> matches;
    QueryProcessor::findMatches(&query_rr, z, matches);
    
    // Should match nothing
    cout << "  Found " << matches.size() << " matches (expected 0)" << endl;
    assert(matches.size() == 0);
    
    cout << "  PASSED" << endl;
}

int main() {
    cout << "Running QueryProcessor unit tests..." << endl << endl;
    
    try {
        test_case_insensitive_matching();
        test_wildcard_query();
        test_ns_record_detection();
        test_single_wildcard_prefix();
        test_double_wildcard_prefix();
        test_wildcard_with_typestar();
        test_wildcard_no_matches();
        
        cout << endl << "All tests PASSED!" << endl;
        return 0;
    } catch (const exception& e) {
        cerr << "Test FAILED: " << e.what() << endl;
        return 1;
    }
}
