#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include "rr.h"
#include "rra.h"
#include "rraaaa.h"
#include "rrsoa.h"
#include "rrns.h"
#include "rrmx.h"
#include "rrcname.h"
#include "rrptr.h"
#include "rrtxt.h"
#include "rrcert.h"
#include "rrdhcid.h"

using namespace std;

// Helper function to test roundtrip for any RR type
template<typename RRType>
bool testRRRoundtrip(const string& test_name, const vector<string>& input_tokens, 
                      const string& origin = "")
{
	cout << "Testing " << test_name << "..." << endl;
	
	// Phase 1: Parse from string
	RRType* rr1 = new RRType();
	rr1->fromString(input_tokens, origin);
	
	// Phase 2: Convert to string
	string str1 = rr1->toString();
	cout << "  Generated: " << str1 << endl;
	
	// Phase 3: Parse again from the generated string
	// Tokenize the generated string
	vector<string> tokens2;
	string temp;
	for (size_t i = 0; i < str1.length(); i++)
	{
		if (str1[i] == ' ' || str1[i] == '\t')
		{
			if (!temp.empty())
			{
				tokens2.push_back(temp);
				temp.clear();
			}
		}
		else
		{
			temp += str1[i];
		}
	}
	if (!temp.empty())
		tokens2.push_back(temp);
	
	RRType* rr2 = new RRType();
	rr2->fromString(tokens2, origin);
	
	// Phase 4: Compare the two RR objects
	bool success = true;
	
	// Compare basic fields
	if (rr1->name != rr2->name)
	{
		cerr << "  ERROR: Names differ: '" << rr1->name << "' vs '" << rr2->name << "'" << endl;
		success = false;
	}
	
	if (rr1->type != rr2->type)
	{
		cerr << "  ERROR: Types differ" << endl;
		success = false;
	}
	
	if (rr1->rrclass != rr2->rrclass)
	{
		cerr << "  ERROR: Classes differ" << endl;
		success = false;
	}
	
	// Compare toString output
	string str2 = rr2->toString();
	if (str1 != str2)
	{
		cerr << "  ERROR: toString() outputs differ:" << endl;
		cerr << "    First:  " << str1 << endl;
		cerr << "    Second: " << str2 << endl;
		success = false;
	}
	
	delete rr1;
	delete rr2;
	
	if (success)
		cout << "  ✓ PASS" << endl;
	else
		cout << "  ✗ FAIL" << endl;
		
	cout << endl;
	return success;
}

// Specialized test for SOA (has many fields)
bool testSOARoundtrip()
{
	cout << "Testing SOA record roundtrip..." << endl;
	
	vector<string> tokens;
	tokens.push_back("example.com.");
	tokens.push_back("IN");
	tokens.push_back("SOA");
	tokens.push_back("ns1.example.com.");
	tokens.push_back("admin.example.com.");
	tokens.push_back("2026010201");
	tokens.push_back("3600");
	tokens.push_back("1800");
	tokens.push_back("604800");
	tokens.push_back("86400");
	
	RRSoa* soa1 = new RRSoa();
	soa1->fromString(tokens);
	
	// Check all fields
	assert(soa1->name == "example.com.");
	assert(soa1->type == RR::SOA);
	assert(soa1->ns == "ns1.example.com.");
	assert(soa1->mail == "admin.example.com.");
	assert(soa1->serial == 2026010201UL);
	assert(soa1->refresh == 3600UL);
	assert(soa1->retry == 1800UL);
	assert(soa1->expire == 604800UL);
	assert(soa1->minttl == 86400UL);
	
	string str1 = soa1->toString();
	cout << "  Generated: " << str1 << endl;
	
	// Parse again
	vector<string> tokens2;
	string temp;
	for (size_t i = 0; i < str1.length(); i++)
	{
		if (str1[i] == ' ' || str1[i] == '\t')
		{
			if (!temp.empty())
			{
				tokens2.push_back(temp);
				temp.clear();
			}
		}
		else
		{
			temp += str1[i];
		}
	}
	if (!temp.empty())
		tokens2.push_back(temp);
	
	RRSoa* soa2 = new RRSoa();
	soa2->fromString(tokens2);
	
	// Verify all fields match
	bool success = true;
	if (soa1->name != soa2->name) { cerr << "  ERROR: name mismatch" << endl; success = false; }
	if (soa1->ns != soa2->ns) { cerr << "  ERROR: ns mismatch" << endl; success = false; }
	if (soa1->mail != soa2->mail) { cerr << "  ERROR: mail mismatch" << endl; success = false; }
	if (soa1->serial != soa2->serial) { cerr << "  ERROR: serial mismatch" << endl; success = false; }
	if (soa1->refresh != soa2->refresh) { cerr << "  ERROR: refresh mismatch" << endl; success = false; }
	if (soa1->retry != soa2->retry) { cerr << "  ERROR: retry mismatch" << endl; success = false; }
	if (soa1->expire != soa2->expire) { cerr << "  ERROR: expire mismatch" << endl; success = false; }
	if (soa1->minttl != soa2->minttl) { cerr << "  ERROR: minttl mismatch" << endl; success = false; }
	
	string str2 = soa2->toString();
	if (str1 != str2)
	{
		cerr << "  ERROR: toString() mismatch" << endl;
		cerr << "    First:  " << str1 << endl;
		cerr << "    Second: " << str2 << endl;
		success = false;
	}
	
	delete soa1;
	delete soa2;
	
	if (success)
		cout << "  ✓ PASS" << endl;
	else
		cout << "  ✗ FAIL" << endl;
		
	cout << endl;
	return success;
}

int main()
{
	cout << "========================================" << endl;
	cout << "RR Type Roundtrip Tests" << endl;
	cout << "Testing: fromString → toString → fromString" << endl;
	cout << "========================================" << endl << endl;
	
	int passed = 0;
	int total = 0;
	
	// Test A record
	{
		vector<string> tokens;
		tokens.push_back("www.example.com.");
		tokens.push_back("IN");
		tokens.push_back("A");
		tokens.push_back("192.168.1.1");
		if (testRRRoundtrip<RRA>("A Record", tokens))
			passed++;
		total++;
	}
	
	// Test AAAA record (using full uncompressed format - IPv6 compression not yet supported)
	{
		vector<string> tokens;
		tokens.push_back("www.example.com.");
		tokens.push_back("IN");
		tokens.push_back("AAAA");
		tokens.push_back("2001:0db8:0000:0000:0000:0000:0000:0001");
		if (testRRRoundtrip<RRAAAA>("AAAA Record", tokens))
			passed++;
		total++;
	}
	
	// Test NS record
	{
		vector<string> tokens;
		tokens.push_back("example.com.");
		tokens.push_back("IN");
		tokens.push_back("NS");
		tokens.push_back("ns1.example.com.");
		if (testRRRoundtrip<RRNS>("NS Record", tokens))
			passed++;
		total++;
	}
	
	// Test MX record
	{
		vector<string> tokens;
		tokens.push_back("example.com.");
		tokens.push_back("IN");
		tokens.push_back("MX");
		tokens.push_back("10");
		tokens.push_back("mail.example.com.");
		if (testRRRoundtrip<RRMX>("MX Record", tokens))
			passed++;
		total++;
	}
	
	// Test CNAME record
	{
		vector<string> tokens;
		tokens.push_back("www.example.com.");
		tokens.push_back("IN");
		tokens.push_back("CNAME");
		tokens.push_back("web.example.com.");
		if (testRRRoundtrip<RRCNAME>("CNAME Record", tokens))
			passed++;
		total++;
	}
	
	// Test PTR record
	{
		vector<string> tokens;
		tokens.push_back("1.1.168.192.in-addr.arpa.");
		tokens.push_back("IN");
		tokens.push_back("PTR");
		tokens.push_back("www.example.com.");
		if (testRRRoundtrip<RRPTR>("PTR Record", tokens))
			passed++;
		total++;
	}
	
	// Test TXT record
	{
		vector<string> tokens;
		tokens.push_back("example.com.");
		tokens.push_back("IN");
		tokens.push_back("TXT");
		tokens.push_back("v=spf1 include:_spf.example.com ~all");
		if (testRRRoundtrip<RRTXT>("TXT Record", tokens))
			passed++;
		total++;
	}
	
	// Test SOA record (special test)
	if (testSOARoundtrip())
		passed++;
	total++;
	
	// Test CERT record
	{
		vector<string> tokens;
		tokens.push_back("example.com.");
		tokens.push_back("IN");
		tokens.push_back("CERT");
		tokens.push_back("1");
		tokens.push_back("0");
		tokens.push_back("0");
		tokens.push_back("AQNRU3mG7TVTO...");
		if (testRRRoundtrip<RRCERT>("CERT Record", tokens))
			passed++;
		total++;
	}
	
	// Test DHCID record
	{
		vector<string> tokens;
		tokens.push_back("host.example.com.");
		tokens.push_back("IN");
		tokens.push_back("DHCID");
		tokens.push_back("AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=");
		if (testRRRoundtrip<RRDHCID>("DHCID Record", tokens))
			passed++;
		total++;
	}
	
	cout << "========================================" << endl;
	cout << "Results: " << passed << "/" << total << " tests passed" << endl;
	
	if (passed == total)
	{
		cout << "✅ ALL TESTS PASSED!" << endl;
		return 0;
	}
	else
	{
		cout << "❌ SOME TESTS FAILED" << endl;
		return 1;
	}
}
