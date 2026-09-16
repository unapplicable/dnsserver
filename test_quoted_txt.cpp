#include <iostream>
#include <string>
#include <vector>

#include "zoneFileLoader.h"
#include "zone.h"
#include "rr.h"
#include "rrtxt.h"

// Unit tests for quoted TXT records: semicolons and spaces inside double
// quotes must survive zone-file parsing (DKIM / DMARC records).

static int failures = 0;

static void expect(bool ok, const std::string& what)
{
	std::cout << (ok ? "[PASS] " : "[FAIL] ") << what << std::endl;
	if (!ok)
		++failures;
}

static Zone* loadQuotedZone()
{
	t_data data;
	data.push_back("$ORIGIN example.com");
	data.push_back("example.com.\t\t\tIN\tA\t192.0.2.1");
	data.push_back("example.com.\t\t\tIN\tTXT\tv=spf1 a mx ~all");
	data.push_back("mail._domainkey.example.com.\tIN\tTXT\t\"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB+abc\"");
	data.push_back("_dmarc.example.com.\t\tIN\tTXT\t\"v=DMARC1; p=none; sp=none; rua=mailto:postmaster@example.com; fo=1\"");
	data.push_back("quoted-comment.example.com.\tIN\tTXT\t\"a; b\" ; trailing comment");
	data.push_back("bang-comment.example.com.\tIN\tTXT\t\"x!y\" ! trailing comment");
	data.push_back("; a full-line comment");

	t_zones zones;
	if (!ZoneFileLoader::load(data, zones, "test_quoted_txt.zone"))
	{
		expect(false, "ZoneFileLoader::load returned false");
		return NULL;
	}
	expect(zones.size() == 1, "exactly one zone loaded");
	if (zones.empty())
		return NULL;
	Zone* z = zones[0];
	expect(z->name == "example.com", "zone name is example.com");
	return z;
}

static std::string rdataOf(Zone* z, const std::string& name)
{
	std::vector<RR*> rrs = z->findRecordsByName(name, RR::TXT);
	if (rrs.empty())
		return "";
	return rrs[0]->rdata;
}

int main()
{
	std::cout << "=== Quoted TXT zone-file parsing tests ===" << std::endl;

	Zone* z = loadQuotedZone();
	if (!z)
		return 1;

	expect(rdataOf(z, "mail._domainkey.example.com.") ==
	       "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB+abc",
	       "DKIM TXT keeps semicolons and p= intact");
	expect(rdataOf(z, "_dmarc.example.com.") ==
	       "v=DMARC1; p=none; sp=none; rua=mailto:postmaster@example.com; fo=1",
	       "DMARC TXT keeps full tag list");
	expect(rdataOf(z, "quoted-comment.example.com.") == "a; b",
	       "semicolon inside quotes is data, trailing comment stripped");
	expect(rdataOf(z, "bang-comment.example.com.") == "x!y",
	       "bang inside quotes is data, trailing comment stripped");
	expect(rdataOf(z, "example.com.") == "v=spf1 a mx ~all",
	       "unquoted TXT (SPF) still joins tokens with spaces");

	// TXT pack(): values longer than 255 bytes must be split across multiple
	// character-strings (RFC 1035 3.3.14) so the wire format stays valid.
	{
		RRTXT rr;
		std::string longval = "v=DKIM1; k=rsa; p=";
		for (int i = 0; i < 392; ++i)
			longval += 'A';
		rr.rdata = longval;
		char buf[1200];
		unsigned int off = 2; // RR::pack reserves the rdlen at offset-2
		rr.packContents(buf, sizeof(buf), off);
		std::string got;
		unsigned int idx = 2;
		unsigned int maxChunk = 0;
		while (idx < off)
		{
			unsigned int n = (unsigned char)buf[idx++];
			if (n > maxChunk)
				maxChunk = n;
			got.append(&buf[idx], n);
			idx += n;
		}
		expect(got == longval, "TXT >255 bytes packs as chunked char-strings and round-trips");
		expect(maxChunk <= 255, "no TXT character-string exceeds 255 bytes");
	}

	if (failures == 0)
	{
		std::cout << "All quoted TXT tests passed." << std::endl;
		return 0;
	}
	std::cout << failures << " test(s) FAILED." << std::endl;
	return 1;
}