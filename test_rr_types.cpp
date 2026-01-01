#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include <cstring>
#include <arpa/inet.h>
#include "message.h"
#include "rr.h"
#include "rra.h"
#include "rraaaa.h"
#include "rrcert.h"
#include "rrcname.h"
#include "rrdhcid.h"
#include "rrmx.h"
#include "rrns.h"
#include "rrptr.h"
#include "rrsoa.h"
#include "rrtxt.h"
#include "zoneFileLoader.h"
#include "zone.h"

// ===== Test A Records =====

TEST_CASE("RRA: Parse from zone file", "[rr][a][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN example.com.");
    zoneData.push_back("www     IN  A       192.168.1.1");
    zoneData.push_back("mail    IN  A       10.0.0.5");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 2);
    
    RR* rr1 = zones[0]->getAllRecords()[0];
    CHECK(rr1->name == "www.example.com.");
    CHECK(rr1->type == RR::A);
    CHECK(rr1->rrclass == RR::CLASSIN);
    
    RRA* a_rr = dynamic_cast<RRA*>(rr1);
    REQUIRE(a_rr != nullptr);
    CHECK(a_rr->rdata.length() == 4);
    // Verify IP address bytes
    CHECK((unsigned char)a_rr->rdata[0] == 192);
    CHECK((unsigned char)a_rr->rdata[1] == 168);
    CHECK((unsigned char)a_rr->rdata[2] == 1);
    CHECK((unsigned char)a_rr->rdata[3] == 1);
}

TEST_CASE("RRA: Unpack from network", "[rr][a][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "host.test"
    packet[0] = 4;
    memcpy(packet + 1, "host", 4);
    packet[5] = 4;
    memcpy(packet + 6, "test", 4);
    packet[10] = 0;
    
    // Type: A
    *(uint16_t*)(packet + 11) = htons(1);
    
    // Class: IN
    *(uint16_t*)(packet + 13) = htons(1);
    
    // TTL: 3600
    *(uint32_t*)(packet + 15) = htonl(3600);
    
    // RDLEN: 4
    *(uint16_t*)(packet + 19) = htons(4);
    
    // RDATA: 192.168.1.100
    packet[21] = 192;
    packet[22] = 168;
    packet[23] = 1;
    packet[24] = 100;
    
    RRA* rr = new RRA();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "host.test.");
    CHECK(rr->type == RR::A);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 3600);
    CHECK(rr->rdlen == 4);
    CHECK(rr->rdata.length() == 4);
    // Verify IP address
    CHECK((unsigned char)rr->rdata[0] == 192);
    CHECK((unsigned char)rr->rdata[1] == 168);
    CHECK((unsigned char)rr->rdata[2] == 1);
    CHECK((unsigned char)rr->rdata[3] == 100);
    
    delete rr;
}

// ===== Test AAAA Records =====

TEST_CASE("RRAAAA: Parse from zone file", "[rr][aaaa][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN ipv6.test.");
    // Format with colons every 4 hex digits, as expected by aaaa2bin (i += 5)
    zoneData.push_back("host    IN  AAAA    2001:0db8:0000:0000:0000:0000:0000:0001");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 1);
    
    RR* rr = zones[0]->getAllRecords()[0];
    CHECK(rr->name == "host.ipv6.test.");
    CHECK(rr->type == RR::AAAA);
    
    RRAAAA* aaaa_rr = dynamic_cast<RRAAAA*>(rr);
    REQUIRE(aaaa_rr != nullptr);
    CHECK(aaaa_rr->rdata.length() == 16);
    CHECK(aaaa_rr->rrclass == RR::CLASSIN);
    // Verify IPv6 address starts with 2001:0db8
    CHECK((unsigned char)aaaa_rr->rdata[0] == 0x20);
    CHECK((unsigned char)aaaa_rr->rdata[1] == 0x01);
    CHECK((unsigned char)aaaa_rr->rdata[2] == 0x0d);
    CHECK((unsigned char)aaaa_rr->rdata[3] == 0xb8);
}

TEST_CASE("RRAAAA: Unpack from network", "[rr][aaaa][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "v6"
    packet[0] = 2;
    memcpy(packet + 1, "v6", 2);
    packet[3] = 0;
    
    // Type: AAAA (28)
    *(uint16_t*)(packet + 4) = htons(28);
    
    // Class: IN
    *(uint16_t*)(packet + 6) = htons(1);
    
    // TTL: 7200
    *(uint32_t*)(packet + 8) = htonl(7200);
    
    // RDLEN: 16
    *(uint16_t*)(packet + 12) = htons(16);
    
    // RDATA: 2001:db8::1 (simplified)
    packet[14] = 0x20; packet[15] = 0x01;
    packet[16] = 0x0d; packet[17] = 0xb8;
    // Rest zeros
    packet[29] = 0x01;
    
    RRAAAA* rr = new RRAAAA();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "v6.");
    CHECK(rr->type == RR::AAAA);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 7200);
    CHECK(rr->rdlen == 16);
    CHECK(rr->rdata.length() == 16);
    // Verify IPv6 bytes
    CHECK((unsigned char)rr->rdata[0] == 0x20);
    CHECK((unsigned char)rr->rdata[1] == 0x01);
    CHECK((unsigned char)rr->rdata[15] == 0x01);
    
    delete rr;
}

// ===== Test CNAME Records =====

TEST_CASE("RRCNAME: Parse from zone file", "[rr][cname][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN example.org.");
    zoneData.push_back("www     IN  CNAME   server.example.org.");
    zoneData.push_back("ftp     IN  CNAME   www");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 2);
    
    RRCNAME* cname1 = dynamic_cast<RRCNAME*>(zones[0]->getAllRecords()[0]);
    REQUIRE(cname1 != nullptr);
    CHECK(cname1->name == "www.example.org.");
    CHECK(cname1->type == RR::CNAME);
    CHECK(cname1->rrclass == RR::CLASSIN);
    CHECK(cname1->rdata == "server.example.org.");
    
    RRCNAME* cname2 = dynamic_cast<RRCNAME*>(zones[0]->getAllRecords()[1]);
    REQUIRE(cname2 != nullptr);
    CHECK(cname2->name == "ftp.example.org.");
    CHECK(cname2->rdata == "www.example.org.");
}

TEST_CASE("RRCNAME: Unpack from network", "[rr][cname][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "alias"
    packet[0] = 5;
    memcpy(packet + 1, "alias", 5);
    packet[6] = 0;
    
    // Type: CNAME (5)
    *(uint16_t*)(packet + 7) = htons(5);
    
    // Class: IN
    *(uint16_t*)(packet + 9) = htons(1);
    
    // TTL: 300
    *(uint32_t*)(packet + 11) = htonl(300);
    
    // RDLEN: 9
    *(uint16_t*)(packet + 15) = htons(9);
    
    // RDATA: "target" (encoded DNS name)
    packet[17] = 6;
    memcpy(packet + 18, "target", 6);
    packet[24] = 0;
    
    RRCNAME* rr = new RRCNAME();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "alias.");
    CHECK(rr->type == RR::CNAME);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 300);
    CHECK(rr->rdlen == 9);
    // After unpacking, rdata should contain the target domain name
    CHECK(rr->rdata == "target.");
    
    delete rr;
}

// ===== Test MX Records =====

TEST_CASE("RRMX: Parse from zone file", "[rr][mx][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN mail.test.");
    // Don't use @, specify full names
    zoneData.push_back("mail.test.  IN  MX      10 mail1.mail.test.");
    zoneData.push_back("mail.test.  IN  MX      20 mail2.mail.test.");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 2);
    
    RRMX* mx1 = dynamic_cast<RRMX*>(zones[0]->getAllRecords()[0]);
    REQUIRE(mx1 != nullptr);
    CHECK(mx1->name == "mail.test.");
    CHECK(mx1->type == RR::MX);
    CHECK(mx1->rrclass == RR::CLASSIN);
    CHECK(mx1->pref == 10);
    CHECK(mx1->rdata == "mail1.mail.test.");
    
    RRMX* mx2 = dynamic_cast<RRMX*>(zones[0]->getAllRecords()[1]);
    REQUIRE(mx2 != nullptr);
    CHECK(mx2->pref == 20);
    CHECK(mx2->rdata == "mail2.mail.test.");
}

TEST_CASE("RRMX: Unpack from network", "[rr][mx][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "domain"
    packet[0] = 6;
    memcpy(packet + 1, "domain", 6);
    packet[7] = 0;
    
    // Type: MX (15)
    *(uint16_t*)(packet + 8) = htons(15);
    
    // Class: IN
    *(uint16_t*)(packet + 10) = htons(1);
    
    // TTL: 3600
    *(uint32_t*)(packet + 12) = htonl(3600);
    
    // RDLEN: 11
    *(uint16_t*)(packet + 16) = htons(11);
    
    // RDATA: priority (10) + mail server name
    *(uint16_t*)(packet + 18) = htons(10);
    packet[20] = 4;
    memcpy(packet + 21, "mail", 4);
    packet[25] = 0;
    
    RRMX* rr = new RRMX();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "domain.");
    CHECK(rr->type == RR::MX);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 3600);
    CHECK(rr->pref == 10);
    CHECK(rr->rdata == "mail.");
    
    delete rr;
}

// ===== Test NS Records =====

TEST_CASE("RRNS: Parse from zone file", "[rr][ns][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN zone.test.");
    zoneData.push_back("zone.test.  IN  NS      ns1.zone.test.");
    zoneData.push_back("zone.test.  IN  NS      ns2.zone.test.");
    zoneData.push_back("sub         IN  NS      ns.sub.zone.test.");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 3);
    
    RRNS* ns1 = dynamic_cast<RRNS*>(zones[0]->getAllRecords()[0]);
    REQUIRE(ns1 != nullptr);
    CHECK(ns1->name == "zone.test.");
    CHECK(ns1->type == RR::NS);
    CHECK(ns1->rrclass == RR::CLASSIN);
    CHECK(ns1->rdata == "ns1.zone.test.");
    
    RRNS* ns2 = dynamic_cast<RRNS*>(zones[0]->getAllRecords()[1]);
    REQUIRE(ns2 != nullptr);
    CHECK(ns2->rdata == "ns2.zone.test.");
    
    RRNS* ns3 = dynamic_cast<RRNS*>(zones[0]->getAllRecords()[2]);
    REQUIRE(ns3 != nullptr);
    CHECK(ns3->name == "sub.zone.test.");
    CHECK(ns3->rdata == "ns.sub.zone.test.");
}

TEST_CASE("RRNS: Unpack from network", "[rr][ns][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "sub"
    packet[0] = 3;
    memcpy(packet + 1, "sub", 3);
    packet[4] = 0;
    
    // Type: NS (2)
    *(uint16_t*)(packet + 5) = htons(2);
    
    // Class: IN
    *(uint16_t*)(packet + 7) = htons(1);
    
    // TTL: 86400
    *(uint32_t*)(packet + 9) = htonl(86400);
    
    // RDLEN: 5
    *(uint16_t*)(packet + 13) = htons(5);
    
    // RDATA: "ns" (DNS name)
    packet[15] = 2;
    memcpy(packet + 16, "ns", 2);
    packet[18] = 0;
    
    RRNS* rr = new RRNS();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "sub.");
    CHECK(rr->type == RR::NS);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 86400);
    CHECK(rr->rdata == "ns.");
    
    delete rr;
}

// ===== Test PTR Records =====

TEST_CASE("RRPTR: Parse from zone file", "[rr][ptr][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN 1.168.192.in-addr.arpa.");
    zoneData.push_back("1       IN  PTR     host1.example.com.");
    zoneData.push_back("10      IN  PTR     host10.example.com.");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 2);
    
    RRPTR* ptr = dynamic_cast<RRPTR*>(zones[0]->getAllRecords()[0]);
    REQUIRE(ptr != nullptr);
    CHECK(ptr->name == "1.1.168.192.in-addr.arpa.");
    CHECK(ptr->type == RR::PTR);
    CHECK(ptr->rrclass == RR::CLASSIN);
    CHECK(ptr->rdata == "host1.example.com.");
    
    RRPTR* ptr2 = dynamic_cast<RRPTR*>(zones[0]->getAllRecords()[1]);
    REQUIRE(ptr2 != nullptr);
    CHECK(ptr2->name == "10.1.168.192.in-addr.arpa.");
    CHECK(ptr2->rdata == "host10.example.com.");
}

TEST_CASE("RRPTR: Unpack from network", "[rr][ptr][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "1"
    packet[0] = 1;
    packet[1] = '1';
    packet[2] = 0;
    
    // Type: PTR (12)
    *(uint16_t*)(packet + 3) = htons(12);
    
    // Class: IN
    *(uint16_t*)(packet + 5) = htons(1);
    
    // TTL: 7200
    *(uint32_t*)(packet + 7) = htonl(7200);
    
    // RDLEN: 6
    *(uint16_t*)(packet + 11) = htons(6);
    
    // RDATA: "host"
    packet[13] = 4;
    memcpy(packet + 14, "host", 4);
    packet[18] = 0;
    
    RRPTR* rr = new RRPTR();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "1.");
    CHECK(rr->type == RR::PTR);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 7200);
    CHECK(rr->rdata == "host.");
    
    delete rr;
}

// ===== Test SOA Records =====

TEST_CASE("RRSoa: Parse from zone file", "[rr][soa][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN soa.test.");
    zoneData.push_back("soa.test.   IN  SOA     ns1.soa.test. admin.soa.test. 1 3600 900 604800 86400");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 1);
    
    RRSoa* soa = dynamic_cast<RRSoa*>(zones[0]->getAllRecords()[0]);
    REQUIRE(soa != nullptr);
    CHECK(soa->name == "soa.test.");
    CHECK(soa->type == RR::SOA);
    CHECK(soa->rrclass == RR::CLASSIN);
    CHECK(soa->ns == "ns1.soa.test.");
    CHECK(soa->mail == "admin.soa.test.");
    CHECK(soa->serial == 1);
    CHECK(soa->refresh == 3600);
    CHECK(soa->retry == 900);
    CHECK(soa->expire == 604800);
    CHECK(soa->minttl == 86400);
}

TEST_CASE("RRSoa: Unpack from network", "[rr][soa][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "zone"
    packet[0] = 4;
    memcpy(packet + 1, "zone", 4);
    packet[5] = 0;
    
    // Type: SOA (6)
    *(uint16_t*)(packet + 6) = htons(6);
    
    // Class: IN
    *(uint16_t*)(packet + 8) = htons(1);
    
    // TTL: 3600
    *(uint32_t*)(packet + 10) = htonl(3600);
    
    // RDLEN: 30 (approximate for minimal SOA)
    *(uint16_t*)(packet + 14) = htons(30);
    
    // RDATA: MNAME (ns) + RNAME (admin) + serial + refresh + retry + expire + minimum
    packet[16] = 2;
    memcpy(packet + 17, "ns", 2);
    packet[19] = 0;
    packet[20] = 5;
    memcpy(packet + 21, "admin", 5);
    packet[26] = 0;
    *(uint32_t*)(packet + 27) = htonl(1); // serial
    *(uint32_t*)(packet + 31) = htonl(3600); // refresh
    *(uint32_t*)(packet + 35) = htonl(900); // retry
    *(uint32_t*)(packet + 39) = htonl(604800); // expire
    *(uint32_t*)(packet + 43) = htonl(86400); // minimum
    
    RRSoa* rr = new RRSoa();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "zone.");
    CHECK(rr->type == RR::SOA);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 3600);
    CHECK(rr->ns == "ns.");
    CHECK(rr->mail == "admin.");
    CHECK(rr->serial == 1);
    CHECK(rr->refresh == 3600);
    CHECK(rr->retry == 900);
    CHECK(rr->expire == 604800);
    CHECK(rr->minttl == 86400);
    
    delete rr;
}

// ===== Test TXT Records =====

TEST_CASE("RRTXT: Parse from zone file", "[rr][txt][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN txt.test.");
    zoneData.push_back("info    IN  TXT     \"This is a test\"");
    zoneData.push_back("spf     IN  TXT     \"v=spf1 mx -all\"");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 2);
    
    RRTXT* txt = dynamic_cast<RRTXT*>(zones[0]->getAllRecords()[0]);
    REQUIRE(txt != nullptr);
    CHECK(txt->name == "info.txt.test.");
    CHECK(txt->type == RR::TXT);
    CHECK(txt->rrclass == RR::CLASSIN);
    CHECK(txt->rdata.length() > 0);
    
    RRTXT* txt2 = dynamic_cast<RRTXT*>(zones[0]->getAllRecords()[1]);
    REQUIRE(txt2 != nullptr);
    CHECK(txt2->name == "spf.txt.test.");
}

TEST_CASE("RRTXT: Unpack from network", "[rr][txt][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "txt"
    packet[0] = 3;
    memcpy(packet + 1, "txt", 3);
    packet[4] = 0;
    
    // Type: TXT (16)
    *(uint16_t*)(packet + 5) = htons(16);
    
    // Class: IN
    *(uint16_t*)(packet + 7) = htons(1);
    
    // TTL: 300
    *(uint32_t*)(packet + 9) = htonl(300);
    
    // RDLEN: 6
    *(uint16_t*)(packet + 13) = htons(6);
    
    // RDATA: length-prefixed string "hello"
    packet[15] = 5;
    memcpy(packet + 16, "hello", 5);
    
    RRTXT* rr = new RRTXT();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "txt.");
    CHECK(rr->type == RR::TXT);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 300);
    CHECK(rr->rdlen == 6);
    CHECK(rr->rdata.length() == 6);
    // TXT rdata is length-prefixed
    CHECK((unsigned char)rr->rdata[0] == 5);  // Length byte
    CHECK(rr->rdata.substr(1, 5) == "hello");
    
    delete rr;
}

// ===== Test DHCID Records =====

TEST_CASE("RRDHCID: Parse from zone file", "[rr][dhcid][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN dhcp.test.");
    zoneData.push_back("client1 IN  DHCID   AABBCCDDEEFF00112233445566778899");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 1);
    
    RRDHCID* dhcid = dynamic_cast<RRDHCID*>(zones[0]->getAllRecords()[0]);
    REQUIRE(dhcid != nullptr);
    CHECK(dhcid->name == "client1.dhcp.test.");
    CHECK(dhcid->type == RR::DHCID);
    CHECK(dhcid->rrclass == RR::CLASSIN);
    CHECK(dhcid->identifier.length() > 0);
    CHECK(dhcid->identifier == dhcid->rdata);
}

TEST_CASE("RRDHCID: Unpack from network", "[rr][dhcid][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "lease"
    packet[0] = 5;
    memcpy(packet + 1, "lease", 5);
    packet[6] = 0;
    
    // Type: DHCID (49)
    *(uint16_t*)(packet + 7) = htons(49);
    
    // Class: IN
    *(uint16_t*)(packet + 9) = htons(1);
    
    // TTL: 86400
    *(uint32_t*)(packet + 11) = htonl(86400);
    
    // RDLEN: 16
    *(uint16_t*)(packet + 15) = htons(16);
    
    // RDATA: 16 bytes of identifier
    const char* id = "0123456789ABCDEF";
    memcpy(packet + 17, id, 16);
    
    RRDHCID* rr = new RRDHCID();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "lease.");
    CHECK(rr->type == RR::DHCID);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 86400);
    CHECK(rr->rdlen == 16);
    CHECK(rr->identifier.length() == 16);
    CHECK(rr->identifier == rr->rdata);
    // Verify identifier content
    CHECK(rr->identifier == "0123456789ABCDEF");
    
    delete rr;
}

// ===== Test CERT Records =====

TEST_CASE("RRCERT: Parse from zone file", "[rr][cert][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN cert.test.");
    zoneData.push_back("secure  IN  CERT    AABBCCDD");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->getAllRecords().size() == 1);
    
    RRCERT* cert = dynamic_cast<RRCERT*>(zones[0]->getAllRecords()[0]);
    REQUIRE(cert != nullptr);
    CHECK(cert->name == "secure.cert.test.");
    CHECK(cert->type == RR::CERT);
    CHECK(cert->rrclass == RR::CLASSIN);
    CHECK(cert->rdata.length() > 0);
}

TEST_CASE("RRCERT: Unpack from network", "[rr][cert][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "key"
    packet[0] = 3;
    memcpy(packet + 1, "key", 3);
    packet[4] = 0;
    
    // Type: CERT (37)
    *(uint16_t*)(packet + 5) = htons(37);
    
    // Class: IN
    *(uint16_t*)(packet + 7) = htons(1);
    
    // TTL: 3600
    *(uint32_t*)(packet + 9) = htonl(3600);
    
    // RDLEN: 8
    *(uint16_t*)(packet + 13) = htons(8);
    
    // RDATA: cert data
    memcpy(packet + 15, "CERTDATA", 8);
    
    RRCERT* rr = new RRCERT();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "key.");
    CHECK(rr->type == RR::CERT);
    CHECK(rr->rrclass == RR::CLASSIN);
    CHECK(rr->ttl == 3600);
    CHECK(rr->rdlen == 8);
    CHECK(rr->rdata.length() == 8);
    CHECK(rr->rdata == "CERTDATA");
    
    delete rr;
}

// ===== Integration tests: multiple RR types in same zone =====

TEST_CASE("Zone file with multiple RR types", "[rr][integration][zonefile]")
{
    t_data zoneData;
    zoneData.push_back("$ORIGIN multi.test.");
    zoneData.push_back("multi.test. IN  SOA     ns1.multi.test. admin.multi.test. 1 3600 900 604800 86400");
    zoneData.push_back("multi.test. IN  NS      ns1.multi.test.");
    zoneData.push_back("multi.test. IN  NS      ns2.multi.test.");
    zoneData.push_back("multi.test. IN  MX      10 mail.multi.test.");
    zoneData.push_back("www         IN  A       192.168.1.1");
    zoneData.push_back("www         IN  AAAA    2001:0db8:0000:0000:0000:0000:0000:0001");
    zoneData.push_back("ftp         IN  CNAME   www.multi.test.");
    zoneData.push_back("multi.test. IN  TXT     \"v=spf1 mx -all\"");
    zoneData.push_back("mail        IN  A       192.168.1.10");
    zoneData.push_back("ns1         IN  A       192.168.1.2");
    zoneData.push_back("ns2         IN  A       192.168.1.3");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    Zone* zone = zones[0];
    
    // Count each type
    int soa_count = 0, ns_count = 0, mx_count = 0, a_count = 0, aaaa_count = 0, cname_count = 0, txt_count = 0;
    
    for (size_t i = 0; i < zone->getAllRecords().size(); ++i) {
        RR* rr = zone->getAllRecords()[i];
        switch (rr->type) {
            case RR::SOA: soa_count++; break;
            case RR::NS: ns_count++; break;
            case RR::MX: mx_count++; break;
            case RR::A: a_count++; break;
            case RR::AAAA: aaaa_count++; break;
            case RR::CNAME: cname_count++; break;
            case RR::TXT: txt_count++; break;
            default: break;
        }
    }
    
    CHECK(soa_count == 1);
    CHECK(ns_count == 2);
    CHECK(mx_count == 1);
    CHECK(a_count == 4);  // www, mail, ns1, ns2
    CHECK(aaaa_count == 1);
    CHECK(cname_count == 1);
    CHECK(txt_count == 1);
}

TEST_CASE("Network message with multiple RR types", "[rr][integration][network]")
{
    char packet[300];
    memset(packet, 0, sizeof(packet));
    
    unsigned int off = 0;
    
    // DNS Header
    *(uint16_t*)(packet + 0) = htons(0x1234);
    *(uint16_t*)(packet + 2) = htons(0x8180);  // Response
    *(uint16_t*)(packet + 4) = htons(1);       // 1 question
    *(uint16_t*)(packet + 6) = htons(3);       // 3 answers (A, AAAA, TXT)
    *(uint16_t*)(packet + 8) = htons(0);
    *(uint16_t*)(packet + 10) = htons(0);
    
    off = 12;
    
    // Question: www.test A IN
    packet[off++] = 3;
    memcpy(packet + off, "www", 3); off += 3;
    packet[off++] = 4;
    memcpy(packet + off, "test", 4); off += 4;
    packet[off++] = 0;
    *(uint16_t*)(packet + off) = htons(255); off += 2;  // ANY
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // IN
    
    unsigned int name_offset = 12;  // Offset of "www.test"
    
    // Answer 1: A record
    packet[off++] = 0xC0;  // Pointer
    packet[off++] = name_offset;
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // A
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // IN
    *(uint32_t*)(packet + off) = htonl(3600); off += 4; // TTL
    *(uint16_t*)(packet + off) = htons(4); off += 2;    // RDLEN
    packet[off++] = 192;
    packet[off++] = 168;
    packet[off++] = 1;
    packet[off++] = 1;
    
    // Answer 2: AAAA record
    packet[off++] = 0xC0;  // Pointer
    packet[off++] = name_offset;
    *(uint16_t*)(packet + off) = htons(28); off += 2;   // AAAA
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // IN
    *(uint32_t*)(packet + off) = htonl(3600); off += 4; // TTL
    *(uint16_t*)(packet + off) = htons(16); off += 2;   // RDLEN
    // IPv6 address (simplified)
    for (int i = 0; i < 16; i++) packet[off++] = (i == 15) ? 1 : 0;
    
    // Answer 3: TXT record
    packet[off++] = 0xC0;  // Pointer
    packet[off++] = name_offset;
    *(uint16_t*)(packet + off) = htons(16); off += 2;   // TXT
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // IN
    *(uint32_t*)(packet + off) = htonl(300); off += 4;  // TTL
    *(uint16_t*)(packet + off) = htons(6); off += 2;    // RDLEN
    packet[off++] = 5;
    memcpy(packet + off, "hello", 5); off += 5;
    
    Message msg;
    unsigned int offset = 0;
    bool result = msg.unpack(packet, off, offset);
    
    CHECK(result);
    CHECK(msg.qd.size() == 1);
    CHECK(msg.an.size() == 3);
    
    // Verify types
    CHECK(msg.an[0]->type == RR::A);
    CHECK(msg.an[0]->name == "www.test.");
    CHECK(msg.an[0]->rrclass == RR::CLASSIN);
    CHECK(msg.an[0]->ttl == 3600);
    
    CHECK(msg.an[1]->type == RR::AAAA);
    CHECK(msg.an[1]->name == "www.test.");
    CHECK(msg.an[1]->ttl == 3600);
    
    CHECK(msg.an[2]->type == RR::TXT);
    CHECK(msg.an[2]->name == "www.test.");
    CHECK(msg.an[2]->ttl == 300);
}
