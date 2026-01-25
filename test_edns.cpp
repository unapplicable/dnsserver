#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include <cstring>
#include <arpa/inet.h>
#include "message.h"
#include "rr.h"
#include "rropt.h"

// ===== Test RROPT Construction =====

TEST_CASE("RROPT: Default construction", "[rr][opt][edns]")
{
    RROPT opt;
    
    CHECK(opt.type == RR::OPT);
    CHECK(opt.name == ".");
    CHECK(opt.udp_payload_size == 4096);
    CHECK(opt.version == 0);
    CHECK(opt.extended_rcode == 0);
    CHECK(opt.flags == 0);
    CHECK(opt.getDO() == false);
    CHECK(opt.options.empty());
}

TEST_CASE("RROPT: Set DO flag", "[rr][opt][edns]")
{
    RROPT opt;
    
    opt.setDO(true);
    CHECK(opt.getDO() == true);
    CHECK((opt.flags & 0x8000) != 0);
    
    opt.setDO(false);
    CHECK(opt.getDO() == false);
    CHECK((opt.flags & 0x8000) == 0);
}

TEST_CASE("RROPT: Add EDNS options", "[rr][opt][edns]")
{
    RROPT opt;
    
    opt.addOption(1, "test");
    opt.addOption(2, "data");
    
    CHECK(opt.options.size() == 2);
    CHECK(opt.options[0].code == 1);
    CHECK(opt.options[0].data == "test");
    CHECK(opt.options[1].code == 2);
    CHECK(opt.options[1].data == "data");
}

// ===== Test RROPT Network Packing/Unpacking =====

TEST_CASE("RROPT: Unpack from network (basic)", "[rr][opt][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: root "."
    packet[0] = 0;
    
    // Type: OPT (41)
    *(uint16_t*)(packet + 1) = htons(41);
    
    // CLASS: UDP payload size (1232)
    *(uint16_t*)(packet + 3) = htons(1232);
    
    // TTL: extended_rcode (0) | version (0) | flags (0x8000 = DO bit)
    *(uint32_t*)(packet + 5) = htonl(0x00008000);
    
    // RDLEN: 0 (no options)
    *(uint16_t*)(packet + 9) = htons(0);
    
    RROPT* opt = new RROPT();
    bool result = opt->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK((opt->name == "" || opt->name == "."));  // Root is stored as empty or "."
    CHECK(opt->type == RR::OPT);
    CHECK(opt->udp_payload_size == 1232);
    CHECK(opt->version == 0);
    CHECK(opt->extended_rcode == 0);
    CHECK(opt->flags == 0x8000);
    CHECK(opt->getDO() == true);
    CHECK(opt->rdlen == 0);
    CHECK(opt->options.empty());
    
    delete opt;
}

TEST_CASE("RROPT: Unpack from network (with options)", "[rr][opt][network]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: root "."
    packet[0] = 0;
    
    // Type: OPT (41)
    *(uint16_t*)(packet + 1) = htons(41);
    
    // CLASS: UDP payload size (4096)
    *(uint16_t*)(packet + 3) = htons(4096);
    
    // TTL: extended_rcode (0) | version (0) | flags (0)
    *(uint32_t*)(packet + 5) = htonl(0);
    
    // RDLEN: 12 (two options: 4+4+4 = 12 bytes)
    *(uint16_t*)(packet + 9) = htons(12);
    
    // Option 1: code=3, length=2, data="AB"
    *(uint16_t*)(packet + 11) = htons(3);
    *(uint16_t*)(packet + 13) = htons(2);
    packet[15] = 'A';
    packet[16] = 'B';
    
    // Option 2: code=10, length=2, data="XY"
    *(uint16_t*)(packet + 17) = htons(10);
    *(uint16_t*)(packet + 19) = htons(2);
    packet[21] = 'X';
    packet[22] = 'Y';
    
    RROPT* opt = new RROPT();
    bool result = opt->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(opt->udp_payload_size == 4096);
    CHECK(opt->options.size() == 2);
    CHECK(opt->options[0].code == 3);
    CHECK(opt->options[0].data == "AB");
    CHECK(opt->options[1].code == 10);
    CHECK(opt->options[1].data == "XY");
    
    delete opt;
}

TEST_CASE("RROPT: Pack to network (basic)", "[rr][opt][network]")
{
    RROPT opt;
    opt.udp_payload_size = 512;
    opt.version = 0;
    opt.extended_rcode = 0;
    opt.setDO(true);
    opt.syncFields();
    
    char packet[100];
    memset(packet, 0, sizeof(packet));
    unsigned int offset = 0;
    
    opt.pack(packet, sizeof(packet), offset);
    
    // Verify packed data
    CHECK(packet[0] == 0);  // Root name
    CHECK(ntohs(*(uint16_t*)(packet + 1)) == 41);  // Type OPT
    CHECK(ntohs(*(uint16_t*)(packet + 3)) == 512);  // UDP size in CLASS field
    
    uint32_t ttl = ntohl(*(uint32_t*)(packet + 5));
    CHECK((ttl & 0xFFFF) == 0x8000);  // DO flag set
    CHECK(((ttl >> 16) & 0xFF) == 0);  // Version 0
    CHECK(((ttl >> 24) & 0xFF) == 0);  // Extended RCODE 0
    
    CHECK(ntohs(*(uint16_t*)(packet + 9)) == 0);  // RDLEN 0
    CHECK(offset == 11);  // Total packed size
}

TEST_CASE("RROPT: Pack to network (with options)", "[rr][opt][network]")
{
    RROPT opt;
    opt.udp_payload_size = 4096;
    opt.version = 0;
    opt.extended_rcode = 0;
    opt.flags = 0;
    opt.addOption(5, "TEST");
    opt.syncFields();
    
    char packet[100];
    memset(packet, 0, sizeof(packet));
    unsigned int offset = 0;
    
    opt.pack(packet, sizeof(packet), offset);
    
    // Verify header
    CHECK(ntohs(*(uint16_t*)(packet + 1)) == 41);  // Type OPT
    CHECK(ntohs(*(uint16_t*)(packet + 3)) == 4096);  // UDP size
    
    // Verify RDLEN (4 bytes header + 4 bytes data = 8)
    uint16_t rdlen = ntohs(*(uint16_t*)(packet + 9));
    CHECK(rdlen == 8);
    
    // Verify option
    CHECK(ntohs(*(uint16_t*)(packet + 11)) == 5);  // Option code
    CHECK(ntohs(*(uint16_t*)(packet + 13)) == 4);  // Option length
    CHECK(memcmp(packet + 15, "TEST", 4) == 0);  // Option data
}

TEST_CASE("RROPT: Roundtrip pack/unpack", "[rr][opt][network]")
{
    RROPT opt1;
    opt1.udp_payload_size = 1232;
    opt1.version = 0;
    opt1.extended_rcode = 0;
    opt1.setDO(true);
    opt1.addOption(8, "COOKIE");
    opt1.addOption(15, "ECS");
    opt1.syncFields();
    
    // Pack
    char packet[100];
    memset(packet, 0, sizeof(packet));
    unsigned int offset = 0;
    opt1.pack(packet, sizeof(packet), offset);
    
    // Unpack
    RROPT opt2;
    unsigned int offset2 = 0;
    bool result = opt2.unpack(packet, offset, offset2, false);
    
    CHECK(result);
    CHECK(opt2.udp_payload_size == opt1.udp_payload_size);
    CHECK(opt2.version == opt1.version);
    CHECK(opt2.extended_rcode == opt1.extended_rcode);
    CHECK(opt2.getDO() == opt1.getDO());
    CHECK(opt2.options.size() == opt1.options.size());
    CHECK(opt2.options[0].code == opt1.options[0].code);
    CHECK(opt2.options[0].data == opt1.options[0].data);
    CHECK(opt2.options[1].code == opt1.options[1].code);
    CHECK(opt2.options[1].data == opt1.options[1].data);
}

// ===== Test RROPT in Message Context =====

TEST_CASE("Message: Extract OPT from additional section", "[message][opt][edns]")
{
    Message msg;
    
    // Add some regular RRs
    RR* a_rr = RR::createByType(RR::A);
    a_rr->name = "test.example.com.";
    msg.an.push_back(a_rr);
    
    // Add OPT record
    RROPT* opt = new RROPT();
    opt->udp_payload_size = 1232;
    opt->setDO(true);
    opt->syncFields();
    msg.ar.push_back(opt);
    
    // Test getOPT
    RR* found = msg.getOPT();
    REQUIRE(found != NULL);
    CHECK(found->type == RR::OPT);
    
    RROPT* found_opt = dynamic_cast<RROPT*>(found);
    REQUIRE(found_opt != NULL);
    CHECK(found_opt->udp_payload_size == 1232);
    CHECK(found_opt->getDO() == true);
}

TEST_CASE("Message: copyEDNS from request to response", "[message][opt][edns]")
{
    // Create request with EDNS
    Message request;
    RROPT* req_opt = new RROPT();
    req_opt->udp_payload_size = 1232;
    req_opt->setDO(true);
    req_opt->syncFields();
    request.ar.push_back(req_opt);
    
    // Create response
    Message response;
    response.copyEDNS(&request);
    
    // Verify response has EDNS
    RR* resp_opt_rr = response.getOPT();
    REQUIRE(resp_opt_rr != NULL);
    
    RROPT* resp_opt = dynamic_cast<RROPT*>(resp_opt_rr);
    REQUIRE(resp_opt != NULL);
    CHECK(resp_opt->udp_payload_size == 1232);  // Should match request
    CHECK(resp_opt->version == 0);
}

TEST_CASE("Message: copyEDNS limits UDP size", "[message][opt][edns]")
{
    // Create request with large UDP size
    Message request;
    RROPT* req_opt = new RROPT();
    req_opt->udp_payload_size = 8192;  // Larger than our max
    req_opt->syncFields();
    request.ar.push_back(req_opt);
    
    // Create response
    Message response;
    response.copyEDNS(&request);
    
    // Verify response caps at 4096
    RR* resp_opt_rr = response.getOPT();
    REQUIRE(resp_opt_rr != NULL);
    
    RROPT* resp_opt = dynamic_cast<RROPT*>(resp_opt_rr);
    REQUIRE(resp_opt != NULL);
    CHECK(resp_opt->udp_payload_size == 4096);  // Capped at our max
}

TEST_CASE("Message: No EDNS in request means no EDNS in response", "[message][opt][edns]")
{
    // Create request without EDNS
    Message request;
    
    // Create response
    Message response;
    response.copyEDNS(&request);
    
    // Verify response has no EDNS
    RR* resp_opt_rr = response.getOPT();
    CHECK(resp_opt_rr == NULL);
}

TEST_CASE("RROPT: dumpContents output", "[rr][opt][display]")
{
    RROPT opt;
    opt.udp_payload_size = 1232;
    opt.version = 0;
    opt.extended_rcode = 0;
    opt.setDO(true);
    opt.addOption(8, "TEST");
    opt.syncFields();
    
    std::ostringstream oss;
    opt.dumpContents(oss);
    std::string output = oss.str();
    
    CHECK(output.find("version=0") != std::string::npos);
    CHECK(output.find("udp=1232") != std::string::npos);
    CHECK(output.find("do") != std::string::npos);
    CHECK(output.find("options=1") != std::string::npos);
}
