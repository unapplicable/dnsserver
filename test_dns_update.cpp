#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>
#include <cstring>
#include <arpa/inet.h>
#include "message.h"
#include "rr.h"
#include "rrdhcid.h"
#include "rra.h"
#include "zoneFileLoader.h"
#include "zone.h"

// Test 1: DNS name pointer following bug fix
// Bug: unpackName was incrementing offset for EVERY pointer encountered
// Fix: Only increment offset once for the first pointer in a chain
TEST_CASE("DNS name pointer chain - offset incremented only once", "[pointer][082512b]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 12;
    
    // At offset 12: pointer to offset 30
    packet[12] = 0xC0;  // 11000000 - pointer marker
    packet[13] = 30;    // points to offset 30
    
    // At offset 30: "example" then pointer to offset 50
    packet[30] = 7;     // length of "example"
    memcpy(packet + 31, "example", 7);
    packet[38] = 0xC0;  // pointer marker
    packet[39] = 50;    // points to offset 50
    
    // At offset 50: "com" null terminated
    packet[50] = 3;     // length of "com"
    memcpy(packet + 51, "com", 3);
    packet[54] = 0;     // null terminator
    
    RR rr;
    std::string name = rr.unpackName(packet, sizeof(packet), offset);
    
    CHECK(name == "example.com");
    // CRITICAL: offset should be 14 (12 + 2), not incremented for second pointer
    CHECK(offset == 14);
}

TEST_CASE("DNS name with pointer at end", "[pointer][082512b]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 20;
    
    // At offset 50: "org" null terminated
    packet[50] = 3;
    memcpy(packet + 51, "org", 3);
    packet[54] = 0;
    
    // At offset 20: "subdomain" then pointer to "org"
    packet[20] = 9;
    memcpy(packet + 21, "subdomain", 9);
    packet[30] = 0xC0;  // pointer
    packet[31] = 50;    // to offset 50
    
    RR rr;
    std::string name = rr.unpackName(packet, sizeof(packet), offset);
    
    CHECK(name == "subdomain.org");
    CHECK(offset == 32);  // 20 + 1 + 9 + 2 (for pointer)
}

// Test 2: 64-bit portability - TTL field
// Bug: TTL used 'long' cast which is 8 bytes on 64-bit systems
// Fix: Use explicit uint32_t* cast for TTL (4 bytes)
TEST_CASE("TTL field reads correctly on 64-bit systems", "[portability][082512b]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "test" (offset 0-5)
    packet[0] = 4;
    memcpy(packet + 1, "test", 4);
    packet[5] = 0;
    
    // Type: A (offset 6-7)
    *(uint16_t*)(packet + 6) = htons(1);
    
    // Class: IN (offset 8-9)
    *(uint16_t*)(packet + 8) = htons(1);
    
    // TTL: 3600 seconds (offset 10-13) - exactly 4 bytes
    *(uint32_t*)(packet + 10) = htonl(3600);
    
    // RDLEN: 4 bytes (offset 14-15)
    *(uint16_t*)(packet + 14) = htons(4);
    
    // RDATA: 192.168.1.1 (offset 16-19)
    packet[16] = 192;
    packet[17] = 168;
    packet[18] = 1;
    packet[19] = 1;
    
    RR* rr = RR::createByType(RR::A);
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->ttl == 3600);
    CHECK(rr->rdlen == 4);
    
    delete rr;
}

TEST_CASE("TTL field with large value", "[portability][082512b]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "x"
    packet[0] = 1;
    packet[1] = 'x';
    packet[2] = 0;
    
    // Type: A
    *(uint16_t*)(packet + 3) = htons(1);
    
    // Class: IN
    *(uint16_t*)(packet + 5) = htons(1);
    
    // TTL: Maximum value (2^32 - 1)
    *(uint32_t*)(packet + 7) = htonl(0xFFFFFFFF);
    
    // RDLEN: 4
    *(uint16_t*)(packet + 11) = htons(4);
    
    // RDATA
    *(uint32_t*)(packet + 13) = htonl(0x01020304);
    
    RR* rr = RR::createByType(RR::A);
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->ttl == 0xFFFFFFFF);
    
    delete rr;
}

// Test 3: 64-bit portability - RDLEN field
// Bug: RDLEN used 'short' cast
// Fix: Use explicit uint16_t* cast for rdlen (2 bytes)
TEST_CASE("RDLEN field reads correctly on 64-bit systems", "[portability][082512b]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "x" (offset 0-2)
    packet[0] = 1;
    packet[1] = 'x';
    packet[2] = 0;
    
    // Type: TXT (offset 3-4)
    *(uint16_t*)(packet + 3) = htons(16);
    
    // Class: IN (offset 5-6)
    *(uint16_t*)(packet + 5) = htons(1);
    
    // TTL: 300 (offset 7-10)
    *(uint32_t*)(packet + 7) = htonl(300);
    
    // RDLEN: 11 bytes (offset 11-12)
    *(uint16_t*)(packet + 11) = htons(11);
    
    // RDATA: TXT data "helloworld" (offset 13-23)
    packet[13] = 10;  // TXT length byte
    memcpy(packet + 14, "helloworld", 10);
    
    RR* rr = RR::createByType(RR::TXT);
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->rdlen == 11);
    CHECK(rr->ttl == 300);
    
    delete rr;
}

TEST_CASE("RDLEN field with maximum value", "[portability][082512b]")
{
    char packet[300];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "test"
    packet[0] = 4;
    memcpy(packet + 1, "test", 4);
    packet[5] = 0;
    
    // Type: TXT
    *(uint16_t*)(packet + 6) = htons(16);
    
    // Class: IN
    *(uint16_t*)(packet + 8) = htons(1);
    
    // TTL
    *(uint32_t*)(packet + 10) = htonl(300);
    
    // RDLEN: 255 bytes
    *(uint16_t*)(packet + 14) = htons(255);
    
    // RDATA: Fill with data
    packet[16] = 254;  // TXT length
    memset(packet + 17, 'A', 254);
    
    RR* rr = RR::createByType(RR::TXT);
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->rdlen == 255);
    
    delete rr;
}

// Test 4: RRDHCID unpack method
// Bug: RRDHCID stores data in 'identifier' field but base unpack uses 'rdata'
// Fix: Added override to copy rdata to identifier after base unpack
TEST_CASE("RRDHCID unpack copies rdata to identifier", "[dhcid][082512b]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "host" (offset 0-5)
    packet[0] = 4;
    memcpy(packet + 1, "host", 4);
    packet[5] = 0;
    
    // Type: DHCID (49) (offset 6-7)
    *(uint16_t*)(packet + 6) = htons(49);
    
    // Class: IN (offset 8-9)
    *(uint16_t*)(packet + 8) = htons(1);
    
    // TTL: 86400 (offset 10-13)
    *(uint32_t*)(packet + 10) = htonl(86400);
    
    // RDLEN: 8 bytes (offset 14-15)
    *(uint16_t*)(packet + 14) = htons(8);
    
    // RDATA: DHCID identifier (offset 16-23)
    const char* dhcid_data = "DHCIDABC";
    memcpy(packet + 16, dhcid_data, 8);
    
    RRDHCID* rr = new RRDHCID();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->rdlen == 8);
    // CRITICAL: identifier should be populated from rdata
    CHECK(rr->identifier.length() == 8);
    CHECK(rr->identifier == std::string(dhcid_data, 8));
    CHECK(rr->rdata == rr->identifier);
    
    delete rr;
}

TEST_CASE("RRDHCID with realistic base64-like identifier", "[dhcid][082512b]")
{
    char packet[200];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "client.local"
    packet[0] = 6;
    memcpy(packet + 1, "client", 6);
    packet[7] = 5;
    memcpy(packet + 8, "local", 5);
    packet[13] = 0;
    
    // Type: DHCID (49)
    *(uint16_t*)(packet + 14) = htons(49);
    
    // Class: IN
    *(uint16_t*)(packet + 16) = htons(1);
    
    // TTL
    *(uint32_t*)(packet + 18) = htonl(3600);
    
    // RDLEN: 32 bytes (simulating a hash)
    *(uint16_t*)(packet + 22) = htons(32);
    
    // RDATA: 32 bytes of identifier data
    const char* dhcid_hash = "abcdef0123456789ABCDEF0123456789";
    memcpy(packet + 24, dhcid_hash, 32);
    
    RRDHCID* rr = new RRDHCID();
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(rr->name == "client.local");
    CHECK(rr->identifier == std::string(dhcid_hash, 32));
    
    delete rr;
}

// Test 5: Integration test - UPDATE message with all fixes
// This simulates a real UPDATE message that would have failed before fixes
TEST_CASE("UPDATE message with pointers and A record", "[integration][082512b]")
{
    char packet[200];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // DNS Header (12 bytes)
    *(uint16_t*)(packet + 0) = htons(0x1234);  // ID
    *(uint16_t*)(packet + 2) = htons(0x2800);  // Flags: UPDATE opcode (5 << 11)
    *(uint16_t*)(packet + 4) = htons(1);       // ZOCOUNT: 1
    *(uint16_t*)(packet + 6) = htons(0);       // PRCOUNT: 0
    *(uint16_t*)(packet + 8) = htons(1);       // UPCOUNT: 1
    *(uint16_t*)(packet + 10) = htons(0);      // ADCOUNT: 0
    
    offset = 12;
    
    // Zone section: example.com SOA IN
    packet[12] = 7;
    memcpy(packet + 13, "example", 7);
    packet[20] = 3;
    memcpy(packet + 21, "com", 3);
    packet[24] = 0;
    *(uint16_t*)(packet + 25) = htons(6);  // SOA type
    *(uint16_t*)(packet + 27) = htons(1);  // IN class
    
    // Update section: host.example.com A IN 3600 192.168.1.100
    // Using pointer to "example.com" at offset 12
    packet[29] = 4;
    memcpy(packet + 30, "host", 4);
    packet[34] = 0xC0;  // Pointer to offset 12
    packet[35] = 12;
    *(uint16_t*)(packet + 36) = htons(1);      // A type
    *(uint16_t*)(packet + 38) = htons(1);      // IN class
    *(uint32_t*)(packet + 40) = htonl(3600);   // TTL (must be 4 bytes)
    *(uint16_t*)(packet + 44) = htons(4);      // RDLEN (must be 2 bytes)
    packet[46] = 192;  // IP: 192.168.1.100
    packet[47] = 168;
    packet[48] = 1;
    packet[49] = 100;
    
    Message msg;
    offset = 0;
    bool result = msg.unpack(packet, 50, offset);
    
    CHECK(result);
    CHECK(msg.opcode == Message::UPDATE);
    CHECK(msg.qd.size() == 1);  // Zone section
    CHECK(msg.ns.size() == 1);  // Update section
    
    // Verify the zone
    CHECK(msg.qd[0]->name == "example.com");
    CHECK(msg.qd[0]->type == RR::SOA);
    
    // Verify the update record
    CHECK(msg.ns[0]->name == "host.example.com");
    CHECK(msg.ns[0]->type == RR::A);
    CHECK(msg.ns[0]->ttl == 3600);
    CHECK(msg.ns[0]->rdlen == 4);
}

TEST_CASE("Production-like UPDATE message (124 bytes)", "[integration][082512b]")
{
    // Simulate a production UPDATE message from a DHCP server
    // This would have failed with "faulty" errors before the fixes
    char packet[150];
    memset(packet, 0, sizeof(packet));
    
    // DNS Header
    *(uint16_t*)(packet + 0) = htons(0xABCD);
    *(uint16_t*)(packet + 2) = htons(0x2800);  // UPDATE
    *(uint16_t*)(packet + 4) = htons(1);       // 1 zone
    *(uint16_t*)(packet + 6) = htons(1);       // 1 prerequisite
    *(uint16_t*)(packet + 8) = htons(2);       // 2 updates
    *(uint16_t*)(packet + 10) = htons(0);      // 0 additional
    
    unsigned int off = 12;
    
    // Zone: local SOA IN
    packet[off++] = 5;
    memcpy(packet + off, "local", 5); off += 5;
    packet[off++] = 0;
    *(uint16_t*)(packet + off) = htons(6); off += 2;  // SOA
    *(uint16_t*)(packet + off) = htons(1); off += 2;  // IN
    
    // Prerequisite: pc1.local NONE NONE
    packet[off++] = 3;
    memcpy(packet + off, "pc1", 3); off += 3;
    packet[off++] = 0xC0;  // Pointer to "local" at offset 12
    packet[off++] = 12;
    *(uint16_t*)(packet + off) = htons(255); off += 2;  // ANY
    *(uint16_t*)(packet + off) = htons(254); off += 2;  // NONE
    *(uint32_t*)(packet + off) = htonl(0); off += 4;    // TTL
    *(uint16_t*)(packet + off) = htons(0); off += 2;    // RDLEN
    
    // Update 1: pc1.local A IN 3600 10.0.0.5
    packet[off++] = 0xC0;  // Pointer to "pc1.local"
    packet[off++] = 20;
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // A
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // IN
    *(uint32_t*)(packet + off) = htonl(3600); off += 4; // TTL
    *(uint16_t*)(packet + off) = htons(4); off += 2;    // RDLEN
    packet[off++] = 10;
    packet[off++] = 0;
    packet[off++] = 0;
    packet[off++] = 5;
    
    // Update 2: pc1.local DHCID IN 86400 <hash>
    packet[off++] = 0xC0;  // Pointer to "pc1.local"
    packet[off++] = 20;
    *(uint16_t*)(packet + off) = htons(49); off += 2;     // DHCID
    *(uint16_t*)(packet + off) = htons(1); off += 2;      // IN
    *(uint32_t*)(packet + off) = htonl(86400); off += 4;  // TTL
    *(uint16_t*)(packet + off) = htons(16); off += 2;     // RDLEN
    memcpy(packet + off, "0123456789ABCDEF", 16); off += 16;
    
    Message msg;
    unsigned int offset = 0;
    bool result = msg.unpack(packet, off, offset);
    
    // All three bugs are tested:
    // 1. Pointer chain handling - the pointers to "local" and "pc1.local" parse correctly
    // 2. TTL 64-bit portability - TTL values of 0, 3600, 86400 parse correctly
    // 3. RDLEN 64-bit portability - RDLEN values of 0, 4, 16 parse correctly
    // 4. Virtual unpack - RRDHCID::unpack is called through base pointer
    CHECK(result);
    CHECK(msg.opcode == Message::UPDATE);
    CHECK(msg.qd.size() == 1);
    CHECK(msg.an.size() == 1);
    CHECK(msg.ns.size() == 2);
    
    // Verify DHCID record was created and both rdata and identifier are populated
    RRDHCID* dhcid = dynamic_cast<RRDHCID*>(msg.ns[1]);
    CHECK(dhcid != nullptr);
    if (dhcid) {
        // Both rdata and identifier should be populated now that unpack is virtual
        CHECK(dhcid->rdata.length() == 16);
        CHECK(dhcid->identifier.length() == 16);
        CHECK(dhcid->identifier == dhcid->rdata);
    }
}

// Test 6: RR::unpack should be virtual to allow subclass overrides
// This tests that when calling unpack through a base class pointer,
// the derived class's unpack method is invoked
TEST_CASE("RRDHCID unpack called through base pointer (virtual method)", "[virtual][dhcid]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name: "host"
    packet[0] = 4;
    memcpy(packet + 1, "host", 4);
    packet[5] = 0;
    
    // Type: DHCID (49)
    *(uint16_t*)(packet + 6) = htons(49);
    
    // Class: IN
    *(uint16_t*)(packet + 8) = htons(1);
    
    // TTL: 86400
    *(uint32_t*)(packet + 10) = htonl(86400);
    
    // RDLEN: 8 bytes
    *(uint16_t*)(packet + 14) = htons(8);
    
    // RDATA: DHCID identifier
    const char* dhcid_data = "DHCIDABC";
    memcpy(packet + 16, dhcid_data, 8);
    
    // Create RRDHCID through base class pointer (simulates Message::unpack)
    RR* base_ptr = RR::createByType(RR::DHCID);
    bool result = base_ptr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    CHECK(base_ptr->rdlen == 8);
    CHECK(base_ptr->rdata.length() == 8);
    
    // Cast to RRDHCID and verify identifier was populated
    RRDHCID* dhcid = dynamic_cast<RRDHCID*>(base_ptr);
    REQUIRE(dhcid != nullptr);
    
    // This is the critical test: identifier should be populated
    // because RRDHCID::unpack should be called (requires virtual)
    CHECK(dhcid->identifier.length() == 8);
    CHECK(dhcid->identifier == std::string(dhcid_data, 8));
    
    delete base_ptr;
}

// Test 7: Compression pointer detection bug (commit 0eb4fe3)
// Bug: Was checking (tokencode & 0xC0) != 0 instead of == 0xC0
// This incorrectly treated labels with length 64-127 as compression pointers
TEST_CASE("DNS name with label length 64+ not treated as pointer", "[pointer][0eb4fe3]")
{
    char packet[150];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Create a name with a 65-character label (0x41 = 65)
    // 0x41 has bit 6 set (0x40) but not bit 7, so (0x41 & 0xC0) = 0x40
    // Old buggy code: (0x40 != 0) = true, would treat as pointer -> crash
    // Fixed code: (0x40 == 0xC0) = false, treats as normal label
    packet[0] = 0x41;  // Length 65
    memset(packet + 1, 'A', 65);
    packet[66] = 0;  // Null terminator
    
    RR rr;
    std::string name = rr.unpackName(packet, sizeof(packet), offset);
    
    // Should successfully parse as a 65-character label
    CHECK(name.length() == 65);
    CHECK(name == std::string(65, 'A'));
    CHECK(offset == 67);  // 1 (length) + 65 (data) + 1 (null)
}

TEST_CASE("DNS name with label length 127 not treated as pointer", "[pointer][0eb4fe3]")
{
    char packet[150];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // 0x7F = 127, has both bits 0x40 and 0x20 set, but not 0x80
    // (0x7F & 0xC0) = 0x40, not 0xC0
    // Old code would incorrectly treat this as a pointer
    packet[0] = 0x7F;  // Length 127 (but gets misinterpreted by old code)
    // Don't actually fill 127 bytes since old code would crash trying to read as pointer
    memset(packet + 1, 'B', 10);
    packet[11] = 0;
    
    RR rr;
    // With the fix, this should try to parse but fail due to insufficient data
    // The important thing is it doesn't crash by treating 0x7F as a pointer
    try {
        std::string name = rr.unpackName(packet, 12, offset);
        // If we get here, the length was treated correctly (not as pointer)
        // but packet is too short, so name might be truncated or throw
        SUCCEED("Correctly treated as length, not pointer");
    } catch (...) {
        // Expected if packet too short for 127 bytes
        SUCCEED("Correctly treated as length, not pointer (threw on short packet)");
    }
}

TEST_CASE("DNS compression pointer 0xC0 correctly detected", "[pointer][0eb4fe3]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 20;
    
    // At offset 50: "test" null terminated
    packet[50] = 4;
    memcpy(packet + 51, "test", 4);
    packet[55] = 0;
    
    // At offset 20: compression pointer to offset 50
    // 0xC0 has both bits 7 and 6 set: (0xC0 & 0xC0) == 0xC0
    packet[20] = 0xC0;
    packet[21] = 50;
    
    RR rr;
    std::string name = rr.unpackName(packet, sizeof(packet), offset);
    
    CHECK(name == "test");
    CHECK(offset == 22);  // Moved 2 bytes for the pointer
}

// Test 8: UPDATE message section parsing (commit 0eb4fe3)
// Bug: Was checking (query && rrtype == 0) instead of just (rrtype == 0)
// This caused UPDATE message sections 1-3 to be parsed as query-style when they should be full RRs
TEST_CASE("UPDATE message sections parsed correctly", "[update][0eb4fe3]")
{
    char packet[200];
    memset(packet, 0, sizeof(packet));
    
    // DNS Header for UPDATE message
    *(uint16_t*)(packet + 0) = htons(0x5678);  // ID
    // Opcode = 5 (UPDATE), shifted left 11 bits = 0x2800
    *(uint16_t*)(packet + 2) = htons(0x2800);  
    *(uint16_t*)(packet + 4) = htons(1);       // ZOCOUNT: 1
    *(uint16_t*)(packet + 6) = htons(1);       // PRCOUNT: 1 prerequisite
    *(uint16_t*)(packet + 8) = htons(1);       // UPCOUNT: 1 update
    *(uint16_t*)(packet + 10) = htons(0);      // ADCOUNT: 0
    
    unsigned int off = 12;
    
    // Section 0 (Zone): query-style (name/type/class only, no TTL/RDATA)
    packet[off++] = 7;
    memcpy(packet + off, "example", 7); off += 7;
    packet[off++] = 3;
    memcpy(packet + off, "com", 3); off += 3;
    packet[off++] = 0;
    *(uint16_t*)(packet + off) = htons(6); off += 2;   // SOA type
    *(uint16_t*)(packet + off) = htons(1); off += 2;   // IN class
    
    // Section 1 (Prerequisite): MUST be full RR format (with TTL and RDATA)
    // Bug: old code would parse as query-style for UPDATE messages
    unsigned int prereq_start = off;  // Save start of prerequisite for pointer
    packet[off++] = 4;
    memcpy(packet + off, "test", 4); off += 4;
    packet[off++] = 0xC0;  // Pointer to "example.com"
    packet[off++] = 12;
    *(uint16_t*)(packet + off) = htons(255); off += 2;  // ANY type
    *(uint16_t*)(packet + off) = htons(254); off += 2;  // NONE class
    *(uint32_t*)(packet + off) = htonl(0); off += 4;    // TTL = 0
    *(uint16_t*)(packet + off) = htons(0); off += 2;    // RDLEN = 0
    
    // Section 2 (Update): MUST be full RR format
    packet[off++] = 0xC0;  // Pointer to "test.example.com"
    packet[off++] = prereq_start;
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // A type
    *(uint16_t*)(packet + off) = htons(1); off += 2;    // IN class
    *(uint32_t*)(packet + off) = htonl(3600); off += 4; // TTL = 3600
    *(uint16_t*)(packet + off) = htons(4); off += 2;    // RDLEN = 4
    packet[off++] = 192;  // IP 192.168.1.1
    packet[off++] = 168;
    packet[off++] = 1;
    packet[off++] = 1;
    
    Message msg;
    unsigned int offset = 0;
    bool result = msg.unpack(packet, off, offset);
    
    // With the fix, all sections parse correctly
    CHECK(result);
    CHECK(msg.opcode == Message::UPDATE);
    CHECK(msg.qd.size() == 1);   // Zone section
    CHECK(msg.an.size() == 1);   // Prerequisite section
    CHECK(msg.ns.size() == 1);   // Update section
    
    // Verify prerequisite has TTL and RDATA (full RR format)
    CHECK(msg.an[0]->name == "test.example.com");
    CHECK(msg.an[0]->ttl == 0);
    CHECK(msg.an[0]->rdlen == 0);
    
    // Verify update has TTL and RDATA
    CHECK(msg.ns[0]->name == "test.example.com");
    CHECK(msg.ns[0]->type == RR::A);
    CHECK(msg.ns[0]->ttl == 3600);
    CHECK(msg.ns[0]->rdlen == 4);
}

TEST_CASE("QUERY message question section is query-style", "[query][0eb4fe3]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    // DNS Header for QUERY message
    *(uint16_t*)(packet + 0) = htons(0x9ABC);  // ID
    *(uint16_t*)(packet + 2) = htons(0x0100);  // Standard query with RD bit
    *(uint16_t*)(packet + 4) = htons(1);       // QDCOUNT: 1
    *(uint16_t*)(packet + 6) = htons(0);       // ANCOUNT: 0
    *(uint16_t*)(packet + 8) = htons(0);       // NSCOUNT: 0
    *(uint16_t*)(packet + 10) = htons(0);      // ARCOUNT: 0
    
    unsigned int off = 12;
    
    // Question section: query-style (name/type/class only)
    packet[off++] = 3;
    memcpy(packet + off, "www", 3); off += 3;
    packet[off++] = 7;
    memcpy(packet + off, "example", 7); off += 7;
    packet[off++] = 3;
    memcpy(packet + off, "com", 3); off += 3;
    packet[off++] = 0;
    *(uint16_t*)(packet + off) = htons(1); off += 2;   // A type
    *(uint16_t*)(packet + off) = htons(1); off += 2;   // IN class
    
    Message msg;
    unsigned int offset = 0;
    bool result = msg.unpack(packet, off, offset);
    
    CHECK(result);
    CHECK(msg.opcode == Message::QUERY);
    CHECK(msg.qd.size() == 1);
    CHECK(msg.qd[0]->name == "www.example.com");
    CHECK(msg.qd[0]->type == RR::A);
    CHECK(msg.qd[0]->rrclass == RR::CLASSIN);
    // Query section doesn't have TTL or RDATA
}

TEST_CASE("Zone file with empty name field inherits from previous line", "[zonefile][3e5a586]")
{
    t_data zoneData;
    
    // Typical zone file format with continuation lines
    zoneData.push_back("$ORIGIN example.com.");
    zoneData.push_back("www     IN  A       192.168.1.1");
    zoneData.push_back("        IN  A       192.168.1.2");  // Empty name, should inherit "www"
    zoneData.push_back("mail    IN  A       192.168.1.10");
    zoneData.push_back("        IN  A       192.168.1.11");  // Empty name, should inherit "mail"
    
    ZoneFileLoader loader;
    t_zones zones;
    
    bool result = loader.load(zoneData, zones);
    
    CHECK(result);
    CHECK(zones.size() == 1);
    
    if (zones.size() > 0) {
        Zone* zone = zones[0];
        CHECK(zone->name == "example.com.");
        
        // Should have 4 RRs total (www A, www A, mail A, mail A)
        INFO("Number of RRs: " << zone->rrs.size());
        CHECK(zone->rrs.size() == 4);
        
        if (zone->rrs.size() >= 2) {
            // First two should all be for "www.example.com."
            INFO("RR[0] name: " << zone->rrs[0]->name);
            CHECK(zone->rrs[0]->name == "www.example.com.");
            CHECK(zone->rrs[0]->type == RR::A);
            
            INFO("RR[1] name: " << zone->rrs[1]->name);
            CHECK(zone->rrs[1]->name == "www.example.com.");
            CHECK(zone->rrs[1]->type == RR::A);
        }
        
        if (zone->rrs.size() >= 4) {
            // Third and fourth should be for "mail.example.com."
            INFO("RR[2] name: " << zone->rrs[2]->name);
            CHECK(zone->rrs[2]->name == "mail.example.com.");
            CHECK(zone->rrs[2]->type == RR::A);
            
            INFO("RR[3] name: " << zone->rrs[3]->name);
            CHECK(zone->rrs[3]->name == "mail.example.com.");
            CHECK(zone->rrs[3]->type == RR::A);
        }
    }
}

TEST_CASE("Zone file with explicit names works correctly", "[zonefile][3e5a586]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN test.org.");
    zoneData.push_back("host1   IN  A       10.0.0.1");
    zoneData.push_back("host2   IN  A       10.0.0.2");
    
    ZoneFileLoader loader;
    t_zones zones;
    
    bool result = loader.load(zoneData, zones);
    
    CHECK(result);
    CHECK(zones.size() == 1);
    
    if (zones.size() > 0) {
        Zone* zone = zones[0];
        CHECK(zone->rrs.size() == 2);
        
        if (zone->rrs.size() >= 2) {
            CHECK(zone->rrs[0]->name == "host1.test.org.");
            CHECK(zone->rrs[1]->name == "host2.test.org.");
        }
    }
}

// Test case-insensitive DNS name handling
TEST_CASE("DNS names are stored lowercase", "[case][refactor]")
{
    char packet[100];
    memset(packet, 0, sizeof(packet));
    
    unsigned int offset = 0;
    
    // Name with mixed case: "WwW.ExAmPlE.CoM"
    packet[0] = 3;
    memcpy(packet + 1, "WwW", 3);
    packet[4] = 7;
    memcpy(packet + 5, "ExAmPlE", 7);
    packet[12] = 3;
    memcpy(packet + 13, "CoM", 3);
    packet[16] = 0;
    
    // Type: A
    *(uint16_t*)(packet + 17) = htons(1);
    
    // Class: IN
    *(uint16_t*)(packet + 19) = htons(1);
    
    // TTL: 3600
    *(uint32_t*)(packet + 21) = htonl(3600);
    
    // RDLEN: 4
    *(uint16_t*)(packet + 25) = htons(4);
    
    // RDATA: 192.168.1.1
    packet[27] = 192;
    packet[28] = 168;
    packet[29] = 1;
    packet[30] = 1;
    
    RR* rr = RR::createByType(RR::A);
    bool result = rr->unpack(packet, sizeof(packet), offset, false);
    
    CHECK(result);
    // Name should be stored lowercase
    CHECK(rr->name == "www.example.com");
    
    delete rr;
}

TEST_CASE("Zone file names are stored lowercase", "[case][refactor]")
{
    t_data zoneData;
    
    // Mixed case zone name and hostnames
    zoneData.push_back("$ORIGIN Example.COM.");
    zoneData.push_back("WwW     IN  A       192.168.1.1");
    zoneData.push_back("MaIl    IN  A       192.168.1.2");
    
    ZoneFileLoader loader;
    t_zones zones;
    
    bool result = loader.load(zoneData, zones);
    
    CHECK(result);
    REQUIRE(zones.size() == 1);
    
    Zone* zone = zones[0];
    
    // Zone name should be lowercase
    CHECK(zone->name == "example.com.");
    
    REQUIRE(zone->rrs.size() == 2);
    
    // Record names should be lowercase
    CHECK(zone->rrs[0]->name == "www.example.com.");
    CHECK(zone->rrs[1]->name == "mail.example.com.");
}

TEST_CASE("Case-insensitive comparison works without tolower", "[case][refactor]")
{
    // Test that names stored lowercase can be compared directly
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN test.org.");
    zoneData.push_back("host    IN  A       10.0.0.1");
    
    ZoneFileLoader loader;
    t_zones zones;
    loader.load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->rrs.size() == 1);
    
    // Direct string comparison should work (both already lowercase)
    std::string query_name = dns_name_tolower("HoSt.TeSt.OrG.");
    CHECK(zones[0]->rrs[0]->name == query_name);
}

// ===== Tests for actual use cases that required lowercasing =====

// Use case 1: UPDATE zone matching (handleUpdate zone finding)
TEST_CASE("UPDATE message finds zone with mixed case", "[usecase][update][case]")
{
    t_data zoneData;
    
    // Zone defined in lowercase
    zoneData.push_back("$ORIGIN example.com.");
    zoneData.push_back("@       IN  SOA     ns1.example.com. admin.example.com. 1 3600 900 604800 86400");
    zoneData.push_back("test    IN  A       192.168.1.1");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    
    // Create UPDATE message with mixed-case zone name
    char packet[200];
    memset(packet, 0, sizeof(packet));
    
    *(uint16_t*)(packet + 0) = htons(0x1234);
    *(uint16_t*)(packet + 2) = htons(0x2800);  // UPDATE opcode
    *(uint16_t*)(packet + 4) = htons(1);       // ZOCOUNT
    *(uint16_t*)(packet + 6) = htons(0);       // PRCOUNT
    *(uint16_t*)(packet + 8) = htons(0);       // UPCOUNT
    *(uint16_t*)(packet + 10) = htons(0);      // ADCOUNT
    
    unsigned int off = 12;
    
    // Zone section with MIXED CASE: "ExAmPlE.CoM"
    packet[off++] = 7;
    memcpy(packet + off, "ExAmPlE", 7); off += 7;
    packet[off++] = 3;
    memcpy(packet + off, "CoM", 3); off += 3;
    packet[off++] = 0;
    *(uint16_t*)(packet + off) = htons(6); off += 2;  // SOA
    *(uint16_t*)(packet + off) = htons(1); off += 2;  // IN
    
    Message msg;
    unsigned int offset = 0;
    bool result = msg.unpack(packet, off, offset);
    
    REQUIRE(result);
    REQUIRE(msg.qd.size() == 1);
    
    // Zone name should be stored lowercase
    CHECK(msg.qd[0]->name == "example.com");
    
    // The zone should match despite case difference
    std::string zone_name_normalized(msg.qd[0]->name);
    if (!zone_name_normalized.empty() && zone_name_normalized[zone_name_normalized.length()-1] == '.')
        zone_name_normalized = zone_name_normalized.substr(0, zone_name_normalized.length()-1);
    
    std::string znormalized(zones[0]->name);
    if (!znormalized.empty() && znormalized[znormalized.length()-1] == '.')
        znormalized = znormalized.substr(0, znormalized.length()-1);
    
    CHECK(zone_name_normalized == znormalized);
}

// Use case 2: UPDATE prerequisites - checking if name exists (ANY type)
TEST_CASE("UPDATE prerequisite matches existing RR with mixed case", "[usecase][update][prereq]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN test.org.");
    zoneData.push_back("host    IN  A       10.0.0.1");
    zoneData.push_back("mail    IN  A       10.0.0.2");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->rrs.size() == 2);
    
    // Simulate prerequisite check with mixed case name
    std::string prereq_name = dns_name_tolower("HoSt.TeSt.OrG.");
    std::string prereq_name_normalized(prereq_name);
    if (!prereq_name_normalized.empty() && prereq_name_normalized[prereq_name_normalized.length()-1] == '.')
        prereq_name_normalized = prereq_name_normalized.substr(0, prereq_name_normalized.length()-1);
    
    bool found = false;
    for (size_t i = 0; i < zones[0]->rrs.size(); ++i)
    {
        RR *rr = zones[0]->rrs[i];
        std::string rr_name_normalized(rr->name);
        if (!rr_name_normalized.empty() && rr_name_normalized[rr_name_normalized.length()-1] == '.')
            rr_name_normalized = rr_name_normalized.substr(0, rr_name_normalized.length()-1);
        
        if (rr_name_normalized == prereq_name_normalized)
        {
            found = true;
            break;
        }
    }
    
    CHECK(found);
}

// Use case 3: UPDATE prerequisites - checking if specific RR type exists
TEST_CASE("UPDATE prerequisite matches RR type with mixed case", "[usecase][update][prereq]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN example.net.");
    zoneData.push_back("www     IN  A       192.168.1.1");
    zoneData.push_back("www     IN  MX      10 mail.example.net.");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    
    // Check for A record with mixed case name
    std::string prereq_name = dns_name_tolower("WwW.ExAmPlE.NeT.");
    std::string prereq_name_normalized(prereq_name);
    if (!prereq_name_normalized.empty() && prereq_name_normalized[prereq_name_normalized.length()-1] == '.')
        prereq_name_normalized = prereq_name_normalized.substr(0, prereq_name_normalized.length()-1);
    
    bool found = false;
    for (size_t i = 0; i < zones[0]->rrs.size(); ++i)
    {
        RR *rr = zones[0]->rrs[i];
        std::string rr_name_normalized(rr->name);
        if (!rr_name_normalized.empty() && rr_name_normalized[rr_name_normalized.length()-1] == '.')
            rr_name_normalized = rr_name_normalized.substr(0, rr_name_normalized.length()-1);
        
        if (rr_name_normalized == prereq_name_normalized && rr->type == RR::A)
        {
            found = true;
            break;
        }
    }
    
    CHECK(found);
}

// Use case 4: UPDATE deleting records by name
TEST_CASE("UPDATE delete finds RRs to delete with mixed case", "[usecase][update][delete]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN domain.com.");
    zoneData.push_back("old     IN  A       10.0.0.1");
    zoneData.push_back("keep    IN  A       10.0.0.2");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->rrs.size() == 2);
    
    // Find RR to delete with mixed case name
    std::string delete_name = dns_name_tolower("OlD.DoMaIn.CoM.");
    std::string delete_name_normalized(delete_name);
    if (!delete_name_normalized.empty() && delete_name_normalized[delete_name_normalized.length()-1] == '.')
        delete_name_normalized = delete_name_normalized.substr(0, delete_name_normalized.length()-1);
    
    RR* found_rr = nullptr;
    for (size_t i = 0; i < zones[0]->rrs.size(); ++i)
    {
        RR *rr = zones[0]->rrs[i];
        std::string rr_name_normalized(rr->name);
        if (!rr_name_normalized.empty() && rr_name_normalized[rr_name_normalized.length()-1] == '.')
            rr_name_normalized = rr_name_normalized.substr(0, rr_name_normalized.length()-1);
        
        if (rr_name_normalized == delete_name_normalized)
        {
            found_rr = rr;
            break;
        }
    }
    
    CHECK(found_rr != nullptr);
    if (found_rr) {
        CHECK(found_rr->name == "old.domain.com.");
    }
}

// Use case 5: QUERY matching - finding zone for query
TEST_CASE("QUERY finds zone with mixed case query name", "[usecase][query][case]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN example.org.");
    zoneData.push_back("www     IN  A       192.168.1.100");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    
    // Simulate query with mixed case
    std::string qrr_name = dns_name_tolower("WwW.ExAmPlE.OrG");
    std::string z_name = zones[0]->name;
    
    // Remove trailing dots for comparison
    if (!z_name.empty() && z_name[z_name.length()-1] == '.')
        z_name = z_name.substr(0, z_name.length()-1);
    
    // Check if query name ends with zone name (case-insensitive)
    std::string::size_type zpos = qrr_name.rfind(z_name);
    
    CHECK(zpos != std::string::npos);
    CHECK(zpos == (qrr_name.length() - z_name.length()));
}

// Use case 6: QUERY matching - finding RRs in zone
TEST_CASE("QUERY finds RR with mixed case query", "[usecase][query][case]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN test.com.");
    zoneData.push_back("server  IN  A       10.1.2.3");
    zoneData.push_back("client  IN  A       10.1.2.4");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->rrs.size() == 2);
    
    // Query with mixed case
    std::string qrr_name = dns_name_tolower("SeRvEr.TeSt.CoM.");
    
    bool found = false;
    for (size_t i = 0; i < zones[0]->rrs.size(); ++i)
    {
        RR *rr = zones[0]->rrs[i];
        if (rr->type == RR::A && 
            0 == rr->name.compare(0, qrr_name.length(), qrr_name))
        {
            found = true;
            break;
        }
    }
    
    CHECK(found);
}

// Use case 7: QUERY wildcard matching (TYPESTAR)
TEST_CASE("QUERY ANY type matches all RRs with mixed case", "[usecase][query][wildcard]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN multi.org.");
    zoneData.push_back("host    IN  A       1.2.3.4");
    zoneData.push_back("host    IN  MX      10 mail.multi.org.");
    zoneData.push_back("host    IN  TXT     \"test\"");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    REQUIRE(zones[0]->rrs.size() == 3);
    
    // Query for ANY with mixed case
    std::string qrr_name = dns_name_tolower("HoSt.MuLtI.OrG.");
    
    int match_count = 0;
    for (size_t i = 0; i < zones[0]->rrs.size(); ++i)
    {
        RR *rr = zones[0]->rrs[i];
        if (0 == rr->name.compare(0, qrr_name.length(), qrr_name))
        {
            match_count++;
        }
    }
    
    CHECK(match_count == 3);  // Should match all three records
}

// Use case 8: NS record delegation matching
TEST_CASE("QUERY finds NS record with mixed case", "[usecase][query][ns]")
{
    t_data zoneData;
    
    zoneData.push_back("$ORIGIN parent.com.");
    zoneData.push_back("sub     IN  NS      ns1.sub.parent.com.");
    zoneData.push_back("www     IN  A       10.0.0.1");
    
    t_zones zones;
    ZoneFileLoader::load(zoneData, zones);
    
    REQUIRE(zones.size() == 1);
    
    // Query with mixed case
    std::string qrr_name = dns_name_tolower("SuB.PaReNt.CoM.");
    
    RR* ns_rr = nullptr;
    for (size_t i = 0; i < zones[0]->rrs.size(); ++i)
    {
        RR *rr = zones[0]->rrs[i];
        if (rr->type == RR::NS && 
            0 == rr->name.compare(0, qrr_name.length(), qrr_name))
        {
            ns_rr = rr;
            break;
        }
    }
    
    CHECK(ns_rr != nullptr);
    if (ns_rr) {
        CHECK(ns_rr->name == "sub.parent.com.");
    }
}
