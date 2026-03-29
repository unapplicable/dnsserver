#ifndef HAVE_WIRE_H
#define HAVE_WIRE_H

#include <cstring>
#include <cstdint>
#include <arpa/inet.h>

// Safe wire-format read/write helpers that avoid strict aliasing violations.
// All functions use memcpy to access potentially unaligned data in DNS packets.

inline uint16_t wire_read_u16(const char* data, unsigned int offset) {
	uint16_t val;
	memcpy(&val, &data[offset], sizeof(val));
	return ntohs(val);
}

inline void wire_write_u16(char* data, unsigned int offset, uint16_t val) {
	uint16_t netval = htons(val);
	memcpy(&data[offset], &netval, sizeof(netval));
}

inline uint32_t wire_read_u32(const char* data, unsigned int offset) {
	uint32_t val;
	memcpy(&val, &data[offset], sizeof(val));
	return ntohl(val);
}

inline void wire_write_u32(char* data, unsigned int offset, uint32_t val) {
	uint32_t netval = htonl(val);
	memcpy(&data[offset], &netval, sizeof(netval));
}

#endif
