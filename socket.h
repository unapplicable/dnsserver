#ifndef HAVE_SOCKET_H
#define HAVE_SOCKET_H

#ifdef LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#define TRUE 1
typedef int SOCKET;
typedef struct hostent HOSTENT;
typedef struct sockaddr_in6 SOCKADDR_STORAGE;
typedef struct addrinfo ADDRINFO;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1

inline void closesocket_compat(SOCKET s) { close(s); }
inline bool wouldblock() { return errno == EAGAIN; }

#endif
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef struct addrinfo ADDRINFO;
#pragma comment(lib, "ws2_32.lib")

inline void closesocket_compat(SOCKET s) { closesocket(s); }
inline bool wouldblock() { return WSAGetLastError() == WSAEWOULDBLOCK; }

#endif

// Send DNS response - handles both UDP and TCP
// Unified implementation for all platforms
inline int send_dns_response(SOCKET s, const char* buf, int len, SOCKADDR_STORAGE* addr, int addrlen, bool is_tcp)
{
	if (is_tcp)
	{
		// TCP: prefix with 2-byte length
		unsigned short msglen = htons(len);
		if (send(s, (const char*)&msglen, 2, 0) != 2)
			return -1;
		return send(s, buf, len, 0);
	}
	else
	{
		// UDP: just send
		return sendto(s, buf, len, 0, (sockaddr*)addr, addrlen);
	}
}

#endif
