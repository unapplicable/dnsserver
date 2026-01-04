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

// Set receive timeout on socket to prevent slowloris DoS attacks
// Returns 0 on success, -1 on failure
inline int set_recv_timeout(SOCKET s, int timeout_seconds)
{
#ifdef LINUX
	struct timeval timeout;
	timeout.tv_sec = timeout_seconds;
	timeout.tv_usec = 0;
	return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#else
	DWORD timeout_ms = timeout_seconds * 1000;
	return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#endif
}

// Check if last socket error was a timeout
inline bool is_recv_timeout()
{
#ifdef LINUX
	return errno == EAGAIN || errno == EWOULDBLOCK;
#else
	return WSAGetLastError() == WSAETIMEDOUT;
#endif
}

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
