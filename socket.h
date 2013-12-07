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
#endif
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef struct addrinfo ADDRINFO;
#pragma comment(lib, "ws2_32.lib")
#endif

#endif
