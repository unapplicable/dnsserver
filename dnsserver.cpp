#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <cstring>
#include "socket.h"

using namespace std;

#include "zone.h"
#include "message.h"
#include "rr.h"
#include "zoneFileLoader.h"

std::string VERSION("$Id$"); 



void dump(char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		printf("\\x%02X", (unsigned char)buf[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	if ((i - 1) % 16 != 15)
		printf("\n");
}


void handle(SOCKET s, char *buf, int len, char *from, SOCKADDR_STORAGE *addr, int addrlen, vector<Zone *>& zones)
{
	time_t t = time(NULL);
	tm *tmt = localtime(&t);
	char tmp[200];

	
	HOSTENT *he = NULL;
	/*
	char *ipBytes = (char *)&((sockaddr_in *)addr)->sin_addr.s_addr;
	
	he = gethostbyaddr(ipBytes, addrlen, AF_INET);
	*/

	printf("\n");
	strftime(tmp, sizeof(tmp), "%Y.%m.%d %H:%M:%S", tmt);
	printf("%s [%s] {%s} : %i\n",tmp, from, he ? he->h_name : "-", len);
	fflush(stdout);
	unsigned long fromaddr = inet_addr(from);

	//dump(buf, len);

	Message *reply = NULL;
	Message *msgtest = new Message();
	unsigned int offset = 0;
	if (!msgtest->unpack(buf, len, offset))
	{
		delete msgtest;
		cout << "faulty" << endl;
		return;
	}

	cout << *msgtest;
	if (msgtest->query && msgtest->opcode == Message::QUERY)
	{
		if (msgtest->qd.size() == 1 && msgtest->qd[0])
		{
			const RR *qrr = msgtest->qd[0];
			vector<Zone *>::const_iterator ziter;
			for (ziter = zones.begin(); ziter != zones.end(); ++ziter)
			{
				const Zone *z = *ziter;

				string qrrlower(qrr->name), zlower(z->name);
				std::transform(qrrlower.begin(), qrrlower.end(), qrrlower.begin(), (int (*)(int))tolower);
				std::transform(zlower.begin(), zlower.end(), zlower.begin(), (int (*)(int))tolower);

				string::size_type zpos = qrrlower.rfind(zlower);
				if (zpos == string::npos || zpos != (qrrlower.length() - zlower.length()))
					continue;

				if (z->acl.size())
				{
					Zone* matched = NULL;
					for (vector<AclEntry>::const_iterator i = z->acl.begin(); i != z->acl.end(); ++i)
					{
						if (i->subnet.match(fromaddr))
						{
							char tmp[20];
							char tmp2[20];
							strcpy(tmp, inet_ntoa(*reinterpret_cast<const in_addr*>(&i->subnet.ip)));
							strcpy(tmp2, inet_ntoa(*reinterpret_cast<const in_addr*>(&i->subnet.mask)));

							printf("ACL: matched %s/%s\n", tmp, tmp2);
							matched = i->zone;
							break;
						}
					}

					if (matched != NULL)
						z = matched;
				}

				reply = new Message();
				reply->id = msgtest->id;
				reply->opcode = Message::QUERY;
				reply->qd.push_back(qrr->clone());
				reply->truncation = false;
				reply->query = false;
				reply->authoritative = true;
				reply->rcode = Message::CODENOERROR;
				reply->recursionavailable = reply->recursiondesired = msgtest->recursiondesired;

				vector<RR *>::const_iterator rriter;
				for (rriter = z->rrs.begin(); rriter != z->rrs.end(); ++rriter)
				{
					RR *rr = *rriter;


					if (
						(rr->type == qrr->type && 
						0 == rr->name.compare(0, qrrlower.length(), qrrlower)
						) ||
						(qrr->type == RR::TYPESTAR)
						)
					{
						RR *arr = rr->clone();
						arr->query = false;												
						
						arr->ttl = 10 * 60; // 10 minutes
												
						reply->an.push_back(arr);

						if (qrr->type != RR::TYPESTAR)
							break;
					}
				}
				
				break;
			}

			if (reply == NULL || reply->an.size() == 0)
			{
				reply = new Message();
				reply->id = msgtest->id;
				reply->opcode = Message::QUERY;
				reply->qd.push_back(qrr->clone());
				reply->truncation = false;
				reply->query = false;
				reply->authoritative = true;
				reply->recursionavailable = reply->recursiondesired = msgtest->recursiondesired;
				reply->rcode = Message::CODENAMEERROR;
			}
		}
	}
		
	if (reply != NULL)
	{
		char packet[0x10000] = {};
		unsigned int packetsize = 0;
		
		cout << *reply << endl;

		reply->pack(packet, (unsigned int)sizeof(packet), packetsize);
		//dump(packet, packetsize);
		
		sendto(s, packet, packetsize, 0, (sockaddr *)addr, addrlen);
		delete reply;
	} else
	{
		printf("NOANS\n");
		
	}

	fflush(stdout);

	delete msgtest;
}

int setnonblock(SOCKET sockfd, int nonblock)
{
#ifdef LINUX
	int flags;
	flags = fcntl(sockfd, F_GETFL, 0);
	if (TRUE == nonblock)
		return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	else
		return fcntl(sockfd, F_SETFL, flags & (~O_NONBLOCK));
#else
	u_long mode = nonblock;
	return ioctlsocket(sockfd, FIONBIO, &mode);
#endif
}

void daemonize()
{
#ifdef LINUX
	setreuid(1000, 1000);
	setregid(1000, 1000);

	if (fork() != 0)
		exit(1);
#endif
}

void serverloop(char **vaddr, vector<Zone *>& zones)
{
	SOCKET s[100];
	ADDRINFO hints, *addrinfo, *addrinfoi;
	int numSockets = 0;
	int port = 53;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags =  AI_PASSIVE;

	for (numSockets = 0; vaddr[numSockets] != 0; ++numSockets)
	{
		char* addr = vaddr[numSockets];
		fprintf(stderr, "binding to %s:%d\n", addr, port);

		if (getaddrinfo(addr, "53", &hints, &addrinfo))
		{
			fprintf(stderr, "getaddrinfo failed for %s\n", addr);
			return;
		}

		for (addrinfoi = addrinfo; 
			addrinfoi && addrinfoi->ai_family != PF_INET && addrinfoi->ai_family != PF_INET6;
			addrinfoi = addrinfoi->ai_next);

		if ((s[numSockets] = socket(addrinfoi->ai_family, addrinfoi->ai_socktype, addrinfoi->ai_protocol)) == INVALID_SOCKET)
		{
			fprintf(stderr, "socket failed %s\n", addr);
			return;
		}

		setnonblock(s[numSockets], 1);

		if (bind(s[numSockets], addrinfoi->ai_addr, static_cast<int>(addrinfoi->ai_addrlen)) == SOCKET_ERROR)
		{
			fprintf(stderr, "bind failed %s:%d\n", addr, port);
			return;
		}

		freeaddrinfo(addrinfo);
	}

	daemonize();
	
	while (true)
	{
		char buf[0xFFFF] = {0};
		char hostname[NI_MAXHOST] = {0x41};
		sockaddr_in6 from;
		socklen_t fromlen;
		fd_set rdfds;
		SOCKET maxfd = 0;

		FD_ZERO(&rdfds);
		for (int i = 0; i < numSockets; ++i)
		{
			FD_SET(s[i], &rdfds);
			maxfd = max(maxfd, s[i]);
		}
		
		if (0 >= select(static_cast<int>(maxfd + 1), &rdfds, NULL, NULL, NULL))
		{
			continue;
		}

		for (int i = 0; i < numSockets; ++i)
		{
			if (!FD_ISSET(s[i], &rdfds))
			{
				continue;
			}

			fromlen = sizeof(from);
			memset(&from, 0, fromlen);
			int numrecv = recvfrom(s[i], (char *)&buf, sizeof(buf), 0, (sockaddr *)&from, &fromlen);
			if (numrecv == SOCKET_ERROR || numrecv == 0)
			{
#ifdef LINUX
				int wsaerr = errno;
				if (wsaerr == EAGAIN)
#else
				int wsaerr = WSAGetLastError();
				if (wsaerr == WSAEWOULDBLOCK)
#endif
				
				{
				} else
				{
					fprintf(stderr, "recvfrom failed %08X %d\n", wsaerr, wsaerr);
				}
				continue;
			}

			if (getnameinfo((sockaddr *)&from, fromlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST))
				strcpy(hostname, "unknown");

			handle(s[i], buf, numrecv, hostname, reinterpret_cast<SOCKADDR_STORAGE*>(&from), fromlen, zones);
		}
	}
}



int main(int argc, char* argv[])
{
	vector<Zone *> zones;
	vector<string> zonedata;

	std::cout << "dnsserver version " << VERSION << std::endl;

	ifstream a;
	ifstream zonefile;
	zonefile.open(argv[1]);
	do
	{
		char line[4096];
		if (zonefile.getline(line, sizeof(line)))
		{
			zonedata.push_back(line);
		} else
			break;
	} while (true);
	
	if (!ZoneFileLoader::load(zonedata, zones))
	{
		cerr << "[-] error loading zones, malformed data" << endl;
		return 0;
	}

	serverloop(&argv[2], zones);
	return 0;
}

