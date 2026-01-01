#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <cstring>
#include <pthread.h>
#include "socket.h"

using namespace std;

#include "zone.h"
#include "message.h"
#include "rr.h"
#include "rrsoa.h"
#include "zoneFileLoader.h"
#include "zone_authority.h"
#include "zone_database.h"
#include "update_processor.h"
#include "query_processor.h"

std::string VERSION("$Id$");

// Global mutex for zone modifications
pthread_mutex_t g_zone_mutex = PTHREAD_MUTEX_INITIALIZER; 



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


void handleQuery(SOCKET s, char * /*buf*/, int /*len*/, char * /*from*/, SOCKADDR_STORAGE *addr, int addrlen,
                 Message *request, vector<Zone *>& zones, unsigned long fromaddr, bool is_tcp = false)
{
	if (request->qd.size() != 1 || !request->qd[0])
	{
		return;
	}
	
	const RR *qrr = request->qd[0];
	
	// Find zone using ZoneAuthority
	ZoneAuthority authority(zones);
	ZoneLookupResult lookup = authority.findZoneForName(qrr->name, fromaddr);
	
	if (!lookup.found)
	{
		return;
	}
	
	Zone *z = lookup.authorized ? lookup.zone : lookup.zone;
	
	Message *reply = new Message();
	reply->id = request->id;
	reply->opcode = Message::QUERY;
	reply->qd.push_back(qrr->clone());
	reply->truncation = false;
	reply->query = false;
	reply->authoritative = true;
	reply->rcode = Message::CODENOERROR;
	reply->recursionavailable = reply->recursiondesired = request->recursiondesired;
	
	// Use QueryProcessor to find matching records
	{
		ZoneDatabase zonedb(z);
		vector<RR*> matches;
		RR *rrNs = nullptr;
		QueryProcessor::findMatches(qrr, zonedb, matches, &rrNs);
		
		// Clone matches and add to answer section
		for (vector<RR*>::const_iterator match_iter = matches.begin(); 
		     match_iter != matches.end(); ++match_iter)
		{
			RR *arr = (*match_iter)->clone();
			arr->query = false;
			arr->ttl = 10 * 60; // 10 minutes
			reply->an.push_back(arr);
		}
		
		if (reply->an.size() == 0 && rrNs != nullptr) {
			RR *arr = rrNs->clone();
			arr->query = false;
			arr->ttl = 10 * 60; // 10 minutes
			reply->ns.push_back(arr);
			reply->authoritative = true;
		}
	}
	
	cout << *reply;
	
	char response[0x10000];
	unsigned int response_len = 0;
	reply->pack(response, sizeof(response), response_len);
	
	send_dns_response(s, response, response_len, addr, addrlen, is_tcp);
	
	delete reply;
}

void handleUpdate(SOCKET s, char * /*buf*/, int /*len*/, char * /*from*/, SOCKADDR_STORAGE *addr, int addrlen, 
                  Message *request, vector<Zone *>& zones, unsigned long fromaddr, bool is_tcp = false)
{
	const RR *zone_rr = NULL;
	Message *reply = new Message();
	reply->id = request->id;
	reply->opcode = Message::UPDATE;
	reply->query = false;
	reply->authoritative = true;
	reply->truncation = false;
	reply->recursiondesired = false;
	reply->recursionavailable = false;
	reply->rcode = Message::CODENOERROR;
	
	if (request->qd.size() != 1 || !request->qd[0])
	{
		cout << "UPDATE: Invalid zone section" << endl;
		reply->rcode = Message::CODEFORMATERROR;
		goto send_response;
	}
	
	zone_rr = request->qd[0];
	if (zone_rr->type != RR::SOA)
	{
		cout << "UPDATE: Zone section must be SOA" << endl;
		reply->rcode = Message::CODEFORMATERROR;
		goto send_response;
	}
	
	cout << "UPDATE: Processing zone " << zone_rr->name << endl;
	
	{
		// Find zone using ZoneAuthority
		ZoneAuthority authority(zones);
		ZoneLookupResult lookup = authority.findZoneForName(zone_rr->name, fromaddr);
		
		if (!lookup.found || !lookup.authorized)
		{
			cout << "UPDATE: " << lookup.error_message << endl;
			reply->rcode = Message::CODEREFUSED;
			goto send_response;
		}
		
		Zone *target_zone = lookup.zone;
		cout << "UPDATE: Target zone found: " << target_zone->name << endl;
		cout << "UPDATE: Prerequisites: " << request->an.size() << ", Updates: " << request->ns.size() << endl;
		
		// Check prerequisites using UpdateProcessor
		ZoneDatabase zonedb(target_zone);
		string prereq_error;
		if (!UpdateProcessor::checkPrerequisites(request, zonedb, prereq_error))
		{
			cout << "UPDATE: " << prereq_error << endl;
			reply->rcode = Message::CODENAMEERROR;
			goto send_response;
		}
		
		cout << "UPDATE: All prerequisites passed" << endl;
		
		// CRITICAL SECTION START: Protect all zone modifications
		pthread_mutex_lock(&g_zone_mutex);
		
		// Apply updates using UpdateProcessor
		string update_error;
		UpdateProcessor::applyUpdates(request, zonedb, update_error);
		
		// Increment SOA serial
		ZoneAuthority::incrementSerial(target_zone);
		
		pthread_mutex_unlock(&g_zone_mutex);
		// CRITICAL SECTION END
		
		cout << "UPDATE: Success" << endl;
	}
	
send_response:
	if (zone_rr)
		reply->qd.push_back(zone_rr->clone());
	
	char packet[0x10000] = {};
	unsigned int packetsize = 0;
	
	cout << *reply << endl;
	
	reply->pack(packet, (unsigned int)sizeof(packet), packetsize);
	send_dns_response(s, packet, packetsize, addr, addrlen, is_tcp);
	
	delete reply;
}


void handle(SOCKET s, char *buf, int len, char *from, SOCKADDR_STORAGE *addr, int addrlen, vector<Zone *>& zones, bool is_tcp = false)
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

	Message *msgtest = new Message();
	unsigned int offset = 0;
	if (!msgtest->unpack(buf, len, offset))
	{
		delete msgtest;
		cout << "faulty" << endl;
		return;
	}

	cout << *msgtest;
	
	if (msgtest->query && msgtest->opcode == Message::UPDATE)
	{
		handleUpdate(s, buf, len, from, addr, addrlen, msgtest, zones, fromaddr, is_tcp);
		delete msgtest;
		return;
	}
	
	if (msgtest->query && msgtest->opcode == Message::QUERY)
	{
		handleQuery(s, buf, len, from, addr, addrlen, msgtest, zones, fromaddr, is_tcp);
		delete msgtest;
		return;
	}

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

void daemonize(int uid, int gid)
{
#ifdef LINUX
	if (uid != -1)
		setreuid(uid, uid);

	if (gid != -1)
		setregid(gid, gid);

	if (fork() != 0)
		exit(1);
#endif
}

void serverloop(char **vaddr, vector<Zone *>& zones, int uid, int gid, int port)
{
	SOCKET udp_s[100], tcp_s[100];
	int numSockets = 0;
	char portstr[16];

#ifndef LINUX
	WSADATA wda;
	WSAStartup(MAKEWORD(2, 1), &wda);
#endif

	snprintf(portstr, sizeof(portstr), "%d", port);
	ADDRINFO hints, *addrinfo, *addrinfoi;
	
	// Setup UDP
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	for (numSockets = 0; vaddr[numSockets] != 0; ++numSockets)
	{
		char* addr = vaddr[numSockets];
		fprintf(stderr, "binding UDP to %s:%d\n", addr, port);

		if (getaddrinfo(addr, portstr, &hints, &addrinfo))
		{
			fprintf(stderr, "getaddrinfo failed for %s\n", addr);
			return;
		}

		for (addrinfoi = addrinfo; 
			addrinfoi && addrinfoi->ai_family != PF_INET && addrinfoi->ai_family != PF_INET6;
			addrinfoi = addrinfoi->ai_next);

		if ((udp_s[numSockets] = socket(addrinfoi->ai_family, addrinfoi->ai_socktype, addrinfoi->ai_protocol)) == INVALID_SOCKET)
		{
			fprintf(stderr, "UDP socket failed %s\n", addr);
			return;
		}

		setnonblock(udp_s[numSockets], 1);

		if (bind(udp_s[numSockets], addrinfoi->ai_addr, static_cast<int>(addrinfoi->ai_addrlen)) == SOCKET_ERROR)
		{
			fprintf(stderr, "UDP bind failed %s:%d\n", addr, port);
			return;
		}

		freeaddrinfo(addrinfo);
	}

	// Setup TCP
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	for (int i = 0; i < numSockets; ++i)
	{
		char* addr = vaddr[i];
		fprintf(stderr, "binding TCP to %s:%d\n", addr, port);

		if (getaddrinfo(addr, portstr, &hints, &addrinfo))
		{
			fprintf(stderr, "getaddrinfo failed for TCP %s\n", addr);
			return;
		}

		for (addrinfoi = addrinfo;
			addrinfoi && addrinfoi->ai_family != PF_INET && addrinfoi->ai_family != PF_INET6;
			addrinfoi = addrinfoi->ai_next);

		if ((tcp_s[i] = socket(addrinfoi->ai_family, addrinfoi->ai_socktype, addrinfoi->ai_protocol)) == INVALID_SOCKET)
		{
			fprintf(stderr, "TCP socket failed %s\n", addr);
			return;
		}

		int reuse = 1;
		setsockopt(tcp_s[i], SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
		setnonblock(tcp_s[i], 1);

		if (bind(tcp_s[i], addrinfoi->ai_addr, static_cast<int>(addrinfoi->ai_addrlen)) == SOCKET_ERROR)
		{
			fprintf(stderr, "TCP bind failed %s:%d\n", addr, port);
			return;
		}

		if (listen(tcp_s[i], 128) == SOCKET_ERROR)
		{
			fprintf(stderr, "TCP listen failed %s:%d\n", addr, port);
			return;
		}

		freeaddrinfo(addrinfo);
	}

	daemonize(uid, gid);
	
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
			FD_SET(udp_s[i], &rdfds);
			FD_SET(tcp_s[i], &rdfds);
			maxfd = max(maxfd, max(udp_s[i], tcp_s[i]));
		}
		
		if (0 >= select(static_cast<int>(maxfd + 1), &rdfds, NULL, NULL, NULL))
			continue;

		// Handle UDP
		for (int i = 0; i < numSockets; ++i)
		{
			if (!FD_ISSET(udp_s[i], &rdfds))
				continue;

			fromlen = sizeof(from);
			memset(&from, 0, fromlen);
			int numrecv = recvfrom(udp_s[i], (char *)&buf, sizeof(buf), 0, (sockaddr *)&from, &fromlen);
			if (numrecv == SOCKET_ERROR || numrecv == 0)
			{
				if (!wouldblock())
					fprintf(stderr, "recvfrom failed\n");
				continue;
			}

			if (getnameinfo((sockaddr *)&from, fromlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST))
				strcpy(hostname, "unknown");

			handle(udp_s[i], buf, numrecv, hostname, reinterpret_cast<SOCKADDR_STORAGE*>(&from), fromlen, zones, false);
		}

		// Handle TCP
		for (int i = 0; i < numSockets; ++i)
		{
			if (!FD_ISSET(tcp_s[i], &rdfds))
				continue;

			fromlen = sizeof(from);
			memset(&from, 0, fromlen);
			SOCKET client = accept(tcp_s[i], (sockaddr *)&from, &fromlen);
			if (client == INVALID_SOCKET)
				continue;

			// Read length prefix
			unsigned short msglen;
			if (recv(client, (char*)&msglen, 2, 0) != 2)
			{
				closesocket_compat(client);
				continue;
			}
			msglen = ntohs(msglen);
			if (msglen == 0 || msglen > 65535)
			{
				closesocket_compat(client);
				continue;
			}

			// Read message
			if (recv(client, buf, msglen, 0) != msglen)
			{
				closesocket_compat(client);
				continue;
			}

			if (getnameinfo((sockaddr *)&from, fromlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST))
				strcpy(hostname, "unknown");

			handle(client, buf, msglen, hostname, reinterpret_cast<SOCKADDR_STORAGE*>(&from), fromlen, zones, true);
			
			closesocket_compat(client);
		}
	}
}



int main(int argc, char* argv[])
{
	vector<Zone *> zones;
	vector<string> zonedata;

	std::cout << "dnsserver version " << VERSION << std::endl;

	if (argc < 3)
	{
		cerr << "Usage: " << argv[0] << " [-p port] [-u uid] [-g gid] zonefile IP1 [IP2 ...]" << endl;
		return 1;
	}

	// Parse options first
	int uid = -1, gid = -1, port = 53;
	int arg = 1;
	for (; arg < argc; ) {
		if (argv[arg] == std::string("-p") || argv[arg] == std::string("--port")) {
			port = atoi(argv[arg + 1]);
			arg += 2;
		} else
		if (argv[arg] == std::string("-u")) {
			uid = atoi(argv[arg + 1]);
			arg += 2;
		} else
		if (argv[arg] == std::string("-g")) {
			gid = atoi(argv[arg + 1]);
			arg += 2;
		} else
			break;  // First non-option is zonefile
	}

	// Now arg points to zonefile
	if (arg >= argc)
	{
		cerr << "Error: zonefile not specified" << endl;
		return 1;
	}

	ifstream zonefile;
	zonefile.open(argv[arg]);
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

	// IPs start at arg+1
	serverloop(&argv[arg+1], zones, uid, gid, port);
	return 0;
}

