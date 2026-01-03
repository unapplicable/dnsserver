#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <cstring>
#include <pthread.h>
#include <signal.h>
#include <openssl/opensslv.h>
#include "socket.h"

using namespace std;

#include "zone.h"
#include "acl.h"
#include "message.h"
#include "rr.h"
#include "rrsoa.h"
#include "rrtxt.h"
#include "zoneFileLoader.h"
#include "zoneFileSaver.h"
#include "zone_authority.h"
#include "update_processor.h"
#include "query_processor.h"
#include "tsig.h"
#include "version.h"

// Global mutex for zone modifications
pthread_mutex_t g_zone_mutex = PTHREAD_MUTEX_INITIALIZER; 

// Global flags for signal handlers
volatile sig_atomic_t g_reload_zones = 0; 
volatile sig_atomic_t g_shutdown = 0; 



void dump(char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		cout << "\\x" << hex << setfill('0') << setw(2) << (int)(unsigned char)buf[i] << dec;
		if (i % 16 == 15)
			cout << endl;
	}
	if ((i - 1) % 16 != 15)
		cout << endl;
	cout << flush;
}

void dumpPacketHex(const char* label, char *buf, int len)
{
	cerr << "[" << label << "] Packet dump (" << len << " bytes):" << endl;
	for (int i = 0; i < len; i++)
	{
		cerr << hex << setfill('0') << setw(2) << (int)(unsigned char)buf[i];
		if (i % 16 == 15)
			cerr << endl;
		else if (i % 2 == 1)
			cerr << " ";
	}
	if ((len - 1) % 16 != 15)
		cerr << endl;
	cerr << dec << flush;
}

void handleVersionBind(SOCKET s, SOCKADDR_STORAGE* addr, int addrlen, Message* request, vector<Zone*>& zones, bool is_tcp)
{
	try {
		const RR *qrr = request->qd[0];
		Message *reply = new Message();
		reply->id = request->id;
		reply->opcode = Message::QUERY;
		reply->qd.push_back(qrr->clone());
		reply->truncation = false;
		reply->query = false;
		reply->authoritative = true;
		reply->rcode = Message::CODENOERROR;
		reply->recursionavailable = reply->recursiondesired = request->recursiondesired;
		
		// Check if there's a version.bind record in the zone file
		string version_text = VERSION;
		for (vector<Zone*>::iterator zone_iter = zones.begin(); zone_iter != zones.end(); ++zone_iter)
		{
			Zone* zone = *zone_iter;
			const vector<RR*>& rrs = zone->getAllRecords();
			for (vector<RR*>::const_iterator rr_iter = rrs.begin(); rr_iter != rrs.end(); ++rr_iter)
			{
				const RR* rr = *rr_iter;
				if (rr->name == qrr->name && rr->type == RR::TXT && rr->rrclass == RR::CH)
				{
					// Found zone file entry - prepend it to version
					version_text = rr->rdata + " " + VERSION;
					break;
				}
			}
		}
		
		// Create TXT record with version
		RR *arr = new RRTXT();
		arr->name = qrr->name;
		arr->rrclass = RR::CH;
		arr->type = RR::TXT;
		arr->ttl = 0;
		arr->query = false;
		arr->rdata = version_text;
		reply->an.push_back(arr);
		
		cout << *reply << flush;
		
		char response[0x10000];
		unsigned int response_len = 0;
		reply->pack(response, sizeof(response), response_len);
		
		send_dns_response(s, response, response_len, addr, addrlen, is_tcp);
		delete reply;
	}
	catch (const std::exception& e)
	{
		cerr << "\n[EXCEPTION] In handleVersionBind(): " << e.what() << endl;
		cerr << flush;
		throw; // Re-throw to be caught by handle()
	}
	catch (...)
	{
		cerr << "\n[EXCEPTION] Unknown exception in handleVersionBind()" << endl;
		cerr << flush;
		throw; // Re-throw to be caught by handle()
	}
}

void handleQuery(SOCKET s, char *buf, int len, char *from, SOCKADDR_STORAGE *addr, int addrlen,
                 Message *request, vector<Zone *>& zones, unsigned long fromaddr, bool is_tcp = false)
{
	try {
		if (request->qd.size() != 1 || !request->qd[0])
		{
			return;
		}
		
		const RR *qrr = request->qd[0];
		
		// Handle CHAOS class version.bind queries
		if (qrr->rrclass == RR::CH && qrr->type == RR::TXT && 
		    (qrr->name == "version.bind." || qrr->name == "version."))
		{
			handleVersionBind(s, addr, addrlen, request, zones, is_tcp);
			return;
		}
		
		// Find zone using ZoneAuthority
		ZoneAuthority authority(zones);
		ZoneLookupResult lookup = authority.findZoneForName(qrr->name, fromaddr);
		
		if (!lookup.found)
		{
			return;
		}
		
		if (!lookup.authorized)
		{
			return;
		}
		
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
			vector<RR*> matches;
			RR *rrNs = nullptr;
			
			// Search the zone (ACL longest-match already applied in zone_authority)
			QueryProcessor::findMatches(qrr, *lookup.zone, matches, &rrNs);
			
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
		
		cout << *reply << flush;
		
		char response[0x10000];
		unsigned int response_len = 0;
		reply->pack(response, sizeof(response), response_len);
		
		send_dns_response(s, response, response_len, addr, addrlen, is_tcp);
		
		delete reply;
	}
	catch (const std::exception& e)
	{
		cerr << "\n[EXCEPTION] In handleQuery(): " << e.what() << endl;
		cerr << "[EXCEPTION] Query: " << (request->qd[0] ? request->qd[0]->name : "NULL") 
		     << " from " << from << endl;
		dumpPacketHex("QUERY_EXCEPTION", buf, len);
		cerr << flush;
		throw; // Re-throw to be caught by handle()
	}
	catch (...)
	{
		cerr << "\n[EXCEPTION] Unknown exception in handleQuery()" << endl;
		cerr << "[EXCEPTION] Query: " << (request->qd[0] ? request->qd[0]->name : "NULL") 
		     << " from " << from << endl;
		dumpPacketHex("QUERY_EXCEPTION", buf, len);
		cerr << flush;
		throw; // Re-throw to be caught by handle()
	}
}

void handleUpdate(SOCKET s, char *buf, int len, char *from, SOCKADDR_STORAGE *addr, int addrlen, 
                  Message *request, vector<Zone *>& zones, unsigned long fromaddr, bool is_tcp = false)
{
	try {
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
			cout << "UPDATE: Invalid zone section" << endl << flush;
			reply->rcode = Message::CODEFORMATERROR;
			goto send_response;
		}
		
		zone_rr = request->qd[0];
		if (zone_rr->type != RR::SOA)
		{
			cout << "UPDATE: Zone section must be SOA" << endl << flush;
			reply->rcode = Message::CODEFORMATERROR;
			goto send_response;
		}
		
		cout << "UPDATE: Processing zone " << zone_rr->name << endl << flush;
		
		{
			// Find zone using ZoneAuthority
			ZoneAuthority authority(zones);
			ZoneLookupResult lookup = authority.findZoneForName(zone_rr->name, fromaddr);
			
			if (!lookup.found || !lookup.authorized)
			{
				cout << "UPDATE: " << lookup.error_message << endl << flush;
				reply->rcode = Message::CODEREFUSED;
				goto send_response;
			}
			
			Zone *target_zone = lookup.zone;
			cout << "UPDATE: Target zone found: " << target_zone->name << endl << flush;
			
			// TSIG Authentication Check
			if (target_zone->tsig_key)
			{
				string tsig_error;
				if (!TSIG::verify(request, buf, len, target_zone->tsig_key, tsig_error))
				{
					cout << "UPDATE: TSIG verification failed: " << tsig_error << endl << flush;
					reply->rcode = Message::CODEREFUSED;
					goto send_response;
				}
				cout << "UPDATE: TSIG verification successful" << endl << flush;
			}
			
			cout << "UPDATE: Prerequisites: " << request->an.size() << ", Updates: " << request->ns.size() << endl << flush;
			
			// Check prerequisites using UpdateProcessor
			string prereq_error;
			if (!UpdateProcessor::checkPrerequisites(request, *target_zone, prereq_error))
			{
				cout << "UPDATE: " << prereq_error << endl << flush;
				reply->rcode = Message::CODENAMEERROR;
				goto send_response;
			}
			
			cout << "UPDATE: All prerequisites passed" << endl << flush;
			
			// CRITICAL SECTION START: Protect all zone modifications
			pthread_mutex_lock(&g_zone_mutex);
			
			// Apply updates using UpdateProcessor
			string update_error;
			UpdateProcessor::applyUpdates(request, *target_zone, update_error);
			
			pthread_mutex_unlock(&g_zone_mutex);
			// CRITICAL SECTION END
			
			cout << "UPDATE: Success" << endl << flush;
		}
		
send_response:
		if (zone_rr)
			reply->qd.push_back(zone_rr->clone());
		
		char packet[0x10000] = {};
		unsigned int packetsize = 0;
		
		cout << *reply << endl << flush;
		
		reply->pack(packet, (unsigned int)sizeof(packet), packetsize);
		send_dns_response(s, packet, packetsize, addr, addrlen, is_tcp);
		
		delete reply;
	}
	catch (const std::exception& e)
	{
		cerr << "\n[EXCEPTION] In handleUpdate(): " << e.what() << endl;
		cerr << "[EXCEPTION] Zone: " << (request->qd[0] ? request->qd[0]->name : "NULL") 
		     << " from " << from << endl;
		dumpPacketHex("UPDATE_EXCEPTION", buf, len);
		cerr << flush;
		throw; // Re-throw to be caught by handle()
	}
	catch (...)
	{
		cerr << "\n[EXCEPTION] Unknown exception in handleUpdate()" << endl;
		cerr << "[EXCEPTION] Zone: " << (request->qd[0] ? request->qd[0]->name : "NULL") 
		     << " from " << from << endl;
		dumpPacketHex("UPDATE_EXCEPTION", buf, len);
		cerr << flush;
		throw; // Re-throw to be caught by handle()
	}
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

	strftime(tmp, sizeof(tmp), "%Y.%m.%d %H:%M:%S", tmt);
	cout << "\n" << tmp << " [" << from << "] {" << (he ? he->h_name : "-") << "} : " << len << endl << flush;
	unsigned long fromaddr = inet_addr(from);

	//dump(buf, len);

	try {
		Message *msgtest = new Message();
		unsigned int offset = 0;
		if (!msgtest->unpack(buf, len, offset))
		{
			delete msgtest;
			cerr << "[UNPACK_FAILED] Message unpacking failed" << endl;
			cerr << "[UNPACK_FAILED] Client: " << from << ", Packet length: " << len << " bytes" << endl;
			dumpPacketHex("UNPACK_FAILED", buf, len);
			cerr << flush;
			cout << "faulty" << endl << flush;
			return;
		}

		cout << *msgtest << flush;
		
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
	catch (const std::exception& e)
	{
		cerr << "\n[EXCEPTION] Caught exception in handle(): " << e.what() << endl;
		cerr << "[EXCEPTION] Client: " << from << ", Packet length: " << len << " bytes" << endl;
		dumpPacketHex("EXCEPTION", buf, len);
		cerr << flush;
	}
	catch (...)
	{
		cerr << "\n[EXCEPTION] Caught unknown exception in handle()" << endl;
		cerr << "[EXCEPTION] Client: " << from << ", Packet length: " << len << " bytes" << endl;
		dumpPacketHex("EXCEPTION", buf, len);
		cerr << flush;
	}
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

void* zoneSaveThread(void* arg)
{
	vector<Zone*>* zones = (vector<Zone*>*)arg;
	
	while (true)
	{
		// Sleep for 5 minutes
		sleep(300);
		
		// Check all zones for modifications and save if needed
		pthread_mutex_lock(&g_zone_mutex);
		
		for (vector<Zone*>::iterator it = zones->begin(); it != zones->end(); ++it)
		{
			Zone* zone = *it;
			
			if (zone->auto_save && zone->modified)
			{
				cerr << "[AUTOSAVE] Zone " << zone->name << " has been modified, saving..." << endl;
				
				if (ZoneFileSaver::saveToFile(zone, zone->filename))
				{
					cerr << "[AUTOSAVE] Zone " << zone->name << " saved successfully" << endl;
				}
				else
				{
					cerr << "[AUTOSAVE] Zone " << zone->name << " save failed!" << endl;
				}
			}
		}
		
		pthread_mutex_unlock(&g_zone_mutex);
	}
	
	return NULL;
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

void sighupHandler(int /*signum*/)
{
	g_reload_zones = 1;
}

void sigtermHandler(int /*signum*/)
{
	g_shutdown = 1;
}

void saveModifiedZonesLocked(vector<Zone*>& zones, const char* prefix)
{
	for (vector<Zone*>::iterator it = zones.begin(); it != zones.end(); ++it)
	{
		Zone* zone = *it;
		
		if (zone->auto_save && zone->modified)
		{
			cerr << prefix << "Saving zone " << zone->name << "..." << endl;
			
			if (ZoneFileSaver::saveToFile(zone, zone->filename))
			{
				zone->clearModified();
				cerr << prefix << "Zone " << zone->name << " saved successfully" << endl;
			}
			else
			{
				cerr << prefix << "Zone " << zone->name << " save failed!" << endl;
			}
		}
	}
}

void saveModifiedZones(vector<Zone*>& zones, const char* prefix = "")
{
	pthread_mutex_lock(&g_zone_mutex);
	saveModifiedZonesLocked(zones, prefix);
	pthread_mutex_unlock(&g_zone_mutex);
}

void clearExistingZones(vector<Zone*>& zones)
{
	for (vector<Zone*>::iterator it = zones.begin(); it != zones.end(); ++it)
	{
		delete *it;
	}
	zones.clear();
}

bool loadZoneFile(const string& zonefile_path, vector<Zone*>& zones)
{
	vector<string> zonedata;
	
	ifstream zonefile;
	zonefile.open(zonefile_path.c_str());
	
	if (!zonefile.good())
	{
		cerr << "Error: Cannot open zone file: " << zonefile_path << endl;
		return false;
	}
	
	do
	{
		char line[4096];
		if (zonefile.getline(line, sizeof(line)))
		{
			zonedata.push_back(line);
		}
		else
			break;
	} while (true);
	
	if (!ZoneFileLoader::load(zonedata, zones, zonefile_path))
	{
		cerr << "Error loading zones from " << zonefile_path << endl;
		return false;
	}
	cerr << "Zone " << zonefile_path << " loaded" << endl << flush;
	
	return true;
}

void reloadZonesLocked(vector<Zone*>& zones, vector<string>& zonefiles)
{
	cerr << "[SIGHUP] Clearing existing zones..." << endl;
	clearExistingZones(zones);
	
	cerr << "[SIGHUP] Reloading zones from disk..." << endl;
	for (vector<string>::iterator zf_it = zonefiles.begin(); zf_it != zonefiles.end(); ++zf_it)
	{
		if (loadZoneFile(*zf_it, zones))
		{
			cerr << "[SIGHUP] Reloaded zone file: " << *zf_it << endl;
		}
	}
	
	cerr << "[SIGHUP] Zone reload complete. Total zones: " << zones.size() << endl;
}

void handleReloadRequest(vector<Zone*>& zones, vector<string>& zonefiles)
{
	if (!g_reload_zones)
		return;
	
	g_reload_zones = 0;
	
	cerr << "[SIGHUP] Received reload signal" << endl;
	
	pthread_mutex_lock(&g_zone_mutex);
	
	// Save all modified zones before reloading
	cerr << "[SIGHUP] Saving modified zones..." << endl;
	saveModifiedZonesLocked(zones, "[SIGHUP] ");
	
	// Reload all zones
	reloadZonesLocked(zones, zonefiles);
	
	pthread_mutex_unlock(&g_zone_mutex);
}


void serverloop(char **vaddr, vector<Zone *>& zones, vector<string>& zonefiles, int uid, int gid, int port, bool should_daemonize)
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
		cerr << "binding UDP to " << addr << ":" << port << endl;

		if (getaddrinfo(addr, portstr, &hints, &addrinfo))
		{
			cerr << "getaddrinfo failed for " << addr << endl;
			return;
		}

		for (addrinfoi = addrinfo; 
			addrinfoi && addrinfoi->ai_family != PF_INET && addrinfoi->ai_family != PF_INET6;
			addrinfoi = addrinfoi->ai_next);

		if ((udp_s[numSockets] = socket(addrinfoi->ai_family, addrinfoi->ai_socktype, addrinfoi->ai_protocol)) == INVALID_SOCKET)
		{
			cerr << "UDP socket failed " << addr << endl;
			return;
		}

		setnonblock(udp_s[numSockets], 1);

		if (bind(udp_s[numSockets], addrinfoi->ai_addr, static_cast<int>(addrinfoi->ai_addrlen)) == SOCKET_ERROR)
		{
			cerr << "UDP bind failed " << addr << ":" << port << endl;
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
		cerr << "binding TCP to " << addr << ":" << port << endl;

		if (getaddrinfo(addr, portstr, &hints, &addrinfo))
		{
			cerr << "getaddrinfo failed for TCP " << addr << endl;
			return;
		}

		for (addrinfoi = addrinfo;
			addrinfoi && addrinfoi->ai_family != PF_INET && addrinfoi->ai_family != PF_INET6;
			addrinfoi = addrinfoi->ai_next);

		if ((tcp_s[i] = socket(addrinfoi->ai_family, addrinfoi->ai_socktype, addrinfoi->ai_protocol)) == INVALID_SOCKET)
		{
			cerr << "TCP socket failed " << addr << endl;
			return;
		}

		int reuse = 1;
		setsockopt(tcp_s[i], SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
		setnonblock(tcp_s[i], 1);

		if (bind(tcp_s[i], addrinfoi->ai_addr, static_cast<int>(addrinfoi->ai_addrlen)) == SOCKET_ERROR)
		{
			cerr << "TCP bind failed " << addr << ":" << port << endl;
			return;
		}

		if (listen(tcp_s[i], 128) == SOCKET_ERROR)
		{
			cerr << "TCP listen failed " << addr << ":" << port << endl;
			return;
		}

		freeaddrinfo(addrinfo);
	}

	if (should_daemonize)
		daemonize(uid, gid);
	
	// Signal handlers are installed in main()
	
	while (!g_shutdown)
	{
		// Check for reload request
		handleReloadRequest(zones, zonefiles);
		
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
		
		// Use timeout on select so we can check reload flag periodically
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		
		if (0 >= select(static_cast<int>(maxfd + 1), &rdfds, NULL, NULL, &tv))
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
					cerr << "recvfrom failed" << endl;
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
			if (msglen == 0)
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
	
	// Server is shutting down - save all modified zones
	cerr << "[SHUTDOWN] Saving modified zones before exit..." << endl;
	saveModifiedZones(zones);
	cerr << "[SHUTDOWN] Shutdown complete" << endl;
}



int main(int argc, char* argv[])
{
	vector<Zone *> zones;
	vector<string> zonefiles;

	cout << "dnsserver version " << VERSION << endl;
	cout << "OpenSSL version " << OPENSSL_VERSION_TEXT << endl;

	if (argc < 3)
	{
		cerr << "Usage: " << argv[0] << " [-p port] [-u uid] [-g gid] [-d] -z zonefile [-z zonefile2 ...] IP1 [IP2 ...]" << endl;
		return 1;
	}

	// Parse options first
	int uid = -1, gid = -1, port = 53;
	bool should_daemonize = false;
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
		if (argv[arg] == std::string("-d") || argv[arg] == std::string("--daemon")) {
			should_daemonize = true;
			arg += 1;
		} else
		if (argv[arg] == std::string("-z") || argv[arg] == std::string("--zone")) {
			if (arg + 1 >= argc)
			{
				cerr << "Error: -z requires a zone file argument" << endl;
				return 1;
			}
			zonefiles.push_back(argv[arg + 1]);
			arg += 2;
		} else
			break;  // First non-option is IP address
	}

	// Check if we have at least one zone file
	if (zonefiles.empty())
	{
		cerr << "Error: at least one zone file must be specified with -z" << endl;
		return 1;
	}
	
	// Load all zone files
	for (vector<string>::iterator zf_it = zonefiles.begin(); zf_it != zonefiles.end(); ++zf_it)
	{
		if (!loadZoneFile(*zf_it, zones))
		{
			cerr << "[-] error loading zones from " << *zf_it << ", malformed data" << endl;
			return 1;
		}
	}
	
	if (zones.empty())
	{
		cerr << "Error: No zones loaded" << endl;
		return 1;
	}
	
	// Check we have IP addresses
	if (arg >= argc)
	{
		cerr << "Error: No IP addresses specified" << endl;
		return 1;
	}

	// Start background save thread
	pthread_t save_thread;
	if (pthread_create(&save_thread, NULL, zoneSaveThread, &zones) != 0)
	{
		cerr << "Warning: Failed to create auto-save thread" << endl;
	}
	else
	{
		pthread_detach(save_thread);
		cerr << "Auto-save thread started (checking every 5 minutes)" << endl;
	}

	// Install signal handlers
#ifdef LINUX
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighupHandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &sa, NULL);
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigtermHandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	
	cerr << "Signal handlers installed (SIGHUP=reload, SIGTERM/SIGINT=shutdown)" << endl;
#else
	signal(SIGHUP, sighupHandler);
	signal(SIGTERM, sigtermHandler);
	signal(SIGINT, sigtermHandler);
	cerr << "Signal handlers installed" << endl;
#endif

	// IPs start at arg
	serverloop(&argv[arg], zones, zonefiles, uid, gid, port, should_daemonize);
	
	// Cleanup (saveModifiedZones is already called in serverloop on shutdown)
	
	return 0;
}

