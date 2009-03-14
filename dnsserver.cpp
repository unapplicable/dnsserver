#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#define TRUE 1

using namespace std;

#define SC(x) case x: return os << #x
#define SC2(x, y) case x: return os << #y;
#define SCC(x) case CODE##x: return os << #x;

enum RRType { RRUNDEF = 0, A = 1, NS, MD, MF, CNAME, SOA, MB, MG, MR,RRNULL,WKS, PTR, HINFO, MINFO, MX, TXT,AAAA = 28, CERT = 37, AXFR = 252, MAILB = 253, MAILA = 254, TYPESTAR = 255 };

ostream& operator <<(ostream& os, const RRType rrt)
{
	switch (rrt) { SC(A); SC(NS); SC(MD); SC(CNAME); SC(SOA); SC(MB); SC(MR); SC2(RRNULL, NULL); SC(WKS);
		SC(PTR); SC(MINFO); SC(MX); SC(TXT); SC(AAAA); SC(CERT); SC(AXFR); SC(MAILB); SC(MAILA); SC2(TYPESTAR, STAR);
		default: return os << "unk(" << std::hex << (unsigned short)rrt << ")"; }
}

enum RRClass { CLASSUNDEF = 0, CLASSIN = 1, CS = 2, CH = 3, HS = 4, CLASSSTAR = 255 };

ostream& operator <<(ostream& os, const RRClass rrc)
{
	switch (rrc) { SC2(CLASSIN, IN); SC(CS); SC(CH); SC(HS); SC2(CLASSSTAR, STAR);
		default: return os << "unk(" << std::hex << (int)rrc << ")"; }
}


enum Opcode {QUERY = 0, IQUERY = 1, STATUS = 2};

ostream& operator <<(ostream& os, const Opcode o)
{
	switch (o) { SC(QUERY); SC(IQUERY); SC(STATUS);
		default: return os << "unk(" << std::hex << (int)o << ")"; }
}

enum RCode {CODENOERROR , CODEFORMATERROR, CODESERVERFAILURE, CODENAMEERROR, CODENOTIMPLEMENTED, CODEREFUSED};

ostream& operator <<(ostream& os, const RCode rc)
{
	switch (rc) { SCC(NOERROR); SCC(FORMATERROR); SCC(SERVERFAILURE); SCC(NAMEERROR); SCC(NOTIMPLEMENTED);
	SCC(REFUSED); default: return os << "unk(" << std::hex << (int)rc << ")"; }
}

char *hextab = (char*)"0123456789ABCDEF";

unsigned char hex2bin(const string& hex)
{
	unsigned char res = 0;
	res |= static_cast<unsigned char>((strchr(hextab, toupper(hex[0])) - hextab)) << 4;
	res |= static_cast<unsigned char>((strchr(hextab, toupper(hex[1])) - hextab));
	return res;
}

string bin2hex(unsigned char bin)
{
	string res;
	res += hextab[bin >> 4 & 0x0F];
	res += hextab[bin & 0x0F];

	return res;
}

string bin2aaaa(const string& in)
{
	string res;
	for (string::size_type i = 0; i < in.length(); i += 2)
	{
		res.append(bin2hex(in[i]));
		res.append(bin2hex(in[i + 1]));	
		res.append(1, ':');
	}

	return res;
}

string bin2a(const string& in)
{
	in_addr adr = *reinterpret_cast<const in_addr*>(in.c_str());
	
	return inet_ntoa(adr);
}

string aaaa2bin(const string& in)
{
	string res;
	for (string::size_type i = 0; i < in.length(); i += 5)
	{
		res.append(1, hex2bin(in.substr(i, 2)));
		res.append(1, hex2bin(in.substr(i + 2, 2)));
	}
	
	return res;
}

string a2bin(const string& in)
{
	string res;
	unsigned long a = inet_addr(in.c_str());
	res.append(reinterpret_cast<char*>(&a), 4);
	return res;
}

class RR
{
public:
	string name;
	RRType type;
	RRClass rrclass;
	bool query;
	unsigned long ttl;
	unsigned short rdlen;
	string rdata;

	bool unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery);
	void pack(char *data, unsigned int len, unsigned int& offset);
	~RR();
};

struct Subnet
{
	unsigned long ip;
	unsigned long mask;
	bool match(unsigned long ip) const
	{
		return (ip & mask) == (this->ip & mask);
	}

	Subnet(string str)
	{
		long smask;
		string::size_type s;
		if ((s = str.find('/')) != string::npos)
		{
			smask = atoi(str.substr(s + 1).c_str());
			ip = inet_addr(str.substr(0, s).c_str());
		} else
		{
			smask = 32;
			ip = inet_addr(str.c_str());
		}
		mask = 0;
		for (int i = 31; i >= 32 - smask; --i)
			mask |= 1 << i;

		mask = htonl(mask);
	}
};

class Zone;

struct AclEntry
{
	Subnet subnet;
	Zone* zone;
};

class Zone
{
	public:
		string name;
		vector<AclEntry> acl;
		vector<RR *> rrs;
};

ostream& operator <<(ostream& os, const RR& r)
{
	os << r.rrclass << " " << r.type << " " << r.name;
	if (r.query)
		return os;

	os << " = ";

	switch (r.type)
	{
		case CNAME:
		case PTR:
		case TXT:
		{
			os << r.rdata;
			break;
		}

		case MX:
		{
			
			os << std::dec << 10 << " " << r.rdata;			
			break;
		}

		case A:
		{
			os << bin2a(r.rdata);
			break;
		}

		case AAAA:
		{
			os << bin2aaaa(r.rdata);
			break;
		}

		default:
			for (int i = 0; i < r.rdata.length(); ++i)
				os << std::hex << (unsigned char)r.rdata[i] << " ";
			break;
	}

	return os << " (ttl:" << r.ttl << ")";
}


class Message
{
public:
	unsigned short id;
	bool query;
	Opcode opcode;
	bool authoritative;
	bool truncation;
	bool recursiondesired;
	bool recursionavailable;
	RCode rcode;
	vector<RR *> qd, an, ns, ar;

	bool unpack(char *data, unsigned int len, unsigned int& offset);
	void pack(char *data, unsigned int len, unsigned int& offset) const;
	Message() 
	{
	}
	~Message();
};

ostream& operator <<(ostream& os, const Message& m)
{
	os << hex << m.id << " " << (m.query ? "Q" : "q") << " " << m.opcode << " " << (m.authoritative ? "A" : "a") <<
		(m.truncation ? "T" : "t") << (m.recursiondesired ? "RD" : "rd") << (m.recursionavailable ? "RA" : "ra") <<
		" " << m.rcode;

	for (int rrtype = 0; rrtype < 4; rrtype++)
	{
		vector<RR *> rrs[4] = {(m.qd), (m.an), (m.ns), (m.ar)};

		bool first = true;
		for (unsigned short i = 0; i < rrs[rrtype].size(); i++)
		{
			if (first)
			{
				os << "[ ";
				first = false;
			}
			os << *(rrs[rrtype][i]);
			if (i == rrs[rrtype].size() - 1)
				os << " ]";
			os << "\n";
		}
	}

	return os;
}

void packName(char *data, unsigned int len, unsigned int& offset, string name, bool terminate = true)
{
	string part;
	do
	{
		size_t dot;
		if ((dot = name.find('.')) != -1)
		{
			part = name.substr(0, dot);
			name.erase(0, dot + 1);
		} else
		{
			part = name;
			name.clear();
		};

		if (terminate || !part.empty())
		{
			data[offset++] = (unsigned char)part.length();
			part.copy(&data[offset], part.length());
			offset += (unsigned int)part.length();
		}
		
	} while (!part.empty());
}

RR::~RR()
{
}

void RR::pack(char *data, unsigned int len, unsigned int& offset)
{
	packName(data, len, offset, name);

	(unsigned short&)data[offset] = htons(type);
	offset += 2;

	(unsigned short&)data[offset] = htons(rrclass);
	offset += 2;

	if (query)
		return;

	(unsigned long&)data[offset] = htonl(ttl);
	offset += 4;

	rdlen = rdata.length();
	(unsigned short&)data[offset] = htons(rdlen);
	offset += 2;

	switch (type)
	{
		case CNAME:
		case PTR:		
		{
			unsigned int oldoffset = offset - 2;
			packName(data, len, offset, rdata);
			unsigned int packedrdlen = offset - (oldoffset + 2);
			(unsigned short&)data[oldoffset] = htons(packedrdlen);
			break;
		}

		case TXT:
		{
			unsigned int oldoffset = offset - 2;
			packName(data, len, offset, rdata, false);
			unsigned int packedrdlen = offset - (oldoffset + 2);
			(unsigned short&)data[oldoffset] = htons(packedrdlen);
			break;
		}

		case MX:
		{
			unsigned int oldoffset = offset - 2;
			(unsigned short&)data[offset] = htons(10);
			offset += 2;
			packName(data, len, offset, rdata);
			unsigned int packedrdlen = offset - (oldoffset + 2);
			(unsigned short&)data[oldoffset] = htons(packedrdlen);
			break;
		}

		default:
			rdata.copy(&data[offset], rdlen);
			offset += rdlen;
			break;
	}
}

string unpackName(char *data, unsigned int len, unsigned int& offset)
{
	string name;
	unsigned int& iter = offset;
	bool packed = false;
	

	for (unsigned int i = iter; ;)
	{
		if (i >= len)
			throw exception();

		unsigned char tokencode = (unsigned char)data[i];
		if ((tokencode & 0xC0) != 0)
		{
			i = ntohs((unsigned short &)data[i]) & ~0xC000;
			iter += 2;
			packed = true;
			continue;
		} else
		{
			i++;
			if (!packed)
				iter = i;
		}

		if (tokencode == 0)
			break;

		if (i + tokencode >= len)
			throw exception();

		if (!name.empty())
			name += '.';

		name.append(data + i, tokencode);
		

		i += tokencode;
		if (!packed)
			iter = i;
	}

	return name;
}

bool RR::unpack(char *data, unsigned int len, unsigned int& offset, bool isQuery)
{
	query = isQuery;
	name.clear();

	name = unpackName(data, len, offset);

	if (offset + 1 >= len)
		return false;

	type = (RRType)ntohs((short &)data[offset]);
	offset += 2;

	if (offset + 1 >= len)
		return false;

	rrclass = (RRClass)ntohs((short &)data[offset]);
	offset += 2;

	if (query)
	{
		ttl = 0;
		rdlen = 0;
		rdata.clear();
		return true;
	}

	if (offset + 3 >= len)
		return false;

	ttl = ntohl((long &)data[offset]);
	offset += 4;

	if (offset + 1 >= len)
		return false;

	rdlen = ntohs((short &)data[offset]);
	offset += 2;

	if (offset + rdlen > len)
		return false;

	rdata.clear();
	rdata.append(data + offset, rdlen);
	
	offset += rdlen;
	return true;
}


Message::~Message()
{
	for (int rrtype = 0; rrtype < 4; ++rrtype)
	{
		vector<RR *>* rrs[] = {&qd, &an, &ns, &ar};

		for (vector<RR *>::iterator it = rrs[rrtype]->begin();
			it != rrs[rrtype]->end();
			++it)
		{
			delete *it;
		}
	}
}

bool Message::unpack(char *data, unsigned int len, unsigned int& offset)
{
	unsigned int& iter = offset;

	if (iter + 1 >= len)
		return false;

	id = ntohs((unsigned short &)data[iter]);
	iter += 2;

	if (iter + 1 >= len)
		return false;

	unsigned short flags = ntohs((unsigned short &)data[iter]);
	iter += 2;

	query = (flags & 0x0001) == 0;
	opcode = (Opcode)((flags & 0x000E) >> 1);
	authoritative = (flags & 0x0020) != 0;
	truncation = (flags & 0x0040) != 0;
	recursiondesired = (flags & 0x0080) != 0;
	recursionavailable = (flags & 0x0100) != 0;
	rcode = (RCode)((flags & 0xF000) >> 12);

	if (iter + 2 * 4 > len)
		return false;

	unsigned short counts[] = {0, 0, 0, 0};

	counts[0] = ntohs((unsigned short &)data[iter]);
	iter += 2;
	counts[1] = ntohs((unsigned short &)data[iter]);
	iter += 2;
	counts[2] = ntohs((unsigned short &)data[iter]);
	iter += 2;
	counts[3] = ntohs((unsigned short &)data[iter]);
	iter += 2;

	for (int rrtype = 0; rrtype < 4; rrtype++)
	{
		
		vector<RR *>* rrs[] = {&qd, &an, &ns, &ar};

		for (unsigned short i = 0; i < counts[rrtype]; i++)
		{
			RR *r = new RR();
			if (!r->unpack(data, len, iter, query && rrtype == 0))
			{
				delete r;
				return false;
			}

			rrs[rrtype]->push_back(r);
		}
	}

	return true;
}

void Message::pack(char *data, unsigned int len, unsigned int& offset) const
{
	offset = 0;

	(unsigned short &)data[offset] = htons(id);
	offset += 2;

	unsigned short flags = 0;
	flags |= (query == false) << 15;
	flags |= (opcode & 0x07) << 11;
	flags |= authoritative << 10;
	flags |= truncation ? 0x0200 : 0; 
	flags |= recursiondesired ? 0x0100 : 0;
	flags |= recursionavailable ? 0x0080 : 0;
	flags |= (rcode & 0x0F);
	
	(unsigned short &)data[offset] = htons(flags);
	offset += 2;

	(unsigned short &)data[offset] = htons(qd.size());
	offset += 2;

	(unsigned short &)data[offset] = htons(an.size());
	offset += 2;

	(unsigned short &)data[offset] = htons(ns.size());
	offset += 2;

	(unsigned short &)data[offset] = htons(ar.size());
	offset += 2;

	for (int rrtype = 0; rrtype < 4; rrtype++)
	{
		const vector<RR *>* rrs[] = {&qd, &an, &ns, &ar};

		for (unsigned short i = 0; i < rrs[rrtype]->size(); i++)
			rrs[rrtype]->at(i)->pack(data, len, offset);			
	}
}

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

typedef int SOCKET;
typedef struct hostent HOSTENT;
typedef struct sockaddr_in6 SOCKADDR_STORAGE;
typedef struct addrinfo ADDRINFO;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1

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
	if (msgtest->query && msgtest->opcode == QUERY)
	{
		if (msgtest->qd.size() == 1 && msgtest->qd[0])
		{
			const RR *qrr = msgtest->qd[0];
			vector<Zone *>::const_iterator ziter;
			for (ziter = zones.begin(); ziter != zones.end(); ++ziter)
			{
				const Zone *z = *ziter;

				string qrrlower(qrr->name), zlower(z->name);
				std::transform(qrrlower.begin(), qrrlower.end(), qrrlower.begin(), (int (*)(int))std::tolower);
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
				reply->opcode = QUERY;
				reply->qd.push_back(new RR(*qrr));
				reply->truncation = false;
				reply->query = false;
				reply->authoritative = true;
				reply->rcode = CODENOERROR;
				reply->recursionavailable = reply->recursiondesired = msgtest->recursiondesired;

				vector<RR *>::const_iterator rriter;
				for (rriter = z->rrs.begin(); rriter != z->rrs.end(); ++rriter)
				{
					RR *rr = *rriter;


					if (
						(rr->type == qrr->type && 
						0 == rr->name.compare(0, qrrlower.length(), qrrlower)
						) ||
						(qrr->type == TYPESTAR)
						)
					{
						RR *arr = new RR(*rr);
						arr->query = false;												
						
						arr->ttl = 10 * 60; // 10 minutes
												
						reply->an.push_back(arr);

						if (qrr->type != TYPESTAR)
							break;
					}
				}
				
				break;
			}

			if (reply == NULL || reply->an.size() == 0)
			{
				reply = new Message();
				reply->id = msgtest->id;
				reply->opcode = QUERY;
				reply->qd.push_back(new RR(*qrr));
				reply->truncation = false;
				reply->query = false;
				reply->authoritative = true;
				reply->recursionavailable = reply->recursiondesired = msgtest->recursiondesired;
				reply->rcode = CODENAMEERROR;
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

int setnonblock(int sockfd, int nonblock)
{
	int flags;
	flags = fcntl(sockfd, F_GETFL, 0);
	if (TRUE == nonblock)
		return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	else
		return fcntl(sockfd, F_SETFL, flags & (~O_NONBLOCK));
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

		if (bind(s[numSockets], addrinfoi->ai_addr, addrinfoi->ai_addrlen) == SOCKET_ERROR)
		{
			fprintf(stderr, "bind failed %s:%d\n", addr, port);
			return;
		}

		freeaddrinfo(addrinfo);
	}

	setreuid(1000, 1000);
	setregid(1000, 1000);

	if (fork() != 0)
		exit(1);

	while (true)
	{
		char buf[0xFFFF] = {0};
		char hostname[NI_MAXHOST] = {0x41};
		sockaddr_in6 from;
		socklen_t fromlen;
		fd_set rdfds;
		int maxfd = 0;

		FD_ZERO(&rdfds);
		for (int i = 0; i < numSockets; ++i)
		{
			FD_SET(s[i], &rdfds);
			maxfd = max(maxfd, s[i]);
		}
		
		if (0 >= select(maxfd + 1, &rdfds, NULL, NULL, NULL))
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
				int wsaerr = errno;
				if (wsaerr == EAGAIN)
				{
				} else
				{
					fprintf(stderr, "recvfrom failed %08X %d\n", wsaerr, wsaerr);
				}
				continue;
			}

			if (getnameinfo((sockaddr *)&from, fromlen, hostname, sizeof(hostname), NULL, 0, NI_NUMERICHOST))
				strcpy(hostname, "unknown");

			handle(s[i], buf, numrecv, hostname, &from, fromlen, zones);
		}
	}
}

typedef vector<string> t_data;
typedef vector<Zone*> t_zones;

bool loadZones(const t_data& data, t_zones& zones)
{
	Zone* z = NULL;
	Zone* parent = NULL;
	for (t_data::const_iterator di = data.begin(); di != data.end(); ++di)
	{
		// strip comments
		string line = *di;
		
		string::size_type cmtpos;
		if ((cmtpos = line.find(';')) != string::npos)
			line.erase(cmtpos);
		// tokenize
		vector<string> tokens;
		while (line.length() != 0)
		{
			// find sep
			string::size_type seppos = line.find_first_of(" \t");
			tokens.push_back(line.substr(0, seppos));
			string::size_type nextpos = line.find_first_not_of(" \t", seppos);
			line.erase(0, nextpos);
		};

		if (tokens.size() < 2)
			continue;

		if (tokens[0] == "$ORIGIN")
		{
			if (parent != NULL)
			{
				zones.push_back(parent);
				parent = NULL;
			}
			z = new Zone();
			parent = z;
			z->name = tokens[1];
			continue;
		} else
		if (tokens[0] == "$ACL")
		{
			Zone* acl = new Zone();
			acl->name = parent->name;
			for (int i = 1; i < tokens.size(); ++i)
			{
				AclEntry e = {Subnet(tokens[i]), acl};
				parent->acl.push_back(e);
			}

			z = acl;
			continue;
		}

		RRClass rrclass;
		if (tokens[1] == "IN")
			rrclass = CLASSIN;
		else
		if (tokens[1] == "CH")
			rrclass = CH;
		else
		if (tokens[1] == "*")
			rrclass = CLASSSTAR;
		else
			rrclass = CLASSUNDEF;

		RRType rrtype;
		if (tokens[2] == "MX")
			rrtype = MX;
		else
		if (tokens[2] == "A")
			rrtype = A;
		else
		if (tokens[2] == "AAAA")
			rrtype = AAAA;
		else
		if (tokens[2] == "CERT")
			rrtype = CERT;
		else
		if (tokens[2] == "CNAME")
			rrtype = CNAME;
		else
		if (tokens[2] == "NS")
			rrtype = NS;
		else
		if (tokens[2] == "PTR")
			rrtype = PTR;
		else
		if (tokens[2] == "TXT")
			rrtype = TXT;
		else
			rrtype = RRUNDEF;

		RR* rr = NULL;
		switch (rrtype)
		{
			case MX:
				rr = new RR();
				rr->rdata = tokens[4];
				break;

			case PTR:
			case CNAME:
			case NS:
				rr = new RR();
				rr->rdata = tokens[3];
				break;
		
			case AAAA:
				rr = new RR();
				rr->rdata = aaaa2bin(tokens[3]);
				break;
			
			case A:
				rr = new RR();
				rr->rdata = a2bin(tokens[3]);
				break;

			case TXT:
				rr = new RR();
				for (int i = 3; i < tokens.size(); ++i)
					rr->rdata += (i != 3 ? " " : "" )+ tokens[i];
				break;

			case CERT:
				rr = new RR();
				rr->rdata.append("\x01\x00\x00\x00\x00", 5);
				for (int i = 0; i < tokens[3].length(); i += 2)
					rr->rdata += hex2bin(tokens[3].substr(i, 2));
				break;

			default:
				break;
		}

		if (rr != NULL)
		{
			rr->rrclass = rrclass;
			rr->type = rrtype;
			rr->name = tokens[0];
			if (tokens[0][tokens[0].length() - 1] != '.')
				rr->name = tokens[0] + "." + z->name + ".";
			else
				rr->name = tokens[0];
		}

		if (rr != NULL && z == NULL)
			return false;

		if (rr != NULL)
		{
			z->rrs.push_back(rr);
			rr = NULL;
		}
	}

	// add last zone
	if (parent != NULL)
	{
		zones.push_back(parent);
	}

	return true;
}

int main(int argc, char* argv[])
{
	vector<Zone *> zones;
	vector<string> zonedata;

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
	
	if (!loadZones(zonedata, zones))
	{
		cerr << "[-] error loading zones, malformed data" << endl;
		return 0;
	}

	serverloop(&argv[2], zones);
	return 0;
}

