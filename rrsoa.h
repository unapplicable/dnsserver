#ifndef HAVE_RRSOA_H
#define HAVE_RRSOA_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRSoa : public RR
{
public:
std::string ns;
std::string mail;
unsigned long serial;
unsigned long refresh;
unsigned long retry;
unsigned long expire;
unsigned long minttl;

virtual bool unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery);
virtual void packContents(char* data, unsigned int len, unsigned int& offset);
virtual std::ostream& dumpContents(std::ostream& os) const;
virtual std::string toString() const;
virtual void fromStringContents(const std::vector<std::string>& v, const std::string& origin = "");
virtual RR* clone() const { return new RRSoa(*this); }
virtual ~RRSoa() {}
};

#endif
