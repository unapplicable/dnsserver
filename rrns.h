#ifndef HAVE_RRNS_H
#define HAVE_RRNS_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRNS : public RR
{
	public:
		virtual bool unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery);
		virtual void packContents(char* data, unsigned int len, unsigned int& offset);
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v, const std::string& origin = "");
		virtual RR* clone() const { return new RRNS(*this); }
		virtual ~RRNS() {};
};

#endif