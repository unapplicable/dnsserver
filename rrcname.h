#ifndef HAVE_RRCNAME_H
#define HAVE_RRCNAME_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRCNAME : public RR
{
	public:
		virtual bool unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery);
		virtual void packContents(char* data, unsigned int len, unsigned int& offset);
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v);
		virtual RR* clone() const { return new RRCNAME(*this); }
		virtual ~RRCNAME() {};
};

#endif