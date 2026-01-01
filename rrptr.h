#ifndef HAVE_RRPTR_H
#define HAVE_RRPTR_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRPTR : public RR
{
	public:
		virtual bool unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery);
		virtual void packContents(char* data, unsigned int len, unsigned int& offset);
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v);
		virtual RR* clone() const { return new RRPTR(*this); }
		virtual ~RRPTR() {};
};

#endif