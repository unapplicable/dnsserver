#ifndef HAVE_RRDHCID_H
#define HAVE_RRDHCID_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRDHCID : public RR
{
	public:
		std::string identifier;
		virtual void packContents(char* data, unsigned int len, unsigned int& offset);
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v);
		virtual RR* clone() const { return new RRDHCID(*this); }
		virtual ~RRDHCID() {};
};

#endif
