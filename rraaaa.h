#ifndef HAVE_RRAAAA_H
#define HAVE_RRAAAA_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRAAAA : public RR
{
	public:
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v, const std::string& origin = "");
		virtual RR* clone() const { return new RRAAAA(*this); }
		virtual ~RRAAAA() {};
};

#endif