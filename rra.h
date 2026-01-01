#ifndef HAVE_RRA_H
#define HAVE_RRA_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRA : public RR
{
	public:
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v, const std::string& origin = "");
		virtual RR* clone() const { return new RRA(*this); }
		virtual ~RRA() {};
};

#endif