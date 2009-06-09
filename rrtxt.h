#ifndef HAVE_RRTXT_H
#define HAVE_RRTXT_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRTXT : public RR
{
	public:
		virtual void packContents(char* data, unsigned int len, unsigned int& offset);
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v);
		virtual RR* clone() const { return new RRTXT(*this); }
		virtual ~RRTXT() {};
};

#endif