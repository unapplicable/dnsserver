#ifndef HAVE_RRMX_H
#define HAVE_RRMX_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRMX : public RR
{
	public:
		int pref;

		virtual bool unpack(char* data, unsigned int len, unsigned int& offset, bool isQuery);
		virtual void packContents(char* data, unsigned int len, unsigned int& offset);
		virtual std::ostream& dumpContents(std::ostream& os) const;
		virtual void fromStringContents(const std::vector<std::string>& v);
		virtual RR* clone() const { return new RRMX(*this); }
		virtual ~RRMX() {};
};

#endif