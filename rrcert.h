#ifndef HAVE_RRCERT_H
#define HAVE_RRCERT_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

class RRCERT : public RR
{
	public:		
		virtual void fromStringContents(const std::vector<std::string>& v);
		virtual RR* clone() const { return new RRCERT(*this); }
		virtual ~RRCERT() {};
};

#endif