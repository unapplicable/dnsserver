#ifndef HAVE_RRDYNAMIC_H
#define HAVE_RRDYNAMIC_H

#include <string>
#include <vector>
#include <iostream>

#include "rr.h"

// RRDYNAMIC: A special RR type for ACME challenges and other dynamic content
// Stores a file path and reads it on each query to generate TXT records
// Each non-empty line in the file becomes a separate TXT record
class RRDYNAMIC : public RR
{
public:
	std::string filepath;  // Path to the dynamic content file
	
	// Dynamic records are never packed into responses directly
	// They are resolved to TXT records at query time
	virtual void packContents(char* data, unsigned int len, unsigned int& offset);
	virtual std::ostream& dumpContents(std::ostream& os) const;
	virtual std::string toString() const;
	virtual void fromStringContents(const std::vector<std::string>& v, const std::string& origin = "");
	virtual RR* clone() const { return new RRDYNAMIC(*this); }
	virtual ~RRDYNAMIC() {};
	
	// Read file and return TXT records for the current name
	std::vector<RR*> resolveTXT() const;
};

#endif
