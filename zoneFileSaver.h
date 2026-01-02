#ifndef HAVE_ZONEFILESAVER_H
#define HAVE_ZONEFILESAVER_H

#include <string>
#include <iostream>

class Zone;

class ZoneFileSaver
{
public:
	// Save zone to file (atomic with backup)
	static bool saveToFile(const Zone* zone, const std::string& filename);
	
	// Serialize zone to stream
	static void serialize(const Zone* zone, std::ostream& out);
	
private:
	static void writeHeader(std::ostream& out, const Zone* zone);
	static void writeDirectives(std::ostream& out, const Zone* zone);
	static void writeRecords(std::ostream& out, const Zone* zone);
	static void writeACL(std::ostream& out, const Zone* zone);
};

#endif
