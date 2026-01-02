#ifndef HAVE_ZONEFILESAVER_H
#define HAVE_ZONEFILESAVER_H

#include <string>
#include <iostream>

class Zone;

class ZoneFileSaver
{
public:
	// Save zone to file (atomic with backup)
	static bool saveToFile(Zone* zone, const std::string& filename);
	
	// Serialize zone to stream (public for ACL reuse)
	static void serialize(const Zone* zone, std::ostream& out, bool include_header = true);
	
private:
	static void writeHeader(std::ostream& out, const Zone* zone);
	static void writeDirectives(std::ostream& out, const Zone* zone, bool include_origin);
	static void writeRecords(std::ostream& out, const Zone* zone);
	static void writeACLs(std::ostream& out, const Zone* zone);
};

#endif
