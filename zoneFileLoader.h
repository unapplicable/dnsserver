#ifndef HAVE_ZONEFILELOADER_H
#define HAVE_ZONEFILELOADER_H

#include <string>
#include <vector>

class Zone;

typedef std::vector<std::string> t_data;
typedef std::vector<Zone*> t_zones;

struct ZoneFileLoader
{
	static bool load(const t_data& data, t_zones& zones);
};
#endif