#ifndef HAVE_ZONEFILELOADER_H
#define HAVE_ZONEFILELOADER_H

#include <string>
#include <vector>

class Zone;

typedef std::vector<std::string> t_data;
typedef std::vector<Zone*> t_zones;

struct ZoneFileLoader
{
	static bool load(const t_data& data, t_zones& zones, const std::string& filename = "");
	
private:
	static std::string stripComments(const std::string& line);
	static std::vector<std::string> tokenize(const std::string& line);
	static void handleOrigin(const std::vector<std::string>& tokens, Zone*& parent, Zone*& current, t_zones& zones, std::string& previousName);
	static void handleACL(const std::vector<std::string>& tokens, Zone* parent, Zone*& current);
	static void handleAutoSave(const std::vector<std::string>& tokens, Zone* parent);
	static void handleTSIG(const std::vector<std::string>& tokens, Zone* parent);
	static void handleResourceRecord(const std::vector<std::string>& tokens, Zone* current, std::string& previousName);
};
#endif