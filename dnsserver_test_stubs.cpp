#include <vector>
#include <string>
#include <fstream>
#include "zone.h"
#include "zoneFileLoader.h"

using namespace std;

// Production code extracted from dnsserver.cpp for testing
bool loadZoneFile(const string& zonefile_path, vector<Zone*>& zones)
{
vector<string> zonedata;

ifstream zonefile;
zonefile.open(zonefile_path.c_str());

if (!zonefile.good())
{
return false;
}

do
{
char line[4096];
if (zonefile.getline(line, sizeof(line)))
{
zonedata.push_back(line);
}
else
break;
} while (true);

if (!ZoneFileLoader::load(zonedata, zones, zonefile_path))
{
return false;
}

return true;
}
