#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <unistd.h>
#include <cassert>
#include "zone.h"
#include "zoneFileLoader.h"
#include "zoneFileSaver.h"
#include "rrsoa.h"
#include "rra.h"
#include "acl.h"

using namespace std;

// Forward declaration of production code function from dnsserver.cpp
bool loadZoneFile(const string& zonefile_path, vector<Zone*>& zones);

void test_zone_autosave_flag()
{
	cout << "TEST_CASE: Zone auto-save flag parsing from file" << endl;
	
	// Create test zone file with autosave enabled
	const char* autosave_file = "test_autosave_flag.zone";
	ofstream outfile(autosave_file);
	assert(outfile.good());
	outfile << "$ORIGIN test.com." << endl;
	outfile << "$AUTOSAVE yes" << endl;
	outfile << "test.com. IN SOA ns1.test.com. admin.test.com. 1 3600 1800 604800 86400" << endl;
	outfile << "test.com. IN NS ns1.test.com." << endl;
	outfile.close();
	
	// Load using production code (loadZoneFile from dnsserver.cpp)
	vector<Zone*> zones;
	assert(loadZoneFile(autosave_file, zones) && "Zone should load successfully");
	assert(zones.size() == 1 && "Should have one zone");
	assert(zones[0]->auto_save == true && "Autosave flag should be true");
	
	// Verify modified flag behavior
	zones[0]->recordUpdate();
	assert(zones[0]->modified && "Zone should be marked as modified");
	
	// Save and verify clearing of modified flag (production code path)
	bool saved = ZoneFileSaver::saveToFile(zones[0], zones[0]->filename);
	assert(saved && "Zone should save successfully");
	zones[0]->clearModified();
	assert(!zones[0]->modified && "Zone should not be modified after save");
	
	// Cleanup
	for (size_t i = 0; i < zones.size(); i++)
		delete zones[i];
	remove(autosave_file);
	
	// Test default (no autosave flag = false)
	const char* no_autosave_file = "test_no_autosave_flag.zone";
	ofstream outfile2(no_autosave_file);
	assert(outfile2.good());
	outfile2 << "$ORIGIN test2.com." << endl;
	outfile2 << "test2.com. IN SOA ns1.test2.com. admin.test2.com. 1 3600 1800 604800 86400" << endl;
	outfile2.close();
	
	zones.clear();
	assert(loadZoneFile(no_autosave_file, zones) && "Zone should load successfully");
	assert(zones.size() == 1 && "Should have one zone");
	assert(zones[0]->auto_save == false && "Default autosave flag should be false");
	
	// Cleanup
	for (size_t i = 0; i < zones.size(); i++)
		delete zones[i];
	remove(no_autosave_file);
	
	cout << "  PASSED" << endl;
}

void test_zone_modified_after_update()
{
	cout << "TEST_CASE: Zone marked modified after record update" << endl;
	
	Zone* zone = new Zone();
	zone->name = "test.com.";
	zone->filename = "test_modified.zone";
	zone->auto_save = true;
	zone->modified = false;
	
	// Add initial record
	RRSoa* soa = new RRSoa();
	soa->name = "test.com.";
	soa->type = RR::SOA;
	soa->rrclass = RR::CLASSIN;
	soa->ttl = 3600;
	soa->rdata = "ns1.test.com. admin.test.com. 1 3600 1800 604800 86400";
	zone->addRecord(soa);
	
	assert(!zone->modified && "Zone should not be modified initially");
	
	// Mark as modified (simulating an update operation)
	zone->recordUpdate();
	
	assert(zone->modified && "Zone should be modified after recordUpdate()");
	
	// Save and verify it clears the flag
	ZoneFileSaver::saveToFile(zone, zone->filename);
	zone->clearModified();  // Caller's responsibility (as in dnsserver.cpp)
	assert(!zone->modified && "Zone should not be modified after save");
	
	// Cleanup
	remove(zone->filename.c_str());
	delete zone;
	
	cout << "  PASSED" << endl;
}

void test_zone_reload_from_file()
{
	cout << "TEST_CASE: Zone reload from file preserves data" << endl;
	
	// Create test zone file
	string filename = "test_reload.zone";
	ofstream out(filename.c_str());
	out << "$ORIGIN test.com." << endl;
	out << "$TTL 3600" << endl;
	out << "@ IN SOA ns1.test.com. admin.test.com. 1 3600 1800 604800 86400" << endl;
	out << "@ IN A 192.168.1.1" << endl;
	out << "www IN A 192.168.1.2" << endl;
	out.close();
	
	// Load zone
	vector<string> zonedata;
	ifstream in(filename.c_str());
	string line;
	while (getline(in, line))
	{
		zonedata.push_back(line);
	}
	in.close();
	
	vector<Zone*> zones;
	bool loaded = ZoneFileLoader::load(zonedata, zones, filename);
	assert(loaded && "Zone should load successfully");
	assert(zones.size() == 1 && "Should have one zone");
	
	Zone* zone = zones[0];
	assert(zone->name == "test.com." && "Zone name should match");
	assert(zone->getAllRecords().size() >= 3 && "Should have at least 3 records");
	
	// Verify we can save and reload
	zone->recordUpdate();
	ZoneFileSaver::saveToFile(zone, zone->filename);
	
	// Reload from saved file
	zonedata.clear();
	ifstream reload(zone->filename.c_str());
	while (getline(reload, line))
	{
		zonedata.push_back(line);
	}
	reload.close();
	
	vector<Zone*> reloaded_zones;
	loaded = ZoneFileLoader::load(zonedata, reloaded_zones, filename);
	assert(loaded && "Reloaded zone should load successfully");
	assert(reloaded_zones.size() == 1 && "Should have one reloaded zone");
	
	Zone* reloaded = reloaded_zones[0];
	assert(reloaded->name == zone->name && "Reloaded zone name should match");
	assert(reloaded->getAllRecords().size() == zone->getAllRecords().size() && "Record count should match");
	
	// Cleanup
	remove(filename.c_str());
	for (size_t i = 0; i < zones.size(); i++)
		delete zones[i];
	for (size_t i = 0; i < reloaded_zones.size(); i++)
		delete reloaded_zones[i];
	
	cout << "  PASSED" << endl;
}

void test_acl_zone_serialization()
{
	cout << "TEST_CASE: ACL zones serialize with $ACL headers" << endl;
	
	// Create test zone file with ACL
	string filename = "test_acl_serialize.zone";
	ofstream out(filename.c_str());
	out << "$ORIGIN test.com." << endl;
	out << "$TTL 3600" << endl;
	out << "@ IN SOA ns1.test.com. admin.test.com. 1 3600 1800 604800 86400" << endl;
	out << "@ IN A 192.168.1.1" << endl;
	out << "$ACL 192.168.1.0/24" << endl;
	out << "internal IN A 10.0.0.1" << endl;
	out.close();
	
	// Load zone
	vector<string> zonedata;
	ifstream in(filename.c_str());
	string line;
	while (getline(in, line))
	{
		zonedata.push_back(line);
	}
	in.close();
	
	vector<Zone*> zones;
	bool loaded = ZoneFileLoader::load(zonedata, zones, filename);
	assert(loaded && "Zone should load successfully");
	assert(zones.size() == 1 && "Should have one zone");
	
	Zone* zone = zones[0];
	assert(zone->acl && "Zone should have ACL");
	assert(zone->acl->size() == 1 && "ACL should have one entry");
	
	// Save and verify ACL is preserved
	zone->recordUpdate();
	bool saved = ZoneFileSaver::saveToFile(zone, filename + ".out");
	assert(saved && "Zone should save successfully");
	
	// Reload and verify ACL structure
	zonedata.clear();
	ifstream reload((filename + ".out").c_str());
	while (getline(reload, line))
	{
		zonedata.push_back(line);
	}
	reload.close();
	
	vector<Zone*> reloaded_zones;
	loaded = ZoneFileLoader::load(zonedata, reloaded_zones, filename + ".out");
	assert(loaded && "Reloaded zone should load successfully");
	
	Zone* reloaded = reloaded_zones[0];
	assert(reloaded->acl && "Reloaded zone should have ACL");
	assert(reloaded->acl->size() == 1 && "Reloaded ACL should have one entry");
	
	// Cleanup
	remove(filename.c_str());
	remove((filename + ".out").c_str());
	for (size_t i = 0; i < zones.size(); i++)
		delete zones[i];
	for (size_t i = 0; i < reloaded_zones.size(); i++)
		delete reloaded_zones[i];
	
	cout << "  PASSED" << endl;
}

int main()
{
	cout << "Running SIGHUP unit tests..." << endl << endl;
	
	test_zone_autosave_flag();
	test_zone_modified_after_update();
	test_zone_reload_from_file();
	test_acl_zone_serialization();
	
	cout << endl << "All tests passed!" << endl;
	return 0;
}
