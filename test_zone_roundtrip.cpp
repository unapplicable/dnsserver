#include <iostream>
#include <sstream>
#include <cassert>
#include "zone.h"
#include "zoneFileLoader.h"
#include "zoneFileSaver.h"
#include "rr.h"

using namespace std;

int main() {
    cout << "Running zone persistence roundtrip test..." << endl << endl;
    
    // Create test zone data
    vector<string> zone_data;
    zone_data.push_back("$ORIGIN test.example.com.");
    zone_data.push_back("$AUTOSAVE yes");
    zone_data.push_back("test.example.com. IN SOA ns1.test.example.com. admin.test.example.com. 1 3600 1800 604800 86400");
    zone_data.push_back("test.example.com. IN NS ns1.test.example.com.");
    zone_data.push_back("ns1.test.example.com. IN A 192.168.1.1");
    zone_data.push_back("www.test.example.com. IN A 192.168.1.10");
    zone_data.push_back("mail.test.example.com. IN A 192.168.1.20");
    zone_data.push_back("test.example.com. IN MX 10 mail.test.example.com.");
    zone_data.push_back("$ACL 0.0.0.0/0");
    
    // Phase 1: Load zone Z from text
    cout << "[Phase 1] Loading zone Z from text..." << endl;
    vector<Zone*> zones_z;
    if (!ZoneFileLoader::load(zone_data, zones_z, "test_roundtrip.zone"))
    {
        cerr << "ERROR: Failed to load zone Z" << endl;
        return 1;
    }
    
    assert(zones_z.size() == 1);
    Zone* zone_z = zones_z[0];
    cout << "  Zone Z loaded: " << zone_z->name << endl;
    cout << "  Records in Z: " << zone_z->getAllRecords().size() << endl;
    
    // Phase 2: Serialize Z to string
    cout << endl << "[Phase 2] Serializing zone Z to text..." << endl;
    ostringstream serialized;
    ZoneFileSaver::serialize(zone_z, serialized);
    string zone_text = serialized.str();
    cout << "  Serialized length: " << zone_text.length() << " bytes" << endl;
    cout << "  Serialized content:" << endl;
    cout << zone_text << endl;
    
    // Phase 3: Load zone Y from serialized text
    cout << endl << "[Phase 3] Loading zone Y from serialized text..." << endl;
    istringstream iss(zone_text);
    vector<string> zone_data_y;
    string line;
    while (getline(iss, line))
    {
        zone_data_y.push_back(line);
    }
    
    vector<Zone*> zones_y;
    try
    {
        if (!ZoneFileLoader::load(zone_data_y, zones_y, "test_roundtrip_reload.zone"))
        {
            cerr << "ERROR: Failed to load zone Y (returned false)" << endl;
            cerr << "Parsed " << zone_data_y.size() << " lines" << endl;
            for (size_t i = 0; i < zone_data_y.size() && i < 20; i++)
            {
                cerr << "  Line " << i << ": " << zone_data_y[i] << endl;
            }
            return 1;
        }
    }
    catch (const exception& ex)
    {
        cerr << "ERROR: Exception loading zone Y: " << ex.what() << endl;
        return 1;
    }
    
    assert(zones_y.size() == 1);
    Zone* zone_y = zones_y[0];
    cout << "  Zone Y loaded: " << zone_y->name << endl;
    cout << "  Records in Y: " << zone_y->getAllRecords().size() << endl;
    
    // Phase 4: Compare Z and Y
    cout << endl << "[Phase 4] Comparing zones Z and Y..." << endl;
    
    // Compare zone names
    assert(zone_z->name == zone_y->name);
    cout << "  ✓ Zone names match" << endl;
    
    // Compare record counts
    const vector<RR*>& records_z = zone_z->getAllRecords();
    const vector<RR*>& records_y = zone_y->getAllRecords();
    assert(records_z.size() == records_y.size());
    cout << "  ✓ Record counts match: " << records_z.size() << endl;
    
    // Compare each record
    for (size_t i = 0; i < records_z.size(); i++)
    {
        RR* rr_z = records_z[i];
        RR* rr_y = records_y[i];
        
        assert(rr_z->name == rr_y->name);
        assert(rr_z->type == rr_y->type);
        assert(rr_z->rrclass == rr_y->rrclass);
        
        // Compare serialized forms
        string serialized_z = rr_z->toString();
        string serialized_y = rr_y->toString();
        
        if (serialized_z != serialized_y)
        {
            cerr << "ERROR: Record mismatch at index " << i << endl;
            cerr << "  Z: " << rr_z->name << " " << RR::RRTypeToString(rr_z->type) 
                 << " " << serialized_z << endl;
            cerr << "  Y: " << rr_y->name << " " << RR::RRTypeToString(rr_y->type) 
                 << " " << serialized_y << endl;
            return 1;
        }
    }
    cout << "  ✓ All records match" << endl;
    
    // Compare auto_save flag
    assert(zone_z->auto_save == zone_y->auto_save);
    cout << "  ✓ Auto-save flags match" << endl;
    
    // Test actual file save/load
    cout << endl << "[Phase 5] Testing file save/load..." << endl;
    string test_filename = "test_roundtrip_file.zone";
    
    if (!ZoneFileSaver::saveToFile(zone_z, test_filename))
    {
        cerr << "ERROR: Failed to save zone to file" << endl;
        return 1;
    }
    cout << "  ✓ Zone saved to " << test_filename << endl;
    
    // Load from file
    ifstream file_in(test_filename.c_str());
    vector<string> zone_data_file;
    while (getline(file_in, line))
    {
        zone_data_file.push_back(line);
    }
    file_in.close();
    
    vector<Zone*> zones_file;
    if (!ZoneFileLoader::load(zone_data_file, zones_file, test_filename))
    {
        cerr << "ERROR: Failed to load zone from file" << endl;
        return 1;
    }
    
    Zone* zone_file = zones_file[0];
    cout << "  ✓ Zone loaded from file" << endl;
    cout << "  ✓ Records in file: " << zone_file->getAllRecords().size() << endl;
    
    assert(zone_file->getAllRecords().size() == records_z.size());
    
    cout << endl << "========================================" << endl;
    cout << "✅ ALL ROUNDTRIP TESTS PASSED!" << endl;
    cout << "========================================" << endl;
    
    // Cleanup
    for (size_t i = 0; i < zones_z.size(); i++) delete zones_z[i];
    for (size_t i = 0; i < zones_y.size(); i++) delete zones_y[i];
    for (size_t i = 0; i < zones_file.size(); i++) delete zones_file[i];
    
    return 0;
}
