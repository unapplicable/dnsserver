#include "zone_database.h"
#include "rr.h"
#include "rrsoa.h"
#include <algorithm>

using namespace std;

vector<RR*> ZoneDatabase::findRecordsByName(const string& name, RR::RRType type) const
{
    vector<RR*> matches;
    string normalized_name = normalize_dns_name(name);
    
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        string rr_name_normalized = normalize_dns_name(rr->name);
        
        if (rr_name_normalized == normalized_name)
        {
            if (type == RR::RRUNDEF || rr->type == type)
            {
                matches.push_back(rr);
            }
        }
    }
    
    return matches;
}

bool ZoneDatabase::hasRecordWithName(const string& name) const
{
    string normalized_name = normalize_dns_name(name);
    
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        string rr_name_normalized = normalize_dns_name(rr->name);
        
        if (rr_name_normalized == normalized_name)
            return true;
    }
    
    return false;
}

bool ZoneDatabase::hasRecordWithNameAndType(const string& name, RR::RRType type) const
{
    string normalized_name = normalize_dns_name(name);
    
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        string rr_name_normalized = normalize_dns_name(rr->name);
        
        if (rr_name_normalized == normalized_name && rr->type == type)
            return true;
    }
    
    return false;
}

void ZoneDatabase::addRecord(RR* record)
{
    zone_->rrs.push_back(record);
}

int ZoneDatabase::removeRecords(const string& name, RR::RRType type, const string& rdata)
{
    int removed_count = 0;
    string normalized_name = normalize_dns_name(name);
    
    vector<RR*>::iterator it = zone_->rrs.begin();
    while (it != zone_->rrs.end())
    {
        RR* rr = *it;
        string rr_name_normalized = normalize_dns_name(rr->name);
        
        bool name_matches = (rr_name_normalized == normalized_name);
        bool type_matches = (type == RR::RRUNDEF || rr->type == type);
        bool rdata_matches = (rdata.empty() || rr->rdata == rdata);
        
        if (name_matches && type_matches && rdata_matches)
        {
            delete rr;
            it = zone_->rrs.erase(it);
            removed_count++;
        }
        else
        {
            ++it;
        }
    }
    
    return removed_count;
}

RR* ZoneDatabase::findSOARecord() const
{
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        if (rr->type == RR::SOA)
            return rr;
    }
    
    return NULL;
}

