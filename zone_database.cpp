#include "zone_database.h"
#include "rr.h"
#include "rrsoa.h"
#include <algorithm>

using namespace std;

vector<RR*> ZoneDatabase::findRecordsByName(const string& name, RR::RRType type) const
{
    vector<RR*> matches;
    
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        
        if (rr->name == name)
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
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        
        if (rr->name == name)
            return true;
    }
    
    return false;
}

bool ZoneDatabase::hasRecordWithNameAndType(const string& name, RR::RRType type) const
{
    for (vector<RR*>::const_iterator it = zone_->rrs.begin(); it != zone_->rrs.end(); ++it)
    {
        RR* rr = *it;
        
        if (rr->name == name && rr->type == type)
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
    
    vector<RR*>::iterator it = zone_->rrs.begin();
    while (it != zone_->rrs.end())
    {
        RR* rr = *it;
        
        bool name_matches = (rr->name == name);
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

