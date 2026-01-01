#include "zone.h"
#include "rr.h"
#include "rrsoa.h"
#include <algorithm>

using namespace std;

vector<RR*> Zone::findRecordsByName(const string& name, RR::RRType type) const
{
    vector<RR*> matches;
    
    for (vector<RR*>::const_iterator it = rrs.begin(); it != rrs.end(); ++it)
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

bool Zone::hasRecordWithName(const string& name) const
{
    for (vector<RR*>::const_iterator it = rrs.begin(); it != rrs.end(); ++it)
    {
        RR* rr = *it;
        
        if (rr->name == name)
            return true;
    }
    
    return false;
}

bool Zone::hasRecordWithNameAndType(const string& name, RR::RRType type) const
{
    for (vector<RR*>::const_iterator it = rrs.begin(); it != rrs.end(); ++it)
    {
        RR* rr = *it;
        
        if (rr->name == name && rr->type == type)
            return true;
    }
    
    return false;
}

void Zone::addRecord(RR* record)
{
    rrs.push_back(record);
}

int Zone::removeRecords(const string& name, RR::RRType type, const string& rdata)
{
    int removed_count = 0;
    
    vector<RR*>::iterator it = rrs.begin();
    while (it != rrs.end())
    {
        RR* rr = *it;
        
        bool name_matches = (rr->name == name);
        bool type_matches = (type == RR::RRUNDEF || rr->type == type);
        bool rdata_matches = (rdata.empty() || rr->rdata == rdata);
        
        if (name_matches && type_matches && rdata_matches)
        {
            delete rr;
            it = rrs.erase(it);
            removed_count++;
        }
        else
        {
            ++it;
        }
    }
    
    return removed_count;
}

RR* Zone::findSOARecord() const
{
    for (vector<RR*>::const_iterator it = rrs.begin(); it != rrs.end(); ++it)
    {
        RR* rr = *it;
        if (rr->type == RR::SOA)
            return rr;
    }
    
    return NULL;
}

bool Zone::incrementSerial()
{
    for (vector<RR*>::iterator it = rrs.begin(); it != rrs.end(); ++it)
    {
        RR* rr = *it;
        if (rr->type == RR::SOA)
        {
            RRSoa* soa = dynamic_cast<RRSoa*>(rr);
            if (soa)
            {
                soa->serial++;
                return true;
            }
        }
    }
    
    return false;
}
