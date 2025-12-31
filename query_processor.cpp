#include "query_processor.h"

using namespace std;

void QueryProcessor::findMatches(const RR* query_rr,
                                const ZoneDatabase& zonedb,
                                vector<RR*>& matches,
                                RR** ns_record)
{
    string qrr_name = query_rr->name;
    const vector<RR*>& all_records = zonedb.getAllRecords();
    
    for (vector<RR*>::const_iterator rriter = all_records.begin(); 
         rriter != all_records.end(); ++rriter)
    {
        RR *rr = *rriter;
        string rr_name = rr->name;
        
        // Match by type and name prefix
        if ((rr->type == query_rr->type && 
             0 == rr_name.compare(0, qrr_name.length(), qrr_name)) ||
            (query_rr->type == RR::TYPESTAR))
        {
            matches.push_back(rr);
            
            if (query_rr->type != RR::TYPESTAR)
                break;
        }
        else if (rr->type == RR::NS && 
                 0 == rr_name.compare(0, qrr_name.length(), qrr_name))
        {
            if (ns_record && *ns_record == NULL)
                *ns_record = rr;
        }
    }
}

