#include "query_processor.h"

using namespace std;

void QueryProcessor::findMatches(const RR* query_rr,
                                const ZoneDatabase& zonedb,
                                vector<RR*>& matches,
                                RR** ns_record)
{
    const vector<RR*>& all_records = zonedb.getAllRecords();
    
    for (vector<RR*>::const_iterator rriter = all_records.begin(); 
         rriter != all_records.end(); ++rriter)
    {
        RR *rr = *rriter;
        
        // Match by exact name and type, or wildcard type (names already lowercased)
        if ((rr->type == query_rr->type && rr->name == query_rr->name) ||
            (query_rr->type == RR::TYPESTAR && rr->name == query_rr->name))
        {
            matches.push_back(rr);
        }
        else if (rr->type == RR::NS)
        {
            // Check if query name ends with NS record name (subdomain check)
            size_t pos = query_rr->name.rfind(rr->name);
            if (pos != string::npos && pos == query_rr->name.length() - rr->name.length())
            {
                if (ns_record && *ns_record == NULL)
                    *ns_record = rr;
            }
        }
    }
}

