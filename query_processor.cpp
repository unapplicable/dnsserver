#include "query_processor.h"
#include "rrdynamic.h"

using namespace std;

void QueryProcessor::findMatches(const RR* query_rr,
                                const Zone& zone,
                                vector<RR*>& matches,
                                RR** ns_record,
                                vector<RR*>* dynamic_records)
{
    const vector<RR*>& all_records = zone.getAllRecords();
    
    // Check for wildcard prefix queries
    bool is_single_wildcard = false;
    bool is_double_wildcard = false;
    string suffix;
    
    if (query_rr->name.length() >= 2 && query_rr->name.substr(0, 2) == "*.") {
        is_single_wildcard = true;
        suffix = query_rr->name.substr(2);
    } else if (query_rr->name.length() >= 3 && query_rr->name.substr(0, 3) == "**.") {
        is_double_wildcard = true;
        suffix = query_rr->name.substr(3);
    }
    
    for (vector<RR*>::const_iterator rriter = all_records.begin(); 
         rriter != all_records.end(); ++rriter)
    {
        RR *rr = *rriter;
        
        // Handle wildcard prefix queries
        if (is_single_wildcard || is_double_wildcard) {
            // Check if record name ends with suffix
            if (rr->name.length() > suffix.length() && 
                rr->name.substr(rr->name.length() - suffix.length()) == suffix) {
                
                // Extract the prefix part (before the suffix)
                string prefix = rr->name.substr(0, rr->name.length() - suffix.length());
                
                // Remove trailing dot from prefix if present
                if (!prefix.empty() && prefix[prefix.length() - 1] == '.') {
                    prefix = prefix.substr(0, prefix.length() - 1);
                }
                
                if (is_single_wildcard) {
                    // For *.suffix: prefix should not contain dots (immediate subdomain only)
                    if (prefix.find('.') == string::npos) {
                        if (query_rr->type == RR::TYPESTAR || rr->type == query_rr->type) {
                            matches.push_back(rr);
                        }
                    }
                } else {
                    // For **.suffix: any prefix is allowed (all subdomains)
                    if (query_rr->type == RR::TYPESTAR || rr->type == query_rr->type) {
                        matches.push_back(rr);
                    }
                }
            }
        }
    // Match by exact name and type, or wildcard type (names already lowercased)
    else if ((rr->type == query_rr->type && rr->name == query_rr->name) ||
             (query_rr->type == RR::TYPESTAR && rr->name == query_rr->name) ||
             // DYNAMIC records match TXT queries (they resolve to TXT)
             (rr->type == RR::DYNAMIC && query_rr->type == RR::TXT && rr->name == query_rr->name))
    {
        // Special handling for DYNAMIC records
        if (rr->type == RR::DYNAMIC) {
            // Resolve the DYNAMIC to TXT records
            RRDYNAMIC* dynamic_rr = dynamic_cast<RRDYNAMIC*>(rr);
            if (dynamic_rr) {
                vector<RR*> txt_records = dynamic_rr->resolveTXT();
                // Add all resolved TXT records to matches
                for (vector<RR*>::iterator it = txt_records.begin(); it != txt_records.end(); ++it) {
                    matches.push_back(*it);
                    // Track these for cleanup if caller wants them
                    if (dynamic_records) {
                        dynamic_records->push_back(*it);
                    }
                }
            }
        } else {
            matches.push_back(rr);
        }
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

