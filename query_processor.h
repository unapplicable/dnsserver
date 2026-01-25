#ifndef HAVE_QUERY_PROCESSOR_H
#define HAVE_QUERY_PROCESSOR_H

#include <vector>
#include "rr.h"
#include "zone.h"

// Handles DNS QUERY operations
// Finds matching records for queries including wildcards
class QueryProcessor {
public:
    // Find records matching the query
    // matches: output vector of matching records (may include dynamically created records)
    // dynamic_records: output vector of temporary records that need to be freed by caller
    //                  (these are also included in matches and are created from DYNAMIC RRs)
    // ns_record: optional output for delegation NS record
    static void findMatches(const RR* query_rr,
                           const Zone& zone,
                           std::vector<RR*>& matches,
                           RR** ns_record = NULL,
                           std::vector<RR*>* dynamic_records = NULL);
};

#endif
