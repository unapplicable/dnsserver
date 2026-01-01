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
    static void findMatches(const RR* query_rr,
                           const Zone& zone,
                           std::vector<RR*>& matches,
                           RR** ns_record = NULL);
};

#endif
