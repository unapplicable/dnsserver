#include "update_processor.h"
#include "rr.h"

using namespace std;

bool UpdateProcessor::checkPrerequisites(const Message* request, 
                                        Zone& zone,
                                        string& error_message)
{
    for (vector<RR*>::const_iterator iter = request->an.begin(); iter != request->an.end(); ++iter)
    {
        RR *prereq = *iter;
        
        if (prereq->rrclass == RR::CLASSANY)
        {
            if (prereq->type == RR::TYPESTAR)
            {
                // Prerequisite: name is in use (any type)
                if (!zone.hasRecordWithName(prereq->name))
                {
                    error_message = "Prerequisite failed - name not in use";
                    return false;
                }
            }
            else
            {
                // Prerequisite: RRset exists (specific type)
                if (!zone.hasRecordWithNameAndType(prereq->name, prereq->type))
                {
                    error_message = "Prerequisite failed - RRset does not exist";
                    return false;
                }
            }
        }
        else if (prereq->rrclass == RR::CLASSNONE)
        {
            if (prereq->type == RR::TYPESTAR)
            {
                // Prerequisite: name is not in use
                if (zone.hasRecordWithName(prereq->name))
                {
                    error_message = "Prerequisite failed - name is in use";
                    return false;
                }
            }
            else
            {
                // Prerequisite: RRset does not exist
                if (zone.hasRecordWithNameAndType(prereq->name, prereq->type))
                {
                    error_message = "Prerequisite failed - RRset exists";
                    return false;
                }
            }
        }
    }
    
    return true;
}

bool UpdateProcessor::applyUpdates(const Message* request,
                                  Zone& zone,
                                  string& /* error_message */)
{
    for (vector<RR*>::const_iterator iter = request->ns.begin(); iter != request->ns.end(); ++iter)
    {
        RR *update = *iter;
        
        if (update->rrclass == RR::CLASSANY)
        {
            // Delete all RRsets or specific RRset
            RR::RRType type_to_delete = (update->type == RR::TYPESTAR) ? RR::RRUNDEF : update->type;
            zone.removeRecords(update->name, type_to_delete);
        }
        else if (update->rrclass == RR::CLASSNONE)
        {
            // Delete specific RR (matching rdata)
            zone.removeRecords(update->name, update->type, update->rdata);
        }
        else if (update->rrclass == RR::CLASSIN)
        {
            // Add RR
            RR *new_rr = update->clone();
            zone.addRecord(new_rr);
        }
    }
    
    // Increment SOA serial after successful update
    zone.incrementSerial();
    
    return true;
}

