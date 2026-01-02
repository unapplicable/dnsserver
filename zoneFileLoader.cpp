#include "zoneFileLoader.h"

#include "zone.h"
#include "rr.h"
#include "tsig.h"
#include <iostream>

std::string ZoneFileLoader::stripComments(const std::string& line)
{
	std::string result = line;
	std::string::size_type cmtpos = result.find('!');
	if (cmtpos != std::string::npos)
		result.erase(cmtpos);
	return result;
}

std::vector<std::string> ZoneFileLoader::tokenize(const std::string& line)
{
	std::vector<std::string> tokens;
	std::string remaining = line;
	
	while (remaining.length() != 0)
	{
		std::string::size_type seppos = remaining.find_first_of(" \t");
		tokens.push_back(remaining.substr(0, seppos));
		std::string::size_type nextpos = remaining.find_first_not_of(" \t", seppos);
		remaining.erase(0, nextpos);
	}
	
	return tokens;
}

void ZoneFileLoader::handleOrigin(const std::vector<std::string>& tokens, Zone*& parent, Zone*& current, t_zones& zones, std::string& previousName)
{
	if (parent != NULL)
	{
		zones.push_back(parent);
		parent = NULL;
	}
	Zone* z = new Zone();
	parent = z;
	z->name = dns_name_tolower(tokens[1]);
	current = z;
	previousName.clear();
}

void ZoneFileLoader::handleACL(const std::vector<std::string>& tokens, Zone* parent, Zone*& current)
{
	Zone* acl = new Zone();
	acl->name = parent->name;
	// Copy TSIG key from parent to ACL zone
	if (parent->tsig_key) {
		std::cerr << "[" << parent->name << "] Copying TSIG key to ACL zone" << std::endl;
		acl->tsig_key = new TSIG::Key(*parent->tsig_key);
	}
	for (std::string::size_type i = 1; i < tokens.size(); ++i)
	{
		AclEntry e = {Subnet(tokens[i]), acl};
		parent->acl.push_back(e);
	}
	current = acl;
}

void ZoneFileLoader::handleTSIG(const std::vector<std::string>& tokens, Zone* parent)
{
	// $TSIG keyname algorithm secret
	// Example: $TSIG mykey.example.com. hmac-sha256 K2tf3TRrmE7TJd+m2NPBuw==
	if (tokens.size() < 4)
	{
		std::cerr << "Warning: Invalid $TSIG directive (needs: keyname algorithm secret)" << std::endl;
		return;
	}
	
	if (!parent)
	{
		std::cerr << "Warning: $TSIG must come after $ORIGIN" << std::endl;
		return;
	}
	
	TSIG::Key* key = new TSIG::Key();
	key->name = dns_name_tolower(tokens[1]);
	
	// Ensure key name has trailing dot
	if (!key->name.empty() && key->name[key->name.length()-1] != '.')
		key->name += ".";
	
	key->algorithm = TSIG::algorithmFromName(tokens[2]);
	key->secret = tokens[3];
	key->decoded_secret = TSIG::base64Decode(tokens[3]);
	
	parent->tsig_key = key;
	
	std::cerr << "[" << parent->name << "] TSIG key configured: " << key->name 
	          << " (" << TSIG::algorithmToName(key->algorithm) << ")" << std::endl;
}

void ZoneFileLoader::handleResourceRecord(const std::vector<std::string>& tokens, Zone* current, std::string& previousName)
{
	RR::RRType rrtype = RR::RRTypeFromString(tokens[2]);
	RR* rr = RR::createByType(rrtype);
	
	// Get origin without trailing dot for fromString processing
	std::string origin = normalize_dns_name(current->name);
	
	rr->fromString(tokens, origin, previousName);
	
	if (!tokens[0].empty())
		previousName = rr->name;
	
	std::cerr << "[" << current->name << "] " << *rr << std::endl;
	current->addRecord(rr);
}

bool ZoneFileLoader::load(const t_data& data, t_zones& zones)
{
	Zone* z = NULL;
	Zone* parent = NULL;
	std::string previousName;
	
	for (t_data::const_iterator di = data.begin(); di != data.end(); ++di)
	{
		std::string line = stripComments(*di);
		std::vector<std::string> tokens = tokenize(line);

		if (tokens.size() < 2)
			continue;

		if (tokens[0] == "$ORIGIN")
		{
			handleOrigin(tokens, parent, z, zones, previousName);
			continue;
		}
		
		if (tokens[0] == "$ACL")
		{
			handleACL(tokens, parent, z);
			continue;
		}
		
		if (tokens[0] == "$TSIG")
		{
			handleTSIG(tokens, parent);
			continue;
		}

		try
		{
			if (z == NULL)
				return false;
			
			handleResourceRecord(tokens, z, previousName);
		}
		catch (std::exception& ex)
		{
			std::cerr << "error loading rr, line =";
			for (std::vector<std::string>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
				std::cerr << " " << *it;
			std::cerr << std::endl;
			throw;
		}
	}

	if (parent != NULL)
	{
		// Copy TSIG key from parent to all ACL zones before finalizing
		if (parent->tsig_key)
		{
			for (std::vector<AclEntry>::iterator it = parent->acl.begin(); 
			     it != parent->acl.end(); ++it)
			{
				if (it->zone && !it->zone->tsig_key)
				{
					std::cerr << "[" << parent->name << "] Copying TSIG key to ACL zone" << std::endl;
					it->zone->tsig_key = new TSIG::Key(*parent->tsig_key);
				}
			}
		}
		zones.push_back(parent);
	}

	return true;
}
