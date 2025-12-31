#include "zoneFileLoader.h"

#include "zone.h"
#include "rr.h"

bool ZoneFileLoader::load(const t_data& data, t_zones& zones)
{
	Zone* z = NULL;
	Zone* parent = NULL;
	for (t_data::const_iterator di = data.begin(); di != data.end(); ++di)
	{
		// strip comments
		std::string line = *di;
		
		std::string::size_type cmtpos;
		if ((cmtpos = line.find('!')) != std::string::npos ||
			(cmtpos = line.find('!')) != std::string::npos)
			line.erase(cmtpos);
		// tokenize
		std::vector<std::string> tokens;
		while (line.length() != 0)
		{
			// find sep
			std::string::size_type seppos = line.find_first_of(" \t");
			tokens.push_back(line.substr(0, seppos));
			std::string::size_type nextpos = line.find_first_not_of(" \t", seppos);
			line.erase(0, nextpos);
		};

		if (tokens.size() < 2)
			continue;

		if (tokens[0] == "$ORIGIN")
		{
			if (parent != NULL)
			{
				zones.push_back(parent);
				parent = NULL;
			}
			z = new Zone();
			parent = z;
			z->name = tokens[1];
			continue;
		} else
		if (tokens[0] == "$ACL")
		{
			Zone* acl = new Zone();
			acl->name = parent->name;
			for (std::string::size_type i = 1; i < tokens.size(); ++i)
			{
				AclEntry e = {Subnet(tokens[i]), acl};
				parent->acl.push_back(e);
			}

			z = acl;
			continue;
		}

		try
		{
			RR::RRType rrtype = RR::RRTypeFromString(tokens[2]);
			RR* rr = RR::createByType(rrtype);

			// append name of zone when missing terminating .
			if (!tokens[0].empty() && tokens[0][tokens[0].length() - 1] != '.')
				tokens[0] += "." + z->name + ".";
			rr->fromString(tokens);

			if (rr != NULL && z == NULL)
				return false;

			if (rr != NULL)
			{
				std::cerr << "[" << z->name << "] " << *rr << std::endl;
				z->rrs.push_back(rr);
				rr = NULL;
			}
		} catch (std::exception& ex)
		{
			std::cerr << "error loading rr, line =" ;
			for (std::vector<std::string>::const_iterator it = tokens.begin();
				it != tokens.end();
				++it)
				std::cerr << " " << *it;
			std::cerr << std::endl;
			throw;
		}
	}

	// add last zone
	if (parent != NULL)
	{
		zones.push_back(parent);
	}

	return true;
}
