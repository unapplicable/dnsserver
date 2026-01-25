#include "rrdynamic.h"
#include "rrtxt.h"
#include <fstream>
#include <set>

void RRDYNAMIC::packContents(char* /* data */, unsigned int /* len */, unsigned int& /* offset */)
{
	// DYNAMIC records should never be packed directly into DNS responses
	// They are resolved to TXT records at query time via resolveTXT()
	throw std::runtime_error("RRDYNAMIC::packContents should never be called - use resolveTXT() instead");
}

void RRDYNAMIC::fromStringContents(const std::vector<std::string>& tokens, const std::string& /* origin */)
{
	// Expect: $DYNAMIC name filepath
	// tokens should contain the filepath
	if (tokens.size() < 1)
		throw std::runtime_error("RRDYNAMIC requires a filepath");
	
	filepath = tokens[0];
}

std::ostream& RRDYNAMIC::dumpContents(std::ostream& os) const
{
	return os << "DYNAMIC(" << filepath << ")";
}

std::string RRDYNAMIC::toString() const
{
	return name + " " + std::to_string(ttl) + " IN DYNAMIC " + filepath;
}

std::vector<RR*> RRDYNAMIC::resolveTXT() const
{
	std::vector<RR*> result;
	
	std::ifstream file(filepath);
	if (!file.is_open())
	{
		std::cerr << "Warning: RRDYNAMIC file not found: " << filepath << std::endl;
		return result;  // Return empty result if file doesn't exist
	}
	
	// Read unique non-empty lines (like acmeshit.py does)
	std::set<std::string> unique_lines;
	std::string line;
	while (std::getline(file, line))
	{
		// Strip whitespace
		size_t start = line.find_first_not_of(" \t\r\n");
		size_t end = line.find_last_not_of(" \t\r\n");
		
		if (start != std::string::npos && end != std::string::npos)
		{
			std::string trimmed = line.substr(start, end - start + 1);
			if (!trimmed.empty())
				unique_lines.insert(trimmed);
		}
	}
	
	// Create TXT records for each unique line (sorted)
	for (const std::string& txt : unique_lines)
	{
		RRTXT* txtRecord = new RRTXT();
		txtRecord->name = this->name;
		txtRecord->ttl = 1;  // Short TTL like acmeshit.py
		txtRecord->rrclass = RR::CLASSIN;
		txtRecord->type = RR::TXT;
		txtRecord->rdata = txt;
		result.push_back(txtRecord);
	}
	
	return result;
}
