#include "ConfigParser.h"
#include "util.h"
#include "inipp.h"

ConfigParser::ConfigParser(string path)
{
	ifstream file(path);
	if (file.is_open()) {
		opened = true;
		inipp::Ini<char> ini;
		ini.parse(file);
		ini.interpolate();
		auto item = ini.sections.find("Base");
		if (item != ini.sections.end()) {
			for (const auto& item : ini.sections["Base"])
			{
				ConfigParser::TransformKeyValue(item.first, item.second);
			}
		}
		else
		{
			auto item = ini.sections.find("");
			if (item != ini.sections.end()) {
				for (const auto& item : ini.sections[""])
				{
					ConfigParser::TransformKeyValue(item.first, item.second);
				}
			}
		}
		item = ini.sections.find("Users");
		if (item != ini.sections.end()) {
			users = item->second;
		}
		item = ini.sections.find("System");
		if (item != ini.sections.end()) {
			system = item->second;
		}
	}
	else {
		opened = false;
	}
}

bool ConfigParser::TransformKeyValue(string key, string val)
{
	if (CONFIGLIST.find(key) != CONFIGLIST.end()) {
		Value value;
		value.type = CONFIGLIST[key];
		switch (CONFIGLIST[key]) {
		case TYPE_BOOL:
			value.ptr = new bool;
			val = trim(val);
			*((bool*)value.ptr) = [=]() {
				if (_stricmp("true", val.c_str()) == 0) {
					return true;
				}
				if (_stricmp("false", val.c_str()) == 0) {
					return false;
				}
				if (strcmp("1", val.c_str()) == 0) {
					return true;
				}
				if (strcmp("0", val.c_str()) == 0) {
					return false;
				}
				cerr << msg("パースエラー",
					"parse error.") << endl;
				cerr << key + " " + "(1:ON 2:OFF 0:EXIT)" << endl << "> ";
				int input;  cin >> input;
				if (!input)	__exit(EXIT_SUCCESS);

				return (input == 1) ? true : false;
			}();

			break;
		case TYPE_INT:
			value.ptr = new int;
			val = trim(val);
			*((int*)value.ptr) = atoi(val.c_str());
			break;
		case TYPE_STRING:
			value.ptr = new string;
			unsigned int idx = 0;
			for (idx = 0; idx < val.size() && isspace(val[idx]); idx++);
			*((string*)value.ptr) = val.substr(idx);
			break;
		}
		m[key] = value;
	}
	return true;
}

ConfigParser::~ConfigParser()
{
}

bool ConfigParser::isOpened() {
	return opened;
}


bool ConfigParser::isSet(string key) {
	return m.find(key) != m.end();
}


Value ConfigParser::getValue(string key) {
	if (m.find(key) != m.end()) {
		return m[key];
	}
	else {
		cerr << key << msg("は定義されていません", " is undefined") << endl;
		cerr << key + " " + "(1:ON 2:OFF 0:EXIT)" << endl << "> ";
		int input;  cin >> input;
		if (!input)	__exit(EXIT_SUCCESS);
		Value val;
		val.type = TYPE_BOOL;
		val.ptr = new bool;
		CASTVAL(bool,val) = (input == 1) ? true : false;
		return val;
	}	
}

string ConfigParser::trim(string &str) {
	size_t beg, end;
	for (beg = 0; beg < str.size() && isspace(str[beg]); beg++);
	for (end = beg; end < str.size() && !isspace(str[end]); end++);
	str = str.substr(beg, end - beg);
	return str;
}