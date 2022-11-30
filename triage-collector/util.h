#pragma once

#include <iostream>
#include <vector>
#include <windows.h>

using namespace std;

void __exit(int);
void _perror(char *);
void mkdir(char *, bool error=true);
void chdir(char *);
string basename(string &, char delim = '\\');
string dirname(string &, char delim = '\\');
string msg(string jp, string en, WORD lang = GetUserDefaultLangID());
string join(vector<string>, string);
string hexdump(const unsigned char*, size_t);
int findfiles(vector<pair<string, int>>*, string, bool error = true, vector<string> *fltout = {}, const char* filter = "*", unsigned int recurse = 0, unsigned int curr = 0, string currpath = string(""));
vector<pair<string, int>> findstreams(const char* cfilepath, bool error = true);
string base_name(string const&);
bool ends_with(const std::string&, const std::string&);