#ifndef PLISTPARSER_HPP
#define PLISTPARSER_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <filesystem>

/* Generic plist node */
struct Plist
{
    enum Type { None, Bool, Int, Real, Date, String, Data, Array, Dict } type = None;
    int64_t i = 0;  /* integer or bool */
    double r = 0;   /* real, or date as seconds since 2001-01-01 UTC */
    std::string s;  /* UTF-8 string, or raw data bytes */
    std::vector<Plist> arr;
    std::map<std::string, Plist> dict;

    /* Dict lookup, empty node if missing */
    const Plist& operator[](const std::string& key) const;
    bool boolean() const { return type == Bool && i != 0; }
};

/* Parse XML or binary (bplist00) plist, throws on malformed input */
Plist parse_plist(const std::string& data);

/* Read file read-only and parse */
Plist load_plist(const std::filesystem::path& path);

/* Builders and XML writer for protocol messages */
Plist plist_str(const std::string& s);
Plist plist_int(int64_t i);
Plist plist_dict(std::initializer_list<std::pair<const std::string, Plist>> items);
std::string to_xml(const Plist& p);

#endif
