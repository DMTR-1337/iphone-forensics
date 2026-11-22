#ifndef PATHSANITIZER_HPP
#define PATHSANITIZER_HPP

#include "util.hpp"
#include <set>

/* Maps backup logical paths to safe, unique, portable paths below an export root */
class PathSanitizer
{
public:
    explicit PathSanitizer(const fs::path& root);

    /* Destination for domain/relativePath; prefix (if any) is prepended to the leaf name; renamed set when the result differs from the logical path */
    fs::path map(const std::string& domain, const std::string& relative, bool& renamed, const std::string& prefix = "");

    /* True if dst resolves inside root after following links/junctions */
    bool contained(const fs::path& dst) const;

private:
    fs::path root;
    std::set<std::string> taken;  /* lowercased files and directories already used */
};

/* Name of the cloud-sync provider containing path, empty if none */
std::string cloud_provider(const fs::path& path);

/* True if path equals or is inside parent after canonicalization */
bool is_inside(const fs::path& path, const fs::path& parent);

#endif
