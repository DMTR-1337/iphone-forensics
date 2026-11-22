#include "path-sanitizer.hpp"
#include <algorithm>
#include <cstring>
#include <cstdio>

namespace
{
    const size_t npos = std::string::npos;
    const size_t max_name = 120;  /* bytes per path component */
    const size_t max_path = 240;  /* total, below Windows MAX_PATH (260) */

    /* FNV-1a, only used to make shortened names unique */
    std::string short_hash(const std::string& s)
    {
        uint64_t h = 1469598103934665603ull;
        for (unsigned char c : s) h = (h ^ c) * 1099511628211ull;
        char b[12];
        snprintf(b, sizeof b, "%08x", unsigned(h ^ h >> 32));
        return b;
    }

    /* Cut to max bytes keeping the extension, on a UTF-8 boundary */
    std::string truncate(const std::string& s, size_t max, const std::string& tag)
    {
        if (s.size() <= max) return s;
        size_t dot = s.rfind('.');
        std::string ext = dot != npos && s.size() - dot <= 16 ? s.substr(dot) : "";
        size_t cut = max > ext.size() + tag.size() + 1 ? max - ext.size() - tag.size() - 1 : 0;
        while (cut > 0 && (s[cut] & 0xC0) == 0x80) cut--;
        return s.substr(0, cut) + "~" + tag + ext;
    }

    /* Windows reserved device names, with or without extension */
    bool reserved(const std::string& name)
    {
        std::string b = lower(name.substr(0, name.find('.')));
        if (b == "con" || b == "prn" || b == "aux" || b == "nul") return true;
        return b.size() == 4 && (b.compare(0, 3, "com") == 0 || b.compare(0, 3, "lpt") == 0) && b[3] >= '1' && b[3] <= '9';
    }

    /* One portable path component */
    std::string component(const std::string& in)
    {
        std::string s;
        for (unsigned char c : in) s += c < 0x20 || strchr("<>:\"\\|?*", c) ? '_' : char(c);
        if (s.empty() || s == "." || s == "..") s = "_" + s;
        if (s.back() == '.' || s.back() == ' ') s.back() = '_';
        if (reserved(s)) s = "_" + s;
        return truncate(s, max_name, short_hash(in));
    }
}

PathSanitizer::PathSanitizer(const fs::path& root) : root(root) {}

fs::path PathSanitizer::map(const std::string& domain, const std::string& relative, bool& renamed, const std::string& prefix)
{
    std::string logical = domain + "/" + relative, rel;

    /* Sanitize each component, dropping empty ones ("a//b") */
    for (size_t p = 0; p <= logical.size();)
    {
        size_t e = std::min(logical.find('/', p), logical.size());
        if (e > p) rel += (rel.empty() ? "" : "/") + component(logical.substr(p, e - p));
        p = e + 1;
    }

    /* Classification prefix on the leaf (prefix is a known-safe literal) */
    if (!prefix.empty())
    {
        size_t s = rel.rfind('/');
        rel.insert(s == npos ? 0 : s + 1, prefix);
    }

    /* Over-long paths go to <domain>/_long/<hash>_<name> */
    size_t base = to_utf8(root).size() + 1;
    if (base + rel.size() > max_path)
    {
        std::string dir = component(domain) + "/_long/" + short_hash(logical) + "_";
        std::string name = rel.substr(rel.rfind('/') + 1);
        rel = dir + truncate(name, max_path > base + dir.size() + 24 ? max_path - base - dir.size() : 24, short_hash(name));
    }

    /* Case-insensitive collisions (ASCII folding) with earlier files or directories */
    std::string orig = rel;
    size_t slash = orig.rfind('/'), dot = orig.rfind('.');
    if (dot == npos || dot < slash) dot = orig.size();
    for (int n = 2; taken.count(lower(rel)); n++) rel = orig.substr(0, dot) + "~" + std::to_string(n) + orig.substr(dot);

    taken.insert(lower(rel));
    for (size_t s = rel.find('/'); s != npos; s = rel.find('/', s + 1)) taken.insert(lower(rel.substr(0, s)));

    renamed = rel != logical;
    return (root / to_path(rel)).make_preferred();
}

bool PathSanitizer::contained(const fs::path& dst) const
{
    return is_inside(dst, root);
}

bool is_inside(const fs::path& path, const fs::path& parent)
{
    std::error_code e1, e2;
    fs::path p = fs::weakly_canonical(path, e1), r = fs::weakly_canonical(parent, e2);
    if (e1 || e2) return false;
    fs::path rel = p.lexically_relative(r);
    return !rel.empty() && *rel.begin() != "..";
}

std::string cloud_provider(const fs::path& path)
{
    std::error_code ec;
    std::string s = lower(to_utf8(fs::weakly_canonical(path, ec))) + "/";
    std::replace(s.begin(), s.end(), '\\', '/');

    static const char* known[][2] = {
        { "/onedrive", "OneDrive" }, { "/mobile documents/", "iCloud Drive" }, { "/iclouddrive/", "iCloud Drive" },
        { "/dropbox", "Dropbox" }, { "/google drive", "Google Drive" }, { "/googledrive", "Google Drive" },
        { "/my drive/", "Google Drive" }, { "/library/cloudstorage/", "a macOS File Provider (cloud storage)" } };
    for (const auto& k : known)
        if (s.find(k[0]) != npos) return k[1];

    /* Redirected OneDrive roots with custom names */
    for (const char* v : { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
    {
        fs::path p = env_path(v);
        if (!p.empty() && is_inside(path, p)) return "OneDrive";
    }
    return "";
}
