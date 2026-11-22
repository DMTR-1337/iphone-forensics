#ifndef AUDITREPORT_HPP
#define AUDITREPORT_HPP

#include "util.hpp"
#include <utility>

/* Stateless helpers for inventory classification, Core Data timestamps and report formatting.
   Used through a local instance: Report r; r.category(path). */
class Report
{
public:
    /* SQL-quote a Core Data identifier */
    std::string quote(const std::string& id) const;

    /* 40-char hex backup fileID */
    bool valid_id(const std::string& id) const;

    bool is_date(const std::string& column) const;

    /* Core Data timestamp (seconds since 2001-01-01 UTC, or nanoseconds) to ISO-8601 */
    std::string cocoa_iso(double value) const;

    /* database / thumbnail / media / container, from the logical path only */
    std::string category(const std::string& relative) const;

    /* Parent folder truncated to three components */
    std::string folder_of(const std::string& relative) const;

    /* Human reading of a ZTRASHEDSTATE value */
    std::string meaning(const std::string& trash_state) const;

    /* Escape a Markdown table cell */
    std::string cell(const std::string& s) const;

    /* JSON array of quoted strings */
    std::string arr(const std::vector<std::string>& v) const;

    /* Accumulate one entry into a {count, bytes} bucket */
    void add(std::pair<uint64_t, uint64_t>& bucket, uint64_t bytes) const;

    /* Shared caveat text for summary.md */
    const char* caveats() const;
};

#endif
