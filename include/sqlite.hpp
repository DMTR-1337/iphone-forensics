#ifndef SQLITE_HPP
#define SQLITE_HPP

#include "util.hpp"
#include <set>
#include <functional>

/* Opaque SQLite handles, the full API is included only in sqlite.cpp */
struct sqlite3;
struct sqlite3_stmt;

/* Text column as UTF-8, empty when NULL */
std::string text(sqlite3_stmt* s, int col);

/* Minimal read-only SQLite wrapper */
class Sqlite
{
public:
    explicit Sqlite(const fs::path& path);
    ~Sqlite();
    Sqlite(const Sqlite&) = delete;
    Sqlite& operator=(const Sqlite&) = delete;

    /* Run sql, calling row(stmt) once per result row */
    void query(const std::string& sql, const std::function<void(sqlite3_stmt*)>& row);

    bool has_table(const std::string& name);
    std::set<std::string> columns(const std::string& table);

private:
    sqlite3* db = nullptr;
};

#endif
