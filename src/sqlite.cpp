#include "sqlite.hpp"
#include "sqlite3.h"
#include <memory>
#include <stdexcept>

std::string text(sqlite3_stmt* s, int col)
{
    const unsigned char* p = sqlite3_column_text(s, col);
    return p ? std::string((const char*)p, sqlite3_column_bytes(s, col)) : "";
}

Sqlite::Sqlite(const fs::path& path)
{
    if (sqlite3_open_v2(to_utf8(path).c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
    {
        std::string e = sqlite3_errmsg(db);
        sqlite3_close(db);
        throw std::runtime_error("sqlite open: " + e);
    }
}

Sqlite::~Sqlite()
{
    sqlite3_close(db);
}

void Sqlite::query(const std::string& sql, const std::function<void(sqlite3_stmt*)>& row)
{
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) throw std::runtime_error(std::string("sqlite: ") + sqlite3_errmsg(db));
    std::unique_ptr<sqlite3_stmt, int (*)(sqlite3_stmt*)> guard(st, sqlite3_finalize);
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) row(st);
    if (rc != SQLITE_DONE) throw std::runtime_error(std::string("sqlite: ") + sqlite3_errmsg(db));
}

bool Sqlite::has_table(const std::string& name)
{
    bool found = false;
    query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '" + name + "'", [&](sqlite3_stmt*) { found = true; });
    return found;
}

std::set<std::string> Sqlite::columns(const std::string& table)
{
    std::set<std::string> c;
    query("PRAGMA table_info(" + table + ")", [&](sqlite3_stmt* s) { c.insert(text(s, 1)); });
    return c;
}
