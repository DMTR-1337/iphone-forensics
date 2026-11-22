#include "backup-scanner.hpp"
#include "plist-parser.hpp"
#include <fstream>
#include <chrono>
#include <cstring>

std::string BackupInfo::to_json() const
{
    return json_obj({
        { "path", json(to_utf8(path)) }, { "device", json(device) }, { "ios", json(ios) }, { "product", json(product) },
        { "lastBackup", json(last_backup) }, { "snapshot", json(snapshot) },
        { "encrypted", jbool(encrypted) }, { "usable", jbool(usable) }, { "problem", json(problem) } });
}

std::vector<fs::path> default_backup_roots()
{
#ifdef _WIN32
    /* Apple Devices / Store iTunes, then classic iTunes */
    return { home_dir() / "Apple" / "MobileSync" / "Backup", appdata_dir() / "Apple Computer" / "MobileSync" / "Backup" };
#else
    return { appdata_dir() / "MobileSync" / "Backup" };
#endif
}

namespace
{
    bool sqlite_header(const fs::path& p)
    {
        char h[16] = {};
        std::ifstream f(p, std::ios::in | std::ios::binary);
        return f.read(h, 16) && memcmp(h, "SQLite format 3", 16) == 0;
    }

    bool recently_modified(const fs::path& p)
    {
        std::error_code ec;
        auto t = fs::last_write_time(p, ec);
        return !ec && fs::file_time_type::clock::now() - t < std::chrono::minutes(2);
    }
}

BackupInfo inspect_backup(const fs::path& dir)
{
    BackupInfo b;
    b.path = dir;
    try
    {
        for (const char* f : { "Info.plist", "Manifest.plist", "Status.plist" })
            if (!fs::is_regular_file(dir / f)) throw std::runtime_error(std::string("missing ") + f);
        if (!fs::is_regular_file(dir / "Manifest.db"))
            throw std::runtime_error(fs::exists(dir / "Manifest.mbdb") ? "legacy Manifest.mbdb format (iOS 9 or older) not supported" : "missing Manifest.db");

        Plist info = load_plist(dir / "Info.plist"), manifest = load_plist(dir / "Manifest.plist"), status = load_plist(dir / "Status.plist");
        b.device = info["Device Name"].s.empty() ? manifest["Lockdown"]["DeviceName"].s : info["Device Name"].s;
        b.ios = info["Product Version"].s.empty() ? manifest["Lockdown"]["ProductVersion"].s : info["Product Version"].s;
        b.product = info["Product Type"].s;
        b.snapshot = status["SnapshotState"].s;
        b.encrypted = manifest["IsEncrypted"].boolean();
        const Plist& date = info["Last Backup Date"];
        b.last_backup = date.type == Plist::Date ? iso_utc(date.r + 978307200.0) : date.s;

        if (b.encrypted) b.problem = "encrypted backup - automated inspection disabled";
        else if (b.snapshot != "finished") b.problem = "incomplete (SnapshotState: " + (b.snapshot.empty() ? std::string("missing") : b.snapshot) + ")";
        else if (recently_modified(dir / "Manifest.db") || recently_modified(dir / "Status.plist")) b.problem = "modified in the last 2 minutes - backup may still be in progress";
        else if (!sqlite_header(dir / "Manifest.db")) b.problem = "Manifest.db is not a valid SQLite database";
        else b.usable = true;
    }
    catch (const std::exception& e)
    {
        b.problem = std::string("unreadable or corrupted: ") + e.what();
    }
    return b;
}

std::vector<BackupInfo> scan_backups(const fs::path& dir, std::string& error)
{
    std::vector<BackupInfo> out;
    std::error_code ec;
    if (fs::exists(dir / "Manifest.plist", ec)) return { inspect_backup(dir) };

    try
    {
        for (const auto& e : fs::directory_iterator(dir))
        {
            /* Only folders that look like backups */
            const fs::path& p = e.path();
            if (e.is_directory(ec) && (fs::exists(p / "Info.plist", ec) || fs::exists(p / "Manifest.plist", ec) || fs::exists(p / "Manifest.db", ec)))
                out.push_back(inspect_backup(p));
        }
    }
    catch (const fs::filesystem_error& e)
    {
        error = to_utf8(dir) + ": " + e.code().message();
#ifdef __APPLE__
        error += " (grant Full Disk Access to the terminal running this tool)";
#endif
    }
    return out;
}
